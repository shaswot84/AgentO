import type { Finding, FindingStatus, JsonValue, SecurityHypothesis, Severity, SourceLocation } from '@agento/core';
import { EvidenceRedactor, type StoredEvidence } from '@agento/evidence';
import { ReportingError, type CitedText, type ReportFinding, type ReportInput, type ReportingOptions, type SecurityReport } from './contracts.js';
import { canonical, checkedRecord, copy, digest, freeze, index, limit, sorted, strings, text } from './value.js';

export const FINDING_STATUSES: readonly FindingStatus[] = Object.freeze(['HYPOTHESIS', 'LIKELY', 'CONFIRMED', 'NOT_REPRODUCED', 'REJECTED']);
export const SEVERITIES: readonly Severity[] = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);
const runtimeKinds = new Set(['http-request', 'http-response', 'header', 'cookie-security', 'cross-origin',
  'authorization', 'browser-observation', 'identity-session', 'screenshot', 'scanner-output']);
const categories: Readonly<Record<string, string>> = {
  'CWE-639': 'A01:2025', 'CWE-862': 'A01:2025', 'CWE-942': 'A02:2025',
  'CWE-1004': 'A02:2025', 'CWE-614': 'A02:2025', 'CWE-79': 'A05:2025', 'CWE-89': 'A05:2025',
};
export function evidenceClass(record: StoredEvidence): 'static' | 'runtime' | 'other' {
  if (runtimeKinds.has(record.kind) || record.facts.observation === 'security-probe'
    && record.producerId.startsWith('probe:')) return 'runtime';
  return ['source-location', 'static-analysis', 'configuration'].includes(record.kind) ? 'static' : 'other';
}
function location(value: SourceLocation): void {
  if (!value || !text(value.file) || !Number.isSafeInteger(value.startLine) || value.startLine < 1
    || value.endLine !== undefined && (!Number.isSafeInteger(value.endLine) || value.endLine < value.startLine)
    || value.symbol !== undefined && !text(value.symbol)) throw new ReportingError('invalid-input');
}
function sameLocation(a: SourceLocation, b: SourceLocation): boolean {
  return a.file === b.file && a.startLine === b.startLine && (a.endLine ?? a.startLine) === (b.endLine ?? b.startLine);
}

/** Presentation only: consumes a trusted assessment and never executes tests or chooses a verdict. */
export function buildSecurityReport(input: ReportInput, options: ReportingOptions): SecurityReport {
  try { return buildReport(input, options); }
  catch (error) {
    if (error instanceof ReportingError) throw error;
    throw new ReportingError('invalid-input');
  }
}
function buildReport(input: ReportInput, options: ReportingOptions): SecurityReport {
  if (!options?.evidenceStore || typeof options.evidenceStore.get !== 'function') throw new ReportingError('invalid-options');
  const maxFindings = limit(options.maxFindings ?? 1000, 10_000);
  const maxEvidence = limit(options.maxEvidence ?? 10_000, 100_000);
  const maxBytes = limit(options.maxReportBytes ?? 33_554_432, 268_435_456);
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  if (!text(generatedAt) || !Number.isFinite(Date.parse(generatedAt))) throw new ReportingError('invalid-options');
  let redactor: EvidenceRedactor;
  try { redactor = new EvidenceRedactor(options.secrets); } catch { throw new ReportingError('invalid-options'); }
  const data = copy(input);
  if (!data?.context?.project || !text(data.context.project.id) || !text(data.context.project.name)
    || !text(data.context.project.baseUrl)) throw new ReportingError('invalid-input');
  const project = data.context.project;
  const id = (value: string): string => {
    if (!text(value) || redactor.text(value) !== value) throw new ReportingError('invalid-input');
    return value;
  };
  id(project.id);
  const baseUrl = redactor.url(project.baseUrl);
  if (baseUrl === '[REDACTED]') throw new ReportingError('invalid-input');
  const endpoints = index(data.context.endpoints), findings = index(data.findings);
  const hypotheses = index(data.hypotheses ?? []), plans = index(data.plans ?? []), results = index(data.results ?? []);
  const decisions = new Map((data.decisions ?? []).map(item => [item.finding.id, item]));
  const remediation = new Map((data.remediation ?? []).map(item => [item.findingId, item]));
  if (decisions.size !== (data.decisions?.length ?? 0) || remediation.size !== (data.remediation?.length ?? 0)) throw new ReportingError('duplicate-id');
  const retests = new Map((data.retests ?? []).map(item => [item.findingId, item]));
  if (retests.size !== (data.retests?.length ?? 0)) throw new ReportingError('duplicate-id');
  const records = new Map<string, StoredEvidence>();
  const retain = (ids: readonly string[]): string[] => {
    strings(ids);
    for (const ref of ids) {
      id(ref);
      if (records.has(ref)) continue;
      if (records.size >= maxEvidence) throw new ReportingError('report-limit');
      let value;
      try { value = options.evidenceStore.get(ref); } catch { throw new ReportingError('missing-evidence'); }
      if (!value) throw new ReportingError('missing-evidence');
      const record = checkedRecord(value);
      if (record.id !== ref) throw new ReportingError('unrelated-reference');
      if (record.projectId !== project.id) throw new ReportingError('project-mismatch');
      // A changed redaction policy cannot silently change a retained record and its digest.
      if (canonical(redactor.json(record as unknown as JsonValue)) !== canonical(record)) throw new ReportingError('unsafe-evidence');
      records.set(ref, record);
    }
    return sorted(ids);
  };
  const cited = (value: string, evidenceIds: readonly string[]): CitedText | null => {
    if (typeof value !== 'string') throw new ReportingError('invalid-input');
    return value.trim() && evidenceIds.length ? { text: redactor.text(value), evidenceIds: sorted(evidenceIds) } : null;
  };
  for (const hypothesis of hypotheses.values()) {
    id(hypothesis.id);
    if (hypothesis.projectId !== project.id) throw new ReportingError('project-mismatch');
    if (hypothesis.status !== 'HYPOTHESIS' || !/^CWE-\d+$/.test(hypothesis.cweId) || !text(hypothesis.reason)) throw new ReportingError('invalid-input');
    strings(hypothesis.evidenceIds);
  }
  for (const plan of plans.values()) {
    id(plan.id);
    if (!text(plan.hypothesisId) || !/^CWE-\d+$/.test(plan.cweId) || !['scanner', 'browser'].includes(plan.executor)
      || !['passive', 'active'].includes(plan.risk) || redactor.url(plan.targetUrl) === '[REDACTED]'
      || !Array.isArray(plan.steps)) throw new ReportingError('invalid-input');
    strings(plan.requiredCapabilities); strings(plan.identityIds);
    index(plan.steps);
    for (const step of plan.steps) {
      id(step.id);
      if (!text(step.action) || !text(step.expectedObservation)) throw new ReportingError('invalid-input');
    }
    const hypothesis = hypotheses.get(plan.hypothesisId);
    if (hypothesis && hypothesis.cweId !== plan.cweId) throw new ReportingError('unrelated-reference');
    if (!hypothesis && !data.findings.some(item => item.hypothesisId === plan.hypothesisId && item.cweId === plan.cweId)) throw new ReportingError('unrelated-reference');
  }
  for (const result of results.values()) {
    id(result.id);
    if (!plans.has(result.planId) || !['COMPLETED', 'FAILED', 'SKIPPED'].includes(result.outcome)
      || !Array.isArray(result.evidence)) throw new ReportingError('unrelated-reference');
    retain(result.evidence.map(item => item.id));
    for (const supplied of result.evidence) {
      // Compare with the store, not with a mutable result copy that may contain changed facts.
      if (canonical(checkedRecord(supplied)) !== canonical(records.get(supplied.id))) throw new ReportingError('integrity-failed');
    }
  }
  const assessedHypotheses = new Set<string>();
  for (const finding of findings.values()) {
    id(finding.id); id(finding.hypothesisId);
    if (finding.projectId !== project.id) throw new ReportingError('project-mismatch');
    if (!FINDING_STATUSES.includes(finding.status) || !SEVERITIES.includes(finding.severity)
      || !['low', 'medium', 'high'].includes(finding.confidence) || !/^CWE-\d+$/.test(finding.cweId)
      || !text(finding.title) || !text(finding.owaspCategory) || typeof finding.rootCause !== 'string') throw new ReportingError('invalid-input');
    if (assessedHypotheses.has(finding.hypothesisId)) throw new ReportingError('duplicate-id');
    assessedHypotheses.add(finding.hypothesisId);
    const hypothesis = hypotheses.get(finding.hypothesisId);
    if (hypothesis && (hypothesis.cweId !== finding.cweId || hypothesis.endpointId !== undefined
      && finding.endpointId !== hypothesis.endpointId)) throw new ReportingError('unrelated-reference');
    retain(finding.evidenceIds); strings(finding.testPlanIds);
    if (finding.endpointId !== undefined && finding.evidenceIds.some(ref => {
      const record = records.get(ref)!;
      return evidenceClass(record) === 'runtime' && record.endpointId !== undefined && record.endpointId !== finding.endpointId;
    })) throw new ReportingError('unrelated-reference');
    for (const ref of finding.testPlanIds) {
      const plan = plans.get(ref);
      if (!plan || plan.hypothesisId !== finding.hypothesisId || plan.cweId !== finding.cweId) throw new ReportingError('unrelated-reference');
    }
  }
  for (const [ref, decision] of decisions) {
    const finding = findings.get(ref);
    if (!finding || canonical(finding) !== canonical(decision.finding)) throw new ReportingError('unrelated-reference');
    strings(decision.diagnostics);
    const statics = retain(decision.staticEvidenceIds), runtime = retain(decision.runtimeEvidenceIds);
    if ([...statics, ...runtime].some(key => !finding.evidenceIds.includes(key))
      || statics.some(key => evidenceClass(records.get(key)!) !== 'static')
      || runtime.some(key => evidenceClass(records.get(key)!) !== 'runtime')) throw new ReportingError('unrelated-reference');
  }
  for (const [ref, suggestion] of remediation) {
    const finding = findings.get(ref);
    if (!finding || !text(suggestion.explanation)) throw new ReportingError('unrelated-reference');
    retain(suggestion.evidenceIds);
    if (!suggestion.evidenceIds.length || suggestion.evidenceIds.some(key => !finding.evidenceIds.includes(key))) throw new ReportingError('unrelated-reference');
  }
  for (const [findingId, retest] of retests) {
    const finding = findings.get(findingId);
    id(retest.id);
    if (!finding || finding.status !== 'CONFIRMED' || retest.projectId !== project.id || retest.cweId !== finding.cweId
      || !['FIX_VERIFIED', 'FIX_FAILED', 'FIX_INCONCLUSIVE'].includes(retest.status)
      || !retest.beforeEvidenceIds.length || retest.beforeEvidenceIds.some(ref => !finding.evidenceIds.includes(ref))) throw new ReportingError('unrelated-reference');
    retain([retest.comparisonEvidenceId, ...retest.beforeEvidenceIds, ...retest.afterEvidenceIds]);
    const comparison = records.get(retest.comparisonEvidenceId)!, facts = comparison.facts;
    if (comparison.producerId !== 'retest-engine' || facts.observation !== 'fix-verification'
      || facts.retestId !== retest.id || facts.findingId !== finding.id || facts.cweId !== finding.cweId
      || facts.status !== retest.status || !finding.testPlanIds.includes(facts.planId as string)
      || comparison.endpointId !== finding.endpointId
      || canonical(facts.beforeEvidenceIds) !== canonical(retest.beforeEvidenceIds)
      || canonical(facts.afterEvidenceIds) !== canonical(retest.afterEvidenceIds)
      || canonical(facts.beforeDigests) !== canonical(retest.beforeEvidenceIds.map(ref => records.get(ref)!.digest))
      || retest.afterEvidenceIds.some(ref => retest.beforeEvidenceIds.includes(ref)
        || records.get(ref)!.endpointId !== finding.endpointId
        || records.get(ref)!.provenance.environment.id !== comparison.provenance.environment.id)
      || retest.status === 'FIX_VERIFIED' && (!retest.afterEvidenceIds.length
        || facts.securityRegression !== 'PASSED' || facts.normalFlow !== 'PASSED')
      || retest.status === 'FIX_FAILED' && !retest.afterEvidenceIds.length) throw new ReportingError('unrelated-reference');
  }
  const entries: { finding: Finding; hypothesisOnly: boolean }[] = [...findings.values()].map(finding => ({ finding, hypothesisOnly: false }));
  for (const hypothesis of hypotheses.values()) {
    if (assessedHypotheses.has(hypothesis.id)) continue;
    const finding = hypothesisFinding(hypothesis);
    if (findings.has(finding.id)) throw new ReportingError('duplicate-id');
    retain(finding.evidenceIds);
    entries.push({ finding, hypothesisOnly: true });
  }
  if (entries.length > maxFindings) throw new ReportingError('report-limit');
  const output: ReportFinding[] = entries.map(({ finding, hypothesisOnly }) => {
    const refs = retain(finding.evidenceIds), diagnostics: string[] = [];
    const attached = refs.map(ref => records.get(ref)!);
    const runtimeEvidenceIds = attached.filter(item => evidenceClass(item) === 'runtime').map(item => item.id);
    const contextEvidenceIds: string[] = [];
    const relevantPlans = [...plans.values()].filter(plan => plan.hypothesisId === finding.hypothesisId);
    const executions = [...results.values()].filter(result => relevantPlans.some(plan => plan.id === result.planId));
    if (finding.status === 'CONFIRMED' && !executions.some(result => result.outcome === 'COMPLETED' && !result.error
      && finding.testPlanIds.includes(result.planId) && result.evidence.some(item => runtimeEvidenceIds.includes(item.id)))) {
      throw new ReportingError('unrelated-reference');
    }
    let endpoint: ReportFinding['endpoint'] = null;
    if (finding.endpointId !== undefined) {
      const candidate = endpoints.get(finding.endpointId);
      if (!candidate) throw new ReportingError('unrelated-reference');
      if (!['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(candidate.method)
        || !text(candidate.path) || !candidate.path.startsWith('/')) throw new ReportingError('invalid-input');
      strings(candidate.evidenceIds);
      const supports = attached.filter(record => record.endpointId === candidate.id || candidate.evidenceIds.includes(record.id)).map(item => item.id);
      if (supports.length) endpoint = { id: id(candidate.id), method: redactor.text(candidate.method), path: redactor.text(candidate.path), evidenceIds: supports };
      else diagnostics.push('uncited-endpoint-omitted');
    }
    let source: ReportFinding['source'] = null;
    const candidateSource = finding.source ?? (finding.endpointId ? endpoints.get(finding.endpointId)?.handler : undefined);
    if (candidateSource) {
      location(candidateSource);
      let supports = attached.filter(record => record.source && sameLocation(record.source, candidateSource)).map(item => item.id);
      if (!supports.length && finding.endpointId) {
        const contextRefs = retain(endpoints.get(finding.endpointId)!.evidenceIds);
        supports = contextRefs.filter(ref => {
          const record = records.get(ref)!;
          return record.source && sameLocation(record.source, candidateSource);
        });
        contextEvidenceIds.push(...supports.filter(ref => !refs.includes(ref)));
      }
      if (supports.length) source = { location: { file: redactor.text(candidateSource.file), startLine: candidateSource.startLine,
        ...(candidateSource.endLine === undefined ? {} : { endLine: candidateSource.endLine }),
        ...(candidateSource.symbol === undefined ? {} : { symbol: redactor.text(candidateSource.symbol) }) }, evidenceIds: supports };
      else diagnostics.push('uncited-source-omitted');
    }
    const suggestion = remediation.get(finding.id);
    const rootCause = hypothesisOnly ? null : cited(finding.rootCause, refs);
    if (!rootCause) diagnostics.push(hypothesisOnly ? 'root-cause-unverified' : 'uncited-root-cause-omitted');
    if (!runtimeEvidenceIds.length) diagnostics.push('no-runtime-proof');
    const decision = decisions.get(finding.id);
    const attempt = retests.get(finding.id);
    const retest: ReportFinding['retest'] = attempt ? {
      id: attempt.id, findingId: attempt.findingId, projectId: attempt.projectId, cweId: attempt.cweId,
      status: attempt.status, comparisonEvidenceId: attempt.comparisonEvidenceId,
      beforeEvidenceIds: [...attempt.beforeEvidenceIds], afterEvidenceIds: [...attempt.afterEvidenceIds],
    } : { status: 'NOT_RUN' };
    return {
      id: finding.id, hypothesisId: finding.hypothesisId, title: redactor.text(finding.title), cweId: finding.cweId,
      owaspCategory: redactor.text(finding.owaspCategory), status: finding.status,
      severity: hypothesisOnly ? null : finding.severity, confidence: hypothesisOnly ? null : finding.confidence,
      assessment: cited(hypothesisOnly ? finding.rootCause : `${finding.title}. Status: ${finding.status}. Severity: ${finding.severity}. Confidence: ${finding.confidence}.`, refs),
      rootCause, endpoint, source, evidenceIds: sorted([...refs, ...contextEvidenceIds]),
      staticEvidenceIds: attached.filter(item => evidenceClass(item) === 'static').map(item => item.id), runtimeEvidenceIds,
      otherEvidenceIds: attached.filter(item => evidenceClass(item) === 'other').map(item => item.id), contextEvidenceIds,
      testPlans: relevantPlans.sort((a, b) => a.id.localeCompare(b.id, 'en')).map(plan => ({ id: plan.id,
        executor: plan.executor, risk: plan.risk, targetUrl: redactor.url(plan.targetUrl),
        requiredCapabilities: plan.requiredCapabilities.map(id), identityIds: plan.identityIds.map(id),
        steps: plan.steps.map(step => ({ id: step.id, action: redactor.text(step.action), expectedObservation: redactor.text(step.expectedObservation) })),
        evidenceIds: refs })),
      executions: executions.sort((a, b) => a.id.localeCompare(b.id, 'en')).map(result => ({ id: result.id,
        planId: result.planId, outcome: result.outcome, evidenceIds: sorted(result.evidence.map(item => item.id)) })),
      verification: { source: hypothesisOnly ? 'hypothesis' : decision ? 'judge' : 'supplied-finding',
        diagnostics: decision?.diagnostics.map(item => redactor.text(item)) ?? [] },
      remediation: suggestion ? { status: 'SUGGESTED', explanation: cited(suggestion.explanation, suggestion.evidenceIds),
        patch: suggestion.patch === undefined ? null : cited(suggestion.patch, suggestion.evidenceIds),
        regressionTest: suggestion.regressionTest === undefined ? null : cited(suggestion.regressionTest, suggestion.evidenceIds) }
        : { status: 'NOT_PROVIDED', explanation: null, patch: null, regressionTest: null },
      retest, diagnostics: diagnostics.sort(),
    };
  });
  const severityRank = (value: Severity | null) => value === null ? -1 : SEVERITIES.indexOf(value);
  const statusOrder: readonly FindingStatus[] = ['CONFIRMED', 'LIKELY', 'HYPOTHESIS', 'NOT_REPRODUCED', 'REJECTED'];
  output.sort((a, b) => statusOrder.indexOf(a.status) - statusOrder.indexOf(b.status)
    || severityRank(b.severity) - severityRank(a.severity) || a.id.localeCompare(b.id, 'en'));
  const byStatus = Object.fromEntries(FINDING_STATUSES.map(status => [status, output.filter(item => item.status === status).length])) as Record<FindingStatus, number>;
  const confirmedBySeverity = Object.fromEntries(SEVERITIES.map(severity => [severity,
    output.filter(item => item.status === 'CONFIRMED' && item.severity === severity).length])) as Record<Severity, number>;
  const usedEvidenceIds = new Set(output.flatMap(finding => [...finding.evidenceIds,
    ...finding.executions.flatMap(result => result.evidenceIds),
    ...(finding.retest.status === 'NOT_RUN' ? [] : [finding.retest.comparisonEvidenceId, ...finding.retest.beforeEvidenceIds, ...finding.retest.afterEvidenceIds])]));
  const content = { schemaVersion: 1 as const, generatedAt, project: { id: project.id, name: redactor.text(project.name), baseUrl },
    summary: { total: output.length, byStatus, confirmedBySeverity }, findings: output,
    evidence: [...records.values()].filter(record => usedEvidenceIds.has(record.id)).sort((a, b) => a.id.localeCompare(b.id, 'en')),
    limitations: [
      'Finding states come from the supplied assessment. Reporting does not execute tests or independently verify vulnerabilities.',
      'A hypothesis is unverified. NOT_REPRODUCED describes this assessment and does not prove that an application is secure.',
      'Proof contains retained, redacted observations. Private input values, credentials, raw bodies, and external artifacts are not reconstructed.',
      'Test steps describe the assessment. Private bindings must be supplied by the authorized host to reproduce it.',
      retests.size ? 'Fix statuses describe the supplied isolated retest attempts. The original vulnerability assessments remain unchanged.'
        : 'Remediation is included only when supplied with evidence references. Retest has not run.',
    ] };
  const report = { ...content, digest: digest(content) };
  if (Buffer.byteLength(JSON.stringify(report, null, 2)) > maxBytes) throw new ReportingError('report-limit');
  return freeze(report);
}
function hypothesisFinding(hypothesis: SecurityHypothesis): Finding {
  return { id: `hypothesis:${hypothesis.id}`, projectId: hypothesis.projectId, hypothesisId: hypothesis.id,
    cweId: hypothesis.cweId, owaspCategory: categories[hypothesis.cweId] ?? 'UNMAPPED', title: `${hypothesis.cweId} hypothesis`,
    status: 'HYPOTHESIS', severity: 'info', confidence: 'low', rootCause: hypothesis.reason,
    ...(hypothesis.endpointId === undefined ? {} : { endpointId: hypothesis.endpointId }),
    ...(hypothesis.source === undefined ? {} : { source: hypothesis.source }), evidenceIds: hypothesis.evidenceIds, testPlanIds: [] };
}

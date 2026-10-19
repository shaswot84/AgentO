import type { AnalysisContext, Evidence, Finding, SecurityHypothesis, SecurityTestPlan, SecurityTestResult, VerificationEngine } from '@agento/core';
import { fromCoreEvidence, type CWEPlugin, type NormalizedProbeEvidence, type ProbeTestPlan, type ProbeEvidenceCatalog } from '@agento/cwe';
import type { StoredEvidence } from '@agento/evidence';
import { VerificationError, type ModelAssessment, type VerificationDecision, type VerificationDiagnostic, type VerificationInput, type VerifierOptions } from './contracts.js';
import { canonical, checkedRecord, freeze, targetMatches } from './value.js';

/** Rules interpret facts. This boundary binds those facts to a retained run and completed test. */
export class VerificationJudge implements VerificationEngine {
  readonly #plugins = new Map<string, CWEPlugin>();
  readonly #store: VerifierOptions['evidenceStore'];
  readonly #environmentId: string;
  constructor(options: VerifierOptions) {
    this.#store = options.evidenceStore;
    this.#environmentId = options.environmentId ?? 'default';
    if (!this.#store || !this.#environmentId.trim()) throw new VerificationError('invalid-options');
    for (const plugin of options.plugins) {
      if (this.#plugins.has(plugin.cweId) || plugin.metadata().cweId !== plugin.cweId) throw new VerificationError('invalid-options');
      this.#plugins.set(plugin.cweId, plugin);
    }
  }
  async verify(context: AnalysisContext, hypothesis: SecurityHypothesis, plans: readonly SecurityTestPlan[],
    results: readonly SecurityTestResult[]): Promise<Finding> {
    return (await this.judge({ context, hypothesis, plans, results })).finding;
  }
  async judge(input: VerificationInput, assessment?: unknown): Promise<VerificationDecision> {
    // Callers cannot change an in-flight decision by mutating their inputs.
    let snapshot: VerificationInput;
    try { snapshot = freeze(structuredClone(input)); }
    catch { throw new VerificationError('invalid-context'); }
    const { context, hypothesis, plans, results } = snapshot;
    let modelInput: unknown = assessment;
    try { if (assessment !== undefined) modelInput = structuredClone(assessment); }
    catch { modelInput = null; }
    const rule = this.#plugins.get(hypothesis.cweId);
    if (!rule || hypothesis.projectId !== context.project.id || hypothesis.status !== 'HYPOTHESIS') throw new VerificationError('invalid-hypothesis');
    const records = new Map<string, StoredEvidence>();
    for (const item of context.evidence) {
      if (records.has(item.id) || item.projectId !== context.project.id) throw new VerificationError('invalid-context');
      const record = this.resolve(item);
      if (!record) throw new VerificationError('missing-evidence');
      records.set(record.id, record);
    }
    if (new Set(hypothesis.evidenceIds).size !== hypothesis.evidenceIds.length
      || hypothesis.evidenceIds.some(id => !records.has(id))) throw new VerificationError('invalid-hypothesis');
    const safeContext = freeze({ ...context, evidence: [...records.values()] });
    let expected: readonly SecurityTestPlan[];
    try { expected = await rule.generateTests(safeContext, hypothesis); }
    catch { throw new VerificationError('invalid-hypothesis'); }
    const diagnostics = new Set<VerificationDiagnostic>();
    if (!plans.length || !results.length) diagnostics.add('incomplete-execution');
    const acceptedPlans = new Map<string, SecurityTestPlan>();
    const duplicatePlans = duplicates(plans.map(plan => plan.id));
    for (const plan of plans) {
      const original = expected.find(item => item.id === plan.id);
      if (duplicatePlans.has(plan.id) || !original || plan.hypothesisId !== hypothesis.id || plan.cweId !== hypothesis.cweId
        || !targetMatches(plan.targetUrl, original.targetUrl)
        || !context.project.allowedOrigins.includes(new URL(plan.targetUrl).origin)
        || original.requiredCapabilities.some(id => !plan.requiredCapabilities.includes(id))
        || canonical([...plan.identityIds].sort()) !== canonical([...original.identityIds].sort())) {
        diagnostics.add('invalid-plan'); continue;
      }
      acceptedPlans.set(plan.id, plan);
    }
    const proofs = new Map<string, { record: StoredEvidence; probe: NormalizedProbeEvidence }>();
    const duplicateResults = duplicates(results.map(result => result.id));
    const duplicateResultPlans = duplicates(results.map(result => result.planId));
    const repeatedEvidence = duplicates(results.flatMap(result => result.evidence.map(item => item.id)));
    const acceptedResults: SecurityTestResult[] = [];
    for (const result of results) {
      const plan = acceptedPlans.get(result.planId);
      if (!plan || duplicateResults.has(result.id) || duplicateResultPlans.has(result.planId)) { diagnostics.add('invalid-result'); continue; }
      if (result.outcome !== 'COMPLETED' || result.error) { diagnostics.add('incomplete-execution'); continue; }
      const retained: StoredEvidence[] = [];
      for (const supplied of result.evidence) {
        const record = records.get(supplied.id);
        const probe = record && fromCoreEvidence(record);
        if (!record || canonical(record) !== canonical(supplied) || repeatedEvidence.has(supplied.id) || !probe
          || hypothesis.endpointId !== undefined && record.endpointId !== hypothesis.endpointId
          || probe.probeId !== rule.metadata().probeId || record.provenance.probeId !== probe.probeId
          || record.provenance.environment.id !== this.#environmentId
          || !targetMatches(record.provenance.environment.baseUrl, context.project.baseUrl)
          || !targetMatches(record.provenance.environment.targetUrl, plan.targetUrl)
          || !probeTargets(probe).every(url => targetMatches(url, plan.targetUrl))
          || plan.requiredCapabilities.some(id => !record.provenance.capabilityIds.includes(id))) {
          diagnostics.add('unusable-evidence'); continue;
        }
        retained.push(record); proofs.set(record.id, { record, probe });
      }
      acceptedResults.push({ ...result, evidence: retained });
    }
    const orderedProofs = [...proofs.values()].sort((a, b) => a.record.id.localeCompare(b.record.id, 'en'));
    const boundScope = (expected as readonly ProbeTestPlan[])[0]?.scope;
    const votes = boundScope ? await Promise.all(orderedProofs.map(async ({ record, probe }) => ({
      id: record.id, verdict: await rule.evaluate([probe], boundScope),
    }))) : [];
    const positive = votes.filter(item => item.verdict.status === 'CONFIRMED');
    const negative = votes.filter(item => item.verdict.status === 'REJECTED');
    const incomplete = votes.filter(item => item.verdict.status === 'NOT_REPRODUCED');
    let finding = await rule.evaluateEvidence(safeContext, hypothesis,
      acceptedResults.sort((a, b) => a.id.localeCompare(b.id, 'en')).map(result => ({ ...result,
        evidence: [...result.evidence].sort((a, b) => a.id.localeCompare(b.id, 'en')) })));
    if (positive.length && negative.length) {
      diagnostics.add('conflicting-evidence');
      finding = { ...finding, status: 'NOT_REPRODUCED', confidence: 'low',
        rootCause: 'Runtime observations conflict in the selected environment. A consistent vulnerability verdict was not established.' };
    } else if (finding.status === 'CONFIRMED' && !positive.length || !positive.length && (incomplete.length || !votes.length)) {
      finding = { ...finding, status: 'NOT_REPRODUCED', confidence: 'low',
        rootCause: 'Completed, attributable runtime proof did not establish the suspected vulnerability.' };
    } else if (finding.status === 'REJECTED' && negative.length) {
      // A safe observation describes this tested environment; the original suspicion was not reproduced.
      finding = { ...finding, status: 'NOT_REPRODUCED', confidence: 'medium' };
    }
    const staticEvidenceIds = hypothesis.evidenceIds.filter(id => {
      const record = records.get(id)!;
      return ['source-location', 'static-analysis', 'configuration'].includes(record.kind) && !fromCoreEvidence(record);
    }).sort();
    const runtimeEvidenceIds = orderedProofs.map(item => item.record.id);
    finding = freeze({ ...finding, evidenceIds: [...new Set([...staticEvidenceIds, ...runtimeEvidenceIds])].sort(),
      testPlanIds: [...acceptedPlans.keys()].sort() });
    const modelAssessment = modelInput === undefined ? null : validateAssessment(modelInput, finding, new Set(finding.evidenceIds));
    if (modelInput !== undefined && !modelAssessment) diagnostics.add('model-assessment-rejected');
    return freeze({ schemaVersion: 1, finding, staticEvidenceIds, runtimeEvidenceIds,
      diagnostics: [...diagnostics].sort(), modelAssessment });
  }
  private resolve(item: Evidence): StoredEvidence | undefined {
    try {
      const record = this.#store.get(item.id);
      if (!record || canonical(record) !== canonical(item)) return;
      return checkedRecord(record);
    } catch { return; }
  }
}
function duplicates(ids: readonly string[]): Set<string> {
  const seen = new Set<string>(), repeated = new Set<string>();
  for (const id of ids) { if (seen.has(id)) repeated.add(id); seen.add(id); }
  return repeated;
}
function probeTargets(probe: NormalizedProbeEvidence): readonly string[] {
  switch (probe.probeId) {
    case 'cookie-security': return (probe as ProbeEvidenceCatalog['cookie-security']).observations.map(item => item.response.url);
    case 'cross-origin': return (probe as ProbeEvidenceCatalog['cross-origin']).observations.flatMap(item => [item.preflight.response.url, item.actual.response.url]);
    case 'authorization': { const item = probe as ProbeEvidenceCatalog['authorization']; return [item.owner.url, item.attacker.url, item.anonymous.url]; }
    case 'xss': { const item = probe as ProbeEvidenceCatalog['xss']; return [item.baseline.url, item.injected.url, ...(item.browser ? [item.browser.url] : [])]; }
    case 'sql-injection': { const item = probe as ProbeEvidenceCatalog['sql-injection']; return [item.baseline.url, ...item.observations.map(observation => observation.response.url)]; }
    default: return [];
  }
}
function validateAssessment(value: unknown, finding: Finding, allowed: Set<string>): ModelAssessment | null {
  const object = (item: unknown): item is Record<string, unknown> => !!item && typeof item === 'object' && !Array.isArray(item);
  if (!object(value) || Object.keys(value).some(key => !['status', 'claims'].includes(key))
    || value.status !== finding.status || !Array.isArray(value.claims) || !value.claims.length || value.claims.length > 32) return null;
  for (const claim of value.claims) {
    if (!object(claim) || Object.keys(claim).some(key => !['text', 'evidenceIds'].includes(key))
      || typeof claim.text !== 'string' || !claim.text.trim() || claim.text.length > 4000
      || !Array.isArray(claim.evidenceIds) || !claim.evidenceIds.length
      || new Set(claim.evidenceIds).size !== claim.evidenceIds.length
      || claim.evidenceIds.some(id => typeof id !== 'string' || !allowed.has(id))) return null;
  }
  return freeze(structuredClone(value)) as unknown as ModelAssessment;
}

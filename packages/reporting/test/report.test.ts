import { describe, expect, it } from 'vitest';
import { MemoryEvidenceStore } from '@agento/evidence';
import { buildSecurityReport, FINDING_STATUSES, reportToJSON, reportToMarkdown, ReportingError } from '../src/index.js';
import { fixture, generatedAt } from './helpers.js';

describe('evidence-linked developer reports', () => {
  it('includes source, endpoint, root cause, immutable proof, and reproducible test steps', () => {
    const { input, store } = fixture();
    const report = buildSecurityReport(input, { evidenceStore: store, generatedAt });
    expect(report.findings[0]).toMatchObject({ status: 'CONFIRMED', owaspCategory: 'A01:2025', cweId: 'CWE-639',
      severity: 'high', confidence: 'high', source: { location: { file: 'src/routes/orders.ts', startLine: 24 }, evidenceIds: ['source'] },
      endpoint: { method: 'GET', path: '/api/orders/:id' }, rootCause: { evidenceIds: ['runtime', 'source'] },
      verification: { source: 'judge' }, remediation: { status: 'NOT_PROVIDED' }, retest: { status: 'NOT_RUN' } });
    expect(report.findings[0]!.testPlans[0]!.steps).toHaveLength(2);
    expect(report.findings[0]!.executions).toEqual([{ id: 'result', planId: 'plan', outcome: 'COMPLETED', evidenceIds: ['runtime'] }]);
    expect(report.evidence.find(item => item.id === 'runtime')).toEqual(store.get('runtime'));
    expect(report.summary).toMatchObject({ total: 1, byStatus: { CONFIRMED: 1 }, confirmedBySeverity: { high: 1 } });
    const json = reportToJSON(report), markdown = reportToMarkdown(report);
    expect(JSON.parse(json)).toEqual(report);
    expect(markdown).toContain('src/routes/orders.ts:24');
    expect(markdown).toContain('ownerMarkersMatch');
    expect(markdown).toContain('Read the same order as a second user');
    expect(markdown).toContain('"status": 200');
    for (const text of [json, markdown]) expect(text).not.toMatch(/PRIVATE_PASSWORD|PRIVATE_SESSION|private:order-id|PRIVATE_ADAPTER_DEBUG|private-value|\/private\/repository/);
  });
  it.each(FINDING_STATUSES)('preserves the supplied %s state without inferring a new verdict', status => {
    const { input, store } = fixture(status);
    const report = buildSecurityReport(input, { evidenceStore: store, generatedAt });
    expect(report.findings[0]!.status).toBe(status);
    expect(report.summary.byStatus[status]).toBe(1);
    expect(report.summary.confirmedBySeverity.high).toBe(status === 'CONFIRMED' ? 1 : 0);
  });
  it('keeps unassessed hypotheses distinct, without an invented severity or root cause', () => {
    const { input, store, hypothesis } = fixture();
    const report = buildSecurityReport({ ...input, findings: [], decisions: [], results: [], hypotheses: [hypothesis] }, { evidenceStore: store, generatedAt });
    expect(report.findings[0]).toMatchObject({ id: 'hypothesis:hypothesis', status: 'HYPOTHESIS', severity: null, confidence: null,
      assessment: { text: hypothesis.reason, evidenceIds: ['source'] }, rootCause: null, runtimeEvidenceIds: [],
      verification: { source: 'hypothesis' }, retest: { status: 'NOT_RUN' } });
    expect(reportToMarkdown(report)).toContain('A hypothesis is unverified');
  });
  it('permits an empty assessment without claiming the application is secure', () => {
    const { input, store } = fixture();
    const report = buildSecurityReport({ context: input.context, findings: [] }, { evidenceStore: store, generatedAt });
    expect(report.summary.total).toBe(0); expect(report.evidence).toEqual([]);
    expect(reportToMarkdown(report)).toContain('This report makes no claim that the application is secure');
  });
  it('includes supplied remediation and regression text with citations, without testing a fix', () => {
    const { input, store } = fixture();
    const report = buildSecurityReport({ ...input, remediation: [{ findingId: 'finding', explanation: 'Compare the current user with the object owner.',
      patch: 'if (order.userId !== user.id) return deny();', regressionTest: 'A second user must receive 403.', evidenceIds: ['source', 'runtime'] }] }, { evidenceStore: store, generatedAt });
    expect(report.findings[0]!.remediation).toMatchObject({ status: 'SUGGESTED', patch: { evidenceIds: ['runtime', 'source'] } });
    expect(report.findings[0]!.retest.status).toBe('NOT_RUN');
    expect(reportToMarkdown(report)).toContain('A second user must receive 403.');
  });
  it('keeps failed or skipped execution separate from vulnerability status', () => {
    for (const outcome of ['FAILED', 'SKIPPED'] as const) {
      const { input, store, result } = fixture('NOT_REPRODUCED');
      const report = buildSecurityReport({ ...input, results: [{ ...result, outcome, evidence: [] }] }, { evidenceStore: store, generatedAt });
      expect(report.findings[0]!.executions[0]!.outcome).toBe(outcome);
      expect(report.findings[0]!.status).toBe('NOT_REPRODUCED');
    }
  });
  it('omits uncited root cause and locations and explains absent proof', () => {
    const { input, store, finding } = fixture('NOT_REPRODUCED');
    const report = buildSecurityReport({ ...input, context: { ...input.context,
      endpoints: input.context.endpoints.map(item => ({ ...item, evidenceIds: [] })) },
      findings: [{ ...finding, evidenceIds: [] }], decisions: [], results: [] }, { evidenceStore: store, generatedAt });
    expect(report.findings[0]).toMatchObject({ rootCause: null, source: null, endpoint: null,
      diagnostics: ['no-runtime-proof', 'uncited-endpoint-omitted', 'uncited-root-cause-omitted', 'uncited-source-omitted'] });
  });
  it('cites retained handler context separately from a finding assessment', () => {
    const { input, store, finding } = fixture('NOT_REPRODUCED');
    const report = buildSecurityReport({ ...input, findings: [{ ...finding, evidenceIds: ['runtime'] }], decisions: [] }, { evidenceStore: store, generatedAt });
    expect(report.findings[0]!.source?.evidenceIds).toEqual(['source']);
    expect(report.findings[0]!.contextEvidenceIds).toEqual(['source']);
    expect(report.findings[0]!.rootCause?.evidenceIds).toEqual(['runtime']);
    expect(report.findings[0]!.staticEvidenceIds).toEqual([]);
  });
  it('copies inputs, deeply freezes reports, and gives stable exports for a fixed timestamp', () => {
    const { input, store } = fixture();
    const report = buildSecurityReport(input, { evidenceStore: store, generatedAt });
    const reordered = { ...input, findings: [...input.findings].reverse(), results: [...input.results!].reverse() };
    expect(buildSecurityReport(reordered, { evidenceStore: store, generatedAt })).toEqual(report);
    function check(item: unknown): void { if (!item || typeof item !== 'object') return;
      expect(Object.isFrozen(item)).toBe(true); for (const child of Object.values(item)) check(child); }
    check(report);
    (input.findings[0] as { title: string }).title = 'Changed';
    expect(report.findings[0]!.title).toBe('Order ownership check is missing');
    expect(reportToMarkdown(JSON.parse(reportToJSON(report)))).toBe(reportToMarkdown(report));
  });
  it('orders confirmed findings before hypotheses and counts their severity separately', () => {
    const { input, store, hypothesis } = fixture();
    const data = { ...input, hypotheses: [{ ...hypothesis, id: 'pending' }, hypothesis] };
    const report = buildSecurityReport(data, { evidenceStore: store, generatedAt });
    expect(report.findings.map(item => item.status)).toEqual(['CONFIRMED', 'HYPOTHESIS']);
    expect(report.summary).toMatchObject({ total: 2, byStatus: { CONFIRMED: 1, HYPOTHESIS: 1 }, confirmedBySeverity: { high: 1, info: 0 } });
    expect(buildSecurityReport({ ...data, hypotheses: [...data.hypotheses].reverse() }, { evidenceStore: store, generatedAt })).toEqual(report);
    expect(() => buildSecurityReport(data, { evidenceStore: store, maxFindings: 1 })).toThrow('report-limit');
  });
  it('resolves every nested claim citation to the embedded immutable record', () => {
    const { input, store } = fixture();
    const report = buildSecurityReport(input, { evidenceStore: store, generatedAt });
    const records = new Map(report.evidence.map(record => [record.id, record]));
    function check(value: unknown): void {
      if (!value || typeof value !== 'object') return;
      const item = value as Record<string, unknown>;
      if (Array.isArray(item.evidenceIds)) for (const ref of item.evidenceIds) expect(records.has(ref)).toBe(true);
      for (const child of Object.values(item)) check(child);
    }
    check(report.findings);
    for (const record of report.evidence) expect(record.digest).toBe(store.get(record.id)!.digest);
  });
});

describe('reference and integrity failures', () => {
  it('rejects missing, unretained, changed, or cross-project evidence with fixed errors', () => {
    const { input, store } = fixture();
    const original = store.get('source')!;
    const other = new MemoryEvidenceStore();
    other.capture([{ ...original, projectId: 'other' }], { project: { ...input.context.project, id: 'other' }, capabilityIds: ['framework-analysis'] });
    for (const [record, error] of [[undefined, 'missing-evidence'], [{ ...original, digest: undefined }, 'integrity-failed'],
      [{ ...original, summary: 'Damaged' }, 'integrity-failed'], [other.get('source'), 'project-mismatch']] as const) {
      expect(() => buildSecurityReport(input, { evidenceStore: { capture: () => [], get: ref => ref === 'source' ? record as never : store.get(ref) }, generatedAt })).toThrow(error);
    }
  });
  it('rejects duplicate IDs and evidence references', () => {
    const { input, store, finding } = fixture();
    for (const data of [{ ...input, findings: [finding, finding] }, { ...input, findings: [{ ...finding, evidenceIds: ['source', 'source'] }] },
      { ...input, plans: [...input.plans!, ...input.plans!] }, { ...input, decisions: [...input.decisions!, ...input.decisions!] },
      { ...input, hypotheses: [...input.hypotheses!, ...input.hypotheses!] }]) {
      expect(() => buildSecurityReport(data, { evidenceStore: store, generatedAt })).toThrow('duplicate-id');
    }
  });
  it('rejects unrelated plans, results, decisions, and remediation claims', () => {
    const { input, store, finding, plan, result } = fixture();
    for (const data of [{ ...input, findings: [{ ...finding, testPlanIds: ['unknown'] }], decisions: [] },
      { ...input, plans: [{ ...plan, cweId: 'CWE-79' as const }] }, { ...input, results: [{ ...result, planId: 'unrelated' }] },
      { ...input, decisions: [{ ...input.decisions![0]!, finding: { ...finding, status: 'LIKELY' as const } }] },
      { ...input, decisions: [{ ...input.decisions![0]!, staticEvidenceIds: ['runtime'] }] },
      { ...input, remediation: [{ findingId: 'finding', explanation: 'Unsupported', evidenceIds: [] }] }]) {
      expect(() => buildSecurityReport(data, { evidenceStore: store, generatedAt })).toThrow('unrelated-reference');
    }
  });
  it('rejects confirmation without a completed, cited runtime test', () => {
    const { input, store, finding, result } = fixture();
    for (const data of [{ ...input, results: [] }, { ...input, results: [{ ...result, outcome: 'SKIPPED' as const }] },
      { ...input, findings: [{ ...finding, evidenceIds: ['source'] }], decisions: [] }]) {
      expect(() => buildSecurityReport(data, { evidenceStore: store, generatedAt })).toThrow('unrelated-reference');
    }
  });
  it('rejects changes to a stored result copy even if the store remains valid', () => {
    const { input, store, result } = fixture();
    expect(() => buildSecurityReport({ ...input, results: [{ ...result, evidence: [{ ...result.evidence[0]!, facts: { status: 403 } }] }] }, { evidenceStore: store, generatedAt })).toThrow('integrity-failed');
  });
  it('rejects runtime proof explicitly attributed to a different endpoint', () => {
    const { input, store, result } = fixture();
    const replacement = new MemoryEvidenceStore();
    const proof = store.get('runtime')!;
    replacement.capture([{ ...proof, endpointId: 'other-endpoint' }], {
      project: input.context.project, capabilityIds: ['request-executor'], probeId: 'authorization',
    });
    const evidenceStore = { capture: () => [], get: (ref: string) => replacement.get(ref) ?? store.get(ref) };
    expect(() => buildSecurityReport({ ...input, results: [{ ...result, evidence: [replacement.get('runtime')!] }] }, { evidenceStore })).toThrow('unrelated-reference');
  });
  it('rejects forged lookup aliases and protects evidence identifiers from redaction', () => {
    const { input, store } = fixture();
    expect(() => buildSecurityReport(input, { evidenceStore: { capture: () => [], get: () => store.get('runtime') } })).toThrow('unrelated-reference');
    expect(() => buildSecurityReport(input, { evidenceStore: store, secrets: ['source'] })).toThrow('invalid-input');
  });
  it('enforces output limits and options', () => {
    const { input, store } = fixture();
    for (const options of [{ maxFindings: 0 }, { maxEvidence: Infinity }, { maxReportBytes: -1 }, { generatedAt: 'invalid' }, { secrets: [''] }]) {
      expect(() => buildSecurityReport(input, { evidenceStore: store, ...options })).toThrow('invalid-options');
    }
    expect(() => buildSecurityReport(input, { evidenceStore: store, maxEvidence: 1 })).toThrow('report-limit');
    expect(() => buildSecurityReport(input, { evidenceStore: store, maxReportBytes: 100 })).toThrow('report-limit');
  });
  it('rejects invalid states and unsafe JSON without invoking getters', () => {
    const { input, store, finding } = fixture();
    expect(() => buildSecurityReport({ ...input, findings: [{ ...finding, status: 'FIX_VERIFIED' as never }] }, { evidenceStore: store })).toThrow(ReportingError);
    let called = false;
    const accessor = Object.defineProperty({}, 'findings', { enumerable: true, get() { called = true; return []; } });
    expect(() => buildSecurityReport(accessor as never, { evidenceStore: store })).toThrow('invalid-input');
    expect(called).toBe(false);
    const cyclic = { ...input } as unknown as Record<string, unknown>; cyclic.self = cyclic;
    expect(() => buildSecurityReport(cyclic as never, { evidenceStore: store })).toThrow('invalid-input');
  });
  it('detects report edits before export', () => {
    const { input, store } = fixture();
    const report = JSON.parse(reportToJSON(buildSecurityReport(input, { evidenceStore: store, generatedAt })));
    report.findings[0].status = 'REJECTED';
    expect(() => reportToJSON(report)).toThrow('integrity-failed');
    expect(() => reportToMarkdown(report)).toThrow('integrity-failed');
  });
});

describe('private data and Markdown boundaries', () => {
  it('uses the shared evidence redactor for prose, suggestions, and query strings', () => {
    const { input, store, finding, plan } = fixture();
    const secret = 'host-private-marker';
    const report = buildSecurityReport({ ...input, decisions: [], findings: [{ ...finding, title: `Found ${secret}`, rootCause: 'Authorization: Bearer secretbearer' }],
      plans: [{ ...plan, steps: [{ ...plan.steps[0]!, action: `Read ${encodeURIComponent(secret)}` }] }],
      remediation: [{ findingId: 'finding', explanation: `Remove ${secret}`, patch: `password = '${secret}'`, evidenceIds: ['source'] }] },
    { evidenceStore: store, secrets: [secret], generatedAt });
    const output = reportToJSON(report) + reportToMarkdown(report);
    expect(output).not.toMatch(/host-private-marker|secretbearer|private-value/);
    expect(output).toContain('[REDACTED]');
  });
  it('refuses to rewrite proof when the host adds a secret after retention', () => {
    const { input, store } = fixture();
    const original = store.get('source')!;
    expect(() => buildSecurityReport(input, { evidenceStore: store, secrets: ['caller-selected'] })).toThrow('unsafe-evidence');
    expect(store.get('source')).toBe(original);
  });
  it('escapes report text, keeps malicious snippets inside code fences, and resolves every evidence link', () => {
    const { input, store, finding } = fixture();
    const attack = '<script>alert(1)</script>\n![image](https://outside.test)\n# Injected | [click](javascript:alert(1))';
    const report = buildSecurityReport({ ...input, decisions: [], findings: [{ ...finding, title: attack, rootCause: attack }],
      remediation: [{ findingId: 'finding', explanation: attack, patch: '```\n# payload\n```', evidenceIds: ['source'] }] }, { evidenceStore: store, generatedAt });
    const markdown = reportToMarkdown(report);
    expect(markdown).not.toContain('<script>'); expect(markdown).not.toContain('\n# Injected');
    expect(markdown).not.toContain('![image]('); expect(markdown).not.toContain('[click](javascript:');
    expect(markdown).toContain('````\n```\n# payload\n```\n````');
    const targets = [...markdown.matchAll(/\]\(#(evidence-[a-f0-9]+)\)/g)].map(match => match[1]);
    expect(targets.length).toBeGreaterThan(0);
    for (const target of targets) expect(markdown).toContain(`<a id="${target}"></a>`);
  });
});

import { describe, expect, it } from 'vitest';
import type { AnalysisContext, CWEId, Evidence } from '@agento/core';
import { CWE79Plugin, CWE89Plugin, CWE639Plugin, CWE862Plugin, CWE942Plugin, CWE1004Plugin, CWE614Plugin,
  toCoreEvidence, type NormalizedProbeEvidence, type ProbeTestPlan } from '@agento/cwe';
import { MemoryEvidenceStore } from '@agento/evidence';
import { VerificationJudge, type VerificationInput } from '../src/index.js';
import { authorization, context, cookies, cors, policy, response, route, sql, xss } from './helpers.js';

const options = { sensitiveCookieNames: ['sid'], untrustedOrigins: ['https://unapproved.invalid'], authorizationPolicies: [policy] };
const rules = [new CWE639Plugin(options), new CWE862Plugin(options), new CWE942Plugin(options), new CWE1004Plugin(options),
  new CWE614Plugin(options), new CWE79Plugin(options), new CWE89Plugin(options)];
const observations: Record<string, () => NormalizedProbeEvidence> = {
  'CWE-639': authorization, 'CWE-862': authorization, 'CWE-942': cors, 'CWE-1004': cookies,
  'CWE-614': cookies, 'CWE-79': xss, 'CWE-89': sql,
};
async function fixture(cweId: CWEId = 'CWE-614', probes?: readonly NormalizedProbeEvidence[]) {
  const rule = rules.find(item => item.cweId === cweId)!;
  const store = new MemoryEvidenceStore();
  const initial = context();
  const source = store.capture([route], { project: initial.project, capabilityIds: ['route-extraction'] });
  const ctx: AnalysisContext = { ...initial, evidence: source };
  const hypothesis = (await rule.detectCandidates(ctx))[0]!;
  expect(hypothesis).toBeDefined();
  const plans = await rule.generateTests(ctx, hypothesis);
  const plan = plans[0]!;
  const proof = store.capture((probes ?? [observations[cweId]!()]).map(probe => toCoreEvidence(probe, 'order')),
    { project: ctx.project, targetUrl: plan.targetUrl, capabilityIds: plan.requiredCapabilities });
  const input: VerificationInput = { context: { ...ctx, evidence: [...source, ...proof] }, hypothesis, plans,
    results: [{ id: 'result', planId: plan.id, producerId: 'runner', outcome: 'COMPLETED', summary: 'Observed.', evidence: proof }] };
  return { judge: new VerificationJudge({ plugins: [rule], evidenceStore: store }), store, input, rule, proof, plan };
}
function changed(f: Awaited<ReturnType<typeof fixture>>, extra: Partial<VerificationInput>): VerificationInput { return { ...f.input, ...extra }; }

describe('grounded deterministic verdicts', () => {
  it.each(rules.map(rule => rule.cweId))('confirms attributable dynamic proof for %s', async cweId => {
    const f = await fixture(cweId);
    const result = await f.judge.judge(f.input);
    expect(result.finding.status).toBe('CONFIRMED');
    expect(result.runtimeEvidenceIds).toEqual([f.proof[0]!.id]);
    expect(result.staticEvidenceIds).toContain('route');
    expect(result.diagnostics).toEqual([]);
    expect(Object.isFrozen(result.finding.evidenceIds)).toBe(true);
    expect(await f.judge.judge(f.input)).toEqual(result);
  });
  it.each(rules.map(rule => rule.cweId))('cannot confirm %s with static evidence alone', async cweId => {
    const f = await fixture(cweId);
    const input = changed(f, { results: [{ ...f.input.results[0]!, evidence: [f.input.context.evidence[0]!] }] });
    expect((await f.judge.judge(input)).finding.status).toBe('NOT_REPRODUCED');
  });
  it.each(['FAILED', 'SKIPPED'] as const)('does not infer a verdict from %s execution', async outcome => {
    const f = await fixture();
    expect((await f.judge.judge(changed(f, { results: [{ ...f.input.results[0]!, outcome }] }))).finding.status).toBe('NOT_REPRODUCED');
  });
  it('reports no-execution and completed-with-error cases without confirmation', async () => {
    const f = await fixture();
    for (const results of [[], [{ ...f.input.results[0]!, error: { code: 'partial', message: 'Unavailable' } }]]) {
      expect((await f.judge.judge(changed(f, { results }))).finding.status).toBe('NOT_REPRODUCED');
    }
  });
  it('uses target runtime configuration instead of static cookie suspicion', async () => {
    const safe = cookies();
    const f = await fixture('CWE-614', [{ ...safe, observations: safe.observations.map(item => ({ ...item,
      cookies: item.cookies.map(cookie => ({ ...cookie, secure: true })) })) }]);
    const result = await f.judge.judge(f.input);
    expect(result.finding.status).toBe('NOT_REPRODUCED');
    expect(result.finding.confidence).toBe('medium');
  });
  it('does not confirm reflection or visible canaries without script execution', async () => {
    const f = await fixture('CWE-79', [xss({ executionConfirmed: null, domSinkReached: null })]);
    expect((await f.judge.judge(f.input)).finding.status).toBe('NOT_REPRODUCED');
  });
  it('handles conflicting safe and vulnerable observations without ordering bias', async () => {
    const unsafe = cookies(), safe = { ...cookies(), id: 'safe' };
    const f = await fixture('CWE-614', [unsafe, { ...safe, observations: safe.observations.map(item => ({ ...item,
      cookies: item.cookies.map(cookie => ({ ...cookie, secure: true })) })) }]);
    const a = await f.judge.judge(f.input);
    const b = await f.judge.judge(changed(f, { context: { ...f.input.context, evidence: [...f.input.context.evidence].reverse() },
      results: f.input.results.map(item => ({ ...item, evidence: [...item.evidence].reverse() })) }));
    expect(a).toEqual(b); expect(a.finding.status).toBe('NOT_REPRODUCED');
    expect(a.diagnostics).toContain('conflicting-evidence');
  });
});

describe('lineage and integrity failures', () => {
  it.each(['planId', 'duplicate-result', 'duplicate-plan', 'duplicate-proof', 'hypothesis', 'target', 'capabilities', 'identity'])(
    'excludes invalid %s bindings', async kind => {
      const f = await fixture(); let input = f.input;
      if (kind === 'planId') input = changed(f, { results: [{ ...input.results[0]!, planId: 'other' }] });
      if (kind === 'duplicate-result') input = changed(f, { results: [...input.results, ...input.results] });
      if (kind === 'duplicate-plan') input = changed(f, { plans: [...input.plans, ...input.plans] });
      if (kind === 'duplicate-proof') input = changed(f, { results: [{ ...input.results[0]!, evidence: [...f.proof, ...f.proof] }] });
      if (kind === 'hypothesis') input = changed(f, { plans: [{ ...f.plan, hypothesisId: 'other' }] });
      if (kind === 'target') input = changed(f, { plans: [{ ...f.plan, targetUrl: 'https://foreign.test/orders/1' }] });
      if (kind === 'capabilities') input = changed(f, { plans: [{ ...f.plan, requiredCapabilities: [] }] });
      if (kind === 'identity') input = changed(f, { plans: [{ ...f.plan, identityIds: ['unknown'] }] });
      expect((await f.judge.judge(input)).finding.status).toBe('NOT_REPRODUCED');
    });
  it.each(['endpoint', 'environment', 'provenance-target', 'capability', 'probe'])('excludes wrong %s provenance', async kind => {
    const f = await fixture();
    const raw = toCoreEvidence(cookies({ id: 'foreign' }), kind === 'endpoint' ? 'other' : 'order');
    const [proof] = f.store.capture([raw], { project: f.input.context.project,
      targetUrl: kind === 'provenance-target' ? 'https://shop.test/other' : f.plan.targetUrl,
      environmentId: kind === 'environment' ? 'staging' : 'default',
      capabilityIds: kind === 'capability' ? ['other'] : f.plan.requiredCapabilities,
      ...(kind === 'probe' ? { probeId: 'other' } : {}) });
    const input = changed(f, { context: { ...f.input.context, evidence: [...f.input.context.evidence, proof!] },
      results: [{ ...f.input.results[0]!, evidence: [proof!] }] });
    expect((await f.judge.judge(input)).finding.status).toBe('NOT_REPRODUCED');
  });
  it('checks actual response paths against a concrete planned target', async () => {
    const f = await fixture('CWE-614', [cookies({ observations: cookies().observations.map(item => ({ ...item,
      response: response({ url: 'https://shop.test/orders/2' }) })) })]);
    expect((await f.judge.judge(f.input)).finding.status).toBe('NOT_REPRODUCED');
  });
  it('rejects modified and missing retained evidence', async () => {
    const f = await fixture();
    for (const evidence of [f.input.context.evidence.map(item => ({ ...item, summary: 'Changed' })),
      [...f.input.context.evidence, { ...route, id: 'missing' }]]) {
      await expect(f.judge.judge(changed(f, { context: { ...f.input.context, evidence } }))).rejects.toMatchObject({ code: 'missing-evidence' });
    }
  });
  it('does not accept a changed result copy of a valid retained record', async () => {
    const f = await fixture();
    const result = await f.judge.judge(changed(f, { results: [{ ...f.input.results[0]!, evidence: f.proof.map(item => ({ ...item, summary: 'Changed' })) }] }));
    expect(result.finding.status).toBe('NOT_REPRODUCED');
  });
  it('rejects corrupt record digests from a custom store', async () => {
    const f = await fixture();
    const judge = new VerificationJudge({ plugins: [f.rule], evidenceStore: { capture: () => [],
      get: id => { const record = f.store.get(id); return record ? { ...record, digest: '0'.repeat(64) } as Evidence : undefined; } } });
    await expect(judge.judge(f.input)).rejects.toMatchObject({ code: 'missing-evidence' });
  });
  it('rejects cross-project, duplicate context IDs, unregistered CWEs, and nonexistent hypotheses', async () => {
    const f = await fixture();
    for (const input of [changed(f, { hypothesis: { ...f.input.hypothesis, projectId: 'other' } }),
      changed(f, { context: { ...f.input.context, evidence: [...f.input.context.evidence, ...f.proof] } }),
      changed(f, { hypothesis: { ...f.input.hypothesis, cweId: 'CWE-1' } }),
      changed(f, { hypothesis: { ...f.input.hypothesis, id: 'invented' } })]) await expect(f.judge.judge(input)).rejects.toThrow();
  });
});

describe('model claims', () => {
  it('retains only a bounded explanation with valid citations and an agreeing verdict', async () => {
    const f = await fixture();
    const model = { status: 'CONFIRMED', claims: [{ text: 'The sensitive cookie lacks Secure.', evidenceIds: [f.proof[0]!.id] }] };
    const decision = await f.judge.judge(f.input, model);
    expect(decision.modelAssessment).toEqual(model);
    model.claims[0]!.text = 'Changed';
    expect(decision.modelAssessment!.claims[0]!.text).not.toBe('Changed');
  });
  it.each(['no-citations', 'unknown', 'unrelated', 'disagreement', 'hidden-prose', 'empty', 'too-long', 'duplicate-citation', 'uncloneable'])(
    'rejects %s model output and preserves the deterministic decision', async kind => {
      const f = await fixture();
      const extra = f.store.capture([{ ...route, id: 'unrelated' }], { project: f.input.context.project, capabilityIds: ['route-extraction'] });
      const input = changed(f, { context: { ...f.input.context, evidence: [...f.input.context.evidence, ...extra] } });
      const claim = { text: 'Observed.', evidenceIds: [f.proof[0]!.id] };
      let value: unknown = { status: 'CONFIRMED', claims: [claim] };
      if (kind === 'no-citations') claim.evidenceIds = [];
      if (kind === 'unknown') claim.evidenceIds = ['not-stored'];
      if (kind === 'unrelated') claim.evidenceIds = ['unrelated'];
      if (kind === 'disagreement') value = { status: 'REJECTED', claims: [claim] };
      if (kind === 'hidden-prose') value = { status: 'CONFIRMED', claims: [claim], explanation: 'No citation.' };
      if (kind === 'empty') value = { status: 'CONFIRMED', claims: [] };
      if (kind === 'too-long') claim.text = 'a'.repeat(4001);
      if (kind === 'duplicate-citation') claim.evidenceIds.push(claim.evidenceIds[0]!);
      if (kind === 'uncloneable') value = { status: 'CONFIRMED', claims: [claim], callback: () => {} };
      const decision = await f.judge.judge(input, value);
      expect(decision.finding.status).toBe('CONFIRMED');
      expect(decision.modelAssessment).toBeNull();
      expect(decision.diagnostics).toContain('model-assessment-rejected');
    });
  it('cannot promote static evidence through a cited model claim', async () => {
    const f = await fixture();
    const decision = await f.judge.judge(changed(f, { results: [] }), {
      status: 'CONFIRMED', claims: [{ text: 'Vulnerable.', evidenceIds: ['route'] }],
    });
    expect(decision.finding.status).toBe('NOT_REPRODUCED'); expect(decision.modelAssessment).toBeNull();
  });
});

it('treats scanner conclusions and raw successful responses as observations', async () => {
  const f = await fixture();
  const claims = f.store.capture([
    { ...route, id: 'scanner-claim', kind: 'scanner-output', producerId: 'scanner', facts: { verified: true, severity: 'critical' } },
    { ...route, id: 'response-only', kind: 'http-response', producerId: 'http', facts: { status: 200 } },
  ], { project: f.input.context.project, targetUrl: f.plan.targetUrl, capabilityIds: f.plan.requiredCapabilities });
  const input = changed(f, { context: { ...f.input.context, evidence: [...f.input.context.evidence, ...claims] },
    results: [{ ...f.input.results[0]!, evidence: claims }] });
  expect((await f.judge.judge(input)).finding.status).toBe('NOT_REPRODUCED');
});

it('rejects a self-consistent context/store copy with an invalid content digest', async () => {
  const f = await fixture();
  const evidence = f.input.context.evidence.map(item => ({ ...item, digest: '0'.repeat(64) }));
  const judge = new VerificationJudge({ plugins: [f.rule], evidenceStore: { capture: () => [], get: id => evidence.find(item => item.id === id) } });
  await expect(judge.judge(changed(f, { context: { ...f.input.context, evidence } }))).rejects.toMatchObject({ code: 'missing-evidence' });
});

it('requires completed SQL proof beyond generic errors or scanner difference flags', async () => {
  const probe = sql();
  const f = await fixture('CWE-89', [{ ...probe,
    observations: probe.observations.map(item => ({ ...item, dbmsFingerprint: null, errorIndicators: ['sql-syntax-error'],
      comparison: { ...item.comparison, bodyEqual: null } })),
    scanner: { technique: 'time', dbmsFingerprint: null, observedDifference: true } }]);
  expect((await f.judge.judge(f.input)).finding.status).toBe('NOT_REPRODUCED');
});

import { describe, expect, it, vi } from 'vitest';
import { buildSecurityReport, reportToJSON, reportToMarkdown } from '@agento/reporting';
import { RetestEngine } from '../src/index.js';
import { authorization, fixture } from './helpers.js';

describe('original-probe fix lifecycle', () => {
  it('verifies blocked access and passing security and normal cases, preserving originals', async () => {
    const state = await fixture(), before = JSON.stringify(state.input);
    const result = await state.engine.run(state.input);
    expect(result.status).toBe('FIX_VERIFIED');
    expect(state.session.replay).toHaveBeenCalledWith(state.input.plan, 'https://127.0.0.1:4444/api/orders/101', expect.any(AbortSignal));
    expect(JSON.stringify(state.input)).toBe(before);
    expect(state.input.finding.status).toBe('CONFIRMED');
    expect(state.store.get(result.comparisonEvidenceId)!.facts).toMatchObject({ status: 'FIX_VERIFIED', securityRegression: 'PASSED', normalFlow: 'PASSED' });
    expect(state.session.dispose).toHaveBeenCalledOnce();
    expect(Object.isFrozen(result.afterEvidenceIds)).toBe(true);
    expect(JSON.stringify(result)).not.toContain('PRIVATE_INPUT');
  });
  it('records a failed fix when the original exploit still reproduces', async () => {
    const state = await fixture(); state.session.replay.mockImplementation(async (_plan, url) => authorization(url));
    expect((await state.engine.run(state.input)).status).toBe('FIX_FAILED');
  });
  it.each(['security', 'normalFlow'] as const)('does not verify when %s fails', async field => {
    const state = await fixture(); state.session.runRegression.mockResolvedValue({ security: 'PASSED', normalFlow: 'PASSED', [field]: 'FAILED' } as never);
    expect((await state.engine.run(state.input)).status).toBe('FIX_INCONCLUSIVE');
  });
  it.each(['security', 'normalFlow'] as const)('does not verify a skipped %s test', async field => {
    const state = await fixture(); state.session.runRegression.mockResolvedValue({ security: 'PASSED', normalFlow: 'PASSED', [field]: 'NOT_RUN' } as never);
    expect((await state.engine.run(state.input)).status).toBe('FIX_INCONCLUSIVE');
  });
  it.each(['create', 'regression', 'probe', 'cleanup'])('records %s failures without private error text', async stage => {
    const state = await fixture(), error = new Error('/private/secret password=private');
    if (stage === 'create') state.environment.create.mockRejectedValue(error);
    if (stage === 'regression') state.session.runRegression.mockRejectedValue(error);
    if (stage === 'probe') state.session.replay.mockRejectedValue(error);
    if (stage === 'cleanup') state.session.dispose.mockRejectedValue(error);
    const result = await state.engine.run(state.input);
    expect(result.status).toBe('FIX_INCONCLUSIVE');
    expect(JSON.stringify(state.store.get(result.comparisonEvidenceId))).not.toMatch(/private|password/);
    if (stage !== 'create') expect(state.session.dispose).toHaveBeenCalledOnce();
  });
  it.each(['crash', 'partial', 'wrong-target', 'wrong-project', 'no-private-content-proof', 'truncated'])('rejects %s as fix proof', async mode => {
    const state = await fixture();
    state.session.replay.mockImplementation(async (_plan, url) => {
      const probe = authorization(mode === 'wrong-target' ? 'https://outside.test/api/orders/101' : url, true);
      if (mode === 'crash') return { ...probe, owner: { ...probe.owner, status: 500 } };
      if (mode === 'partial') return { ...probe, outcome: 'PARTIAL', diagnostics: ['scanner-unavailable'] };
      if (mode === 'wrong-project') return { ...probe, projectId: 'other' };
      if (mode === 'no-private-content-proof') return { ...probe, attacker: { ...probe.attacker, status: 200 }, attackerComparison: { ...probe.attackerComparison, ownerMarkersMatch: null } };
      if (mode === 'truncated') return { ...probe, owner: { ...probe.owner, body: { ...probe.owner.body, truncated: true } } };
      return probe;
    });
    expect((await state.engine.run(state.input)).status).toBe('FIX_INCONCLUSIVE');
  });
  it.each(['https://outside.test', 'http://localhost:4000', 'https://127.0.0.1/path'])('rejects unsafe sandbox origin %s', async url => {
    const state = await fixture(); state.session.baseUrl = url;
    expect((await state.engine.run(state.input)).status).toBe('FIX_INCONCLUSIVE');
    expect(state.session.replay).not.toHaveBeenCalled(); expect(state.session.dispose).toHaveBeenCalledOnce();
  });
  it.each(['unconfirmed', 'plan', 'patch', 'result', 'missing-proof', 'changed-record'])('refuses invalid %s before applying anything', async mode => {
    const state = await fixture(), input = structuredClone(state.input);
    if (mode === 'unconfirmed') (input.finding as any).status = 'LIKELY';
    if (mode === 'plan') (input.plan as any).hypothesisId = 'other';
    if (mode === 'patch') (input.remediation as any).findingId = 'other';
    if (mode === 'result') (input.originalResult as any).outcome = 'SKIPPED';
    if (mode === 'missing-proof') (input.originalResult as any).evidence = [];
    if (mode === 'changed-record') (input.originalResult.evidence[0] as any).summary = 'Forged';
    await expect(state.engine.run(input)).rejects.toThrow(); expect(state.environment.create).not.toHaveBeenCalled();
  });
  it('honors cancellation before execution and records it without creating a sandbox', async () => {
    const state = await fixture(), controller = new AbortController(); controller.abort();
    expect((await state.engine.run(state.input, controller.signal)).status).toBe('FIX_INCONCLUSIVE');
    expect(state.environment.create).not.toHaveBeenCalled();
  });
  it('signals deadline cancellation to host work and cleans up', async () => {
    const state = await fixture();
    const environment = { create: vi.fn(async (_input, signal: AbortSignal) => {
      await new Promise<void>(resolve => signal.addEventListener('abort', () => resolve(), { once: true }));
      return state.session;
    }) };
    const engine = new RetestEngine({ evidenceStore: state.store, rules: [state.rule], environment, timeoutMs: 10 });
    expect((await engine.run(state.input)).status).toBe('FIX_INCONCLUSIVE'); expect(state.session.dispose).toHaveBeenCalledOnce();
  });
  it('uses unique evidence for repeated attempts and leaves earlier records fixed', async () => {
    const state = await fixture(), first = await state.engine.run(state.input), original = JSON.stringify(state.store.get(first.comparisonEvidenceId));
    const second = await state.engine.run(state.input);
    expect(first.id).not.toBe(second.id); expect(JSON.stringify(state.store.get(first.comparisonEvidenceId))).toBe(original);
  });
  it('exports comparison links and rejects forged report statuses', async () => {
    const state = await fixture(), retest = await state.engine.run(state.input);
    const input = { context: state.input.context, findings: [state.input.finding], plans: [state.input.plan], results: [state.input.originalResult], retests: [{ ...retest, adapterDebug: 'PRIVATE_ADAPTER_DETAIL' }] };
    const report = buildSecurityReport(input, { evidenceStore: state.store });
    expect(report.findings[0]!.retest.status).toBe('FIX_VERIFIED'); expect(report.findings[0]!.status).toBe('CONFIRMED');
    expect(JSON.parse(reportToJSON(report)).evidence).toHaveLength(4);
    expect(reportToMarkdown(report)).toContain('After repair:');
    expect(reportToJSON(report)).not.toContain('PRIVATE_INPUT');
    expect(reportToJSON(report)).not.toContain('PRIVATE_ADAPTER_DETAIL');
    expect(() => buildSecurityReport({ ...input, retests: [{ ...retest, status: 'FIX_FAILED' }] }, { evidenceStore: state.store })).toThrow();
    expect(() => buildSecurityReport({ ...input, retests: [retest, retest] }, { evidenceStore: state.store })).toThrow();
  });
});

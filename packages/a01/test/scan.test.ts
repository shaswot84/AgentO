import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { FileEvidenceStore } from '@agento/evidence';
import { CWE639Plugin, CWE862Plugin, fromCoreEvidence } from '@agento/cwe';
import { VerificationJudge } from '@agento/verifier';
import { ExpressFrameworkAdapter } from '@agento/framework-express';
import { A01Error, runA01Scan } from '../src/index.js';
import { setup, type Mode } from './helpers.js';

const paths: string[] = [];
function fixture(mode: Mode = 'vulnerable', failLogin = false) { const state = setup(mode, failLogin); paths.push(state.repositoryPath); return state; }
afterEach(() => { for (const path of paths.splice(0)) rmSync(path, { recursive: true, force: true }); });
describe('source-grounded authorization assessment', () => {
  it.each(['vulnerable', 'fixed'] as const)('links source, declarations, isolated sessions and stored proof in %s mode', async mode => {
    const state = fixture(mode), report = await runA01Scan(state.options);
    expect(report.hypotheses, JSON.stringify(report.diagnostics)).toHaveLength(2);
    expect(report.diagnostics).toEqual([]);
    expect(report.executions.every(item => item.outcome === 'COMPLETED'), JSON.stringify(report.executions)).toBe(true);
    expect(report.findings.map(item => item.status)).toEqual([mode === 'vulnerable' ? 'CONFIRMED' : 'NOT_REPRODUCED', mode === 'vulnerable' ? 'CONFIRMED' : 'NOT_REPRODUCED']);
    expect(state.logins).toHaveLength(4); expect(state.closed).toHaveLength(4); expect(state.calls).toHaveLength(6);
    for (const decision of report.decisions) {
      expect(decision.diagnostics).toEqual([]); expect(decision.staticEvidenceIds.length).toBeGreaterThan(0); expect(decision.runtimeEvidenceIds).toHaveLength(1);
    }
    expect(report.plans.every(plan => plan.readiness === 'READY')).toBe(true);
    expect(report.context.endpoints.map(item => item.path).sort()).toEqual(['/api/admin/users', '/api/orders/:id']);
    expect(JSON.stringify(report)).not.toMatch(/private-session|owner-only-order-content|admin-only-user-content/);
    expect(Object.isFrozen(report.context.evidence[0])).toBe(true);
    for (const route of ['/api/orders/102', '/api/admin/users']) {
      const requests = state.calls.filter(item => new URL(item.url).pathname === route);
      expect(requests.map(item => item.headers.cookie ?? null)).toEqual([
        `test-session=private-session-${route.includes('orders') ? 'alice' : 'admin'}`, 'test-session=private-session-bob', null,
      ]);
    }
    const observations = report.context.evidence.map(fromCoreEvidence).filter(item => item?.probeId === 'authorization');
    expect(observations).toHaveLength(2);
  });
  it('replays retained decisions after reopening the evidence store without target traffic', async () => {
    const state = fixture(), path = mkdtempSync(join(tmpdir(), 'agento-a01-proof-')); paths.push(path);
    const store = new FileEvidenceStore(path), report = await runA01Scan({ ...state.options, evidenceStore: store });
    const head = store.headDigest; store.close();
    const reopened = new FileEvidenceStore(path, { expectedHeadDigest: head });
    const authorizationPolicies = state.options.targets.map(({ resourceId, ownerIdentityId, attackerIdentityId, attackerIsUnauthorized, anonymousIsUnauthorized }) =>
      ({ resourceId, ownerIdentityId, attackerIdentityId, attackerIsUnauthorized, anonymousIsUnauthorized }));
    try {
      const judge = new VerificationJudge({ plugins: [new CWE639Plugin({ authorizationPolicies }), new CWE862Plugin({ authorizationPolicies })], evidenceStore: reopened });
      for (const hypothesis of report.hypotheses) {
        const plans = report.plans.filter(item => item.hypothesisId === hypothesis.id);
        const decision = await judge.judge({ context: report.context, hypothesis, plans, results: report.results.filter(result => plans.some(plan => plan.id === result.planId)) });
        expect(decision).toEqual(report.decisions.find(item => item.finding.hypothesisId === hypothesis.id));
        expect(reopened.exportFinding(decision.finding).evidence.length).toBeGreaterThan(1);
      }
      expect(state.calls).toHaveLength(6);
    } finally { reopened.close(); }
  });
  it.each(['uniform', 'owner-denied', 'truncated'] as const)('does not confirm with %s responses', async mode => {
    const report = await runA01Scan(fixture(mode).options);
    expect(report.findings).toHaveLength(2); expect(report.findings.every(item => item.status === 'NOT_REPRODUCED')).toBe(true);
    if (mode === 'truncated') expect(report.executions.every(item => item.code === 'partial-collection')).toBe(true);
  });
  it('confirms anonymous privileged data disclosure even when the logged-in attacker is denied', async () => {
    const state = fixture('anonymous-only'), report = await runA01Scan(state.options);
    expect(report.findings.find(item => item.cweId === 'CWE-862')?.status).toBe('CONFIRMED');
    expect(report.findings.find(item => item.cweId === 'CWE-639')?.status).toBe('NOT_REPRODUCED');
  });
  it('keeps approval-required tests skipped with no login or target traffic', async () => {
    const state = fixture(), { approval: _, ...policy } = state.options.policy;
    const report = await runA01Scan({ ...state.options, policy });
    expect(report.executions.every(item => item.code === 'approval-required')).toBe(true); expect(state.logins).toEqual([]); expect(state.calls).toEqual([]);
  });
  it.each([{ allowedMethods: ['POST'] }, { allowedOrigins: ['https://outside.invalid'] }, { tools: { 'a01-http': {} } }])('denies mismatched execution policy %j', async extra => {
    const state = fixture(), report = await runA01Scan({ ...state.options, policy: { ...state.options.policy, ...extra } });
    expect(report.executions.every(item => item.outcome === 'SKIPPED')).toBe(true); expect(state.logins).toEqual([]); expect(state.calls).toEqual([]);
  });
  it('counts logins and resource requests against the same execution budget', async () => {
    const state = fixture(), report = await runA01Scan({ ...state.options, policy: { ...state.options.policy, maxRequestsPerExecution: 2 } });
    expect(state.calls).toHaveLength(2); expect(state.logins).toHaveLength(2); expect(state.closed).toHaveLength(2);
    expect(report.executions.every(item => item.outcome === 'FAILED')).toBe(true); expect(report.findings.every(item => item.status === 'NOT_REPRODUCED')).toBe(true);
  });
  it('handles login failure without retaining private error text or confirming access', async () => {
    const state = fixture('vulnerable', true), report = await runA01Scan(state.options);
    expect(report.executions.every(item => item.outcome === 'FAILED')).toBe(true); expect(state.calls).toEqual([]);
    expect(JSON.stringify(report)).not.toContain('private-login-failure'); expect(report.findings.every(item => item.status === 'NOT_REPRODUCED')).toBe(true);
  });
  it('blocks an owner without the role required by the source endpoint', async () => {
    const state = fixture(), adapter = new ExpressFrameworkAdapter();
    const report = await runA01Scan({ ...state.options, targets: [{ ...state.options.targets[1]!, ownerIdentityId: 'alice' }],
      frameworkAdapter: { id: adapter.id, capabilities: adapter.capabilities, supports: project => adapter.supports(project),
        extract: async project => { const analysis = await adapter.extract(project);
          return { ...analysis, endpoints: analysis.endpoints.map(endpoint => endpoint.path === '/api/admin/users' ? { ...endpoint, roles: ['admin'] } : endpoint) }; } } });
    expect(report.plans[0]?.prerequisites.map(item => item.code)).toContain('eligible-identity-required'); expect(state.logins).toEqual([]);
  });
  it('cancels before source reads or target effects', async () => {
    const state = fixture(); await expect(runA01Scan({ ...state.options, signal: AbortSignal.abort() })).rejects.toThrow('cancelled'); expect(state.logins).toEqual([]);
  });
  it.each(['../outside', '//outside.invalid/test', '/api/orders/*', '/api/orders/:id?', '/api/orders/%2e%2e', '/missing'])('refuses unselected or ambiguous routes %s', async path => {
    const state = fixture(); await expect(runA01Scan({ ...state.options, targets: [{ ...state.options.targets[0]!, path }] })).rejects.toBeInstanceOf(A01Error);
    expect(state.logins).toEqual([]); expect(state.calls).toEqual([]);
  });
  it.each([{ pathValues: {} }, { pathValues: { id: '../users' } }, { pathValues: { id: '102', extra: '201' } },
    { ownerMarkers: [] }, { ownerIdentityId: 'bob' }, { attackerIsUnauthorized: false }, { ownerIdentityId: 'unknown' }])('refuses incomplete or unsafe private bindings %j', async extra => {
    const state = fixture(); await expect(runA01Scan({ ...state.options, targets: [{ ...state.options.targets[0]!, ...extra }] })).rejects.toThrow('invalid-options');
    expect(state.logins).toEqual([]);
  });
});

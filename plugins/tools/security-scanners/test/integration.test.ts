import { describe, expect, it, vi } from 'vitest';
import { AgentOOrchestrator } from '@agento/core';
import type { CWEPlugin } from '@agento/core';
import { CapabilityRegistry } from '@agento/capability-registry';
import { PolicyEngine } from '@agento/policy-engine';
import { CapabilityRegistry as RuntimeCapabilities, NormalizedResponseComparator, SQLInjectionProbe, XSSProbe } from '@agento/runtime';
import { DalfoxAdapter, NucleiAdapter, SqlmapAdapter } from '../src/index.js';
import { collector, input, origin, plan, project, response, runner } from './helpers.js';

describe('host registry and policy integration', () => {
  it('returns one failed result and continues the unchanged core scan', async () => {
    let calls = 0;
    const adapter = new NucleiAdapter({ resolveInput: async (_context, selected) => input({ planId: selected.id }),
      runner: async process => { if (++calls === 1) throw new Error('PRIVATE_FAILURE'); return runner()(process); } });
    const plugin: CWEPlugin = { cweId: 'CWE-89', detectCandidates: async () => [{ id: 'hypothesis', projectId: project.id,
      cweId: 'CWE-89', status: 'HYPOTHESIS', reason: 'Synthetic candidate.', evidenceIds: [] }],
      generateTests: async () => [{ ...plan, id: 'first' }, { ...plan, id: 'second' }],
      evaluateEvidence: async (_context, hypothesis, results) => ({ id: 'finding', projectId: project.id,
        hypothesisId: hypothesis.id, cweId: 'CWE-89', owaspCategory: 'A03', title: 'Synthetic assessment',
        status: 'NOT_REPRODUCED', severity: 'info', confidence: 'low', rootCause: 'Independent proof is required.',
        evidenceIds: results.flatMap(result => result.evidence.map(item => item.id)), testPlanIds: results.map(result => result.planId) }) };
    const report = await new AgentOOrchestrator({ scanner: adapter, plugins: [plugin] }).run({ project, identities: [] });
    expect(report.results.map(result => result.outcome)).toEqual(['FAILED', 'COMPLETED']);
    expect(report.findings[0]?.status).toBe('NOT_REPRODUCED'); expect(JSON.stringify(report)).not.toContain('PRIVATE_FAILURE');
  });
  it('can disable a native tool and replace it without changing a probe', async () => {
    const registry = new CapabilityRegistry().register(new SqlmapAdapter({ enabled: false }).registration());
    const metadata = { id: 'mock-sql', capabilities: ['sql-scanner'] as const, supportedCwes: ['CWE-89'] as const,
      protocols: ['https'] as const, risk: 'active' as const };
    registry.register({ metadata, capabilities: { 'sql-scanner': { scan: async () => ({ technique: 'boolean', dbmsFingerprint: null, observedDifference: null }) } } });
    const resolution = await registry.resolve({ ...plan, requiredCapabilities: ['sql-scanner'] });
    expect(resolution.report.status).toBe('READY'); expect(resolution.capabilities!.get('sql-scanner')).toBeDefined();
    expect(resolution.report.selections[0]?.selectedToolId).toBe('mock-sql');
    expect(JSON.stringify(resolution.report)).not.toMatch(/node_modules|PRIVATE|executable/);
  });
  it('binds generic scanners to tool-specific methods and request budgets', async () => {
    const data = input();
    // The executable check is file-only. A runner seam supplies the protocol fixture.
    const adapter = new NucleiAdapter({ executable: process.execPath, runner: runner() });
    const registry = new CapabilityRegistry().register(adapter.registration());
    const resolution = await registry.resolvePlan(plan);
    expect(resolution.report.status).toBe('READY');
    const engine = new PolicyEngine({ allowedOrigins: [origin], tools: { 'nuclei-adapter': { maxRequests: 1 } },
      approval: { risks: [], severities: [] } });
    const result = await engine.run({ project, plan }, resolution, async execution => {
      return execution.capabilities.get('security-scanner').run(data);
    });
    expect(result.outcome).toBe('COMPLETED'); expect(data.executor.execute).toHaveBeenCalledOnce();
    expect(engine.audit().filter(item => item.operation === 'request' && item.code === 'allowed')).toHaveLength(1);
    expect(engine.audit().filter(item => item.operation === 'tool')).toHaveLength(1);
    expect(JSON.stringify(engine.audit())).not.toMatch(/PRIVATE|\/search/);
  });
  it('rejects unsafe scanner methods before native target transport', async () => {
    const adapter = new SqlmapAdapter({ executable: process.execPath, runner: runner() });
    const registry = new CapabilityRegistry().register(adapter.registration());
    const resolution = await registry.resolvePlan(plan);
    const engine = new PolicyEngine({ allowedOrigins: [origin], tools: { 'sqlmap-adapter': {} }, approval: { risks: [], severities: [] } });
    const data = input({ request: { url: plan.targetUrl, method: 'POST', body: 'q=a' }, parameter: { name: 'q', location: 'query' } });
    const result = await engine.run({ project, plan }, resolution, execution => execution.capabilities.get('security-scanner').run(data));
    expect(result.outcome).toBe('FAILED'); expect(data.executor.execute).not.toHaveBeenCalled();
    expect(engine.audit().some(item => item.code === 'method-denied')).toBe(true);
  });
  it('requires approval for the generic scanner even if metadata and plan say passive', async () => {
    const registration = new NucleiAdapter({ executable: process.execPath }).registration();
    const registry = new CapabilityRegistry().register({ ...registration, metadata: { ...registration.metadata, risk: 'passive' } });
    const passive = { ...plan, risk: 'passive' as const };
    const resolution = await registry.resolvePlan(passive);
    const engine = new PolicyEngine({ allowedOrigins: [origin], tools: { 'nuclei-adapter': {} } });
    expect(engine.review({ project, plan: passive }, resolution.report).outcome).toBe('APPROVAL_REQUIRED');
  });
  it('runs existing SQL and XSS probes with native ports and preserves incomplete coverage', async () => {
    for (const fail of [false, true]) {
      const execute = vi.fn(async request => response(request));
      const capabilities = new RuntimeCapabilities().register('request-executor', { execute }).register('response-collector', collector)
        .register('response-comparator', new NormalizedResponseComparator())
        .register('sql-scanner', new SqlmapAdapter({ runner: fail ? async () => { throw new Error('PRIVATE'); } : runner() }))
        .register('xss-scanner', new DalfoxAdapter({ enabled: !fail, runner: runner() }));
      const request = { project, capabilities, request: { url: plan.targetUrl }, parameter: { name: 'q', location: 'query' } as const };
      const sql = await new SQLInjectionProbe().execute(request);
      expect(sql.scanner?.observedDifference).toBeNull();
      expect(sql.diagnostics.includes('scanner-failed')).toBe(fail);
      const xss = await new XSSProbe().execute(request);
      expect(xss.executionConfirmed).toBeNull(); expect(xss.diagnostics.includes('scanner-skipped')).toBe(fail);
      expect(JSON.stringify([sql, xss])).not.toMatch(/PRIVATE_BODY|PRIVATE_PAYLOAD|PRIVATE_SESSION/);
    }
  });
});

import { describe, expect, it, vi } from 'vitest';
import { AgentOOrchestrator } from '@agento/core';
import { TesterArmyE2EAdapter, demoBrowserOptions } from '../src/index.js';
import { MemorySessionStore } from '../src/sessions.js';
import { BrowserScope } from '../src/policy.js';
import { alice, anonymous, context, fakeRuntime, plan, state, workflow } from './helpers.js';

describe('TesterArmyE2EAdapter', () => {
  it('authenticates isolated Alice, Bob, and Admin and reuses only the matching snapshot', async () => {
    const runtime = fakeRuntime();
    const adapter = new TesterArmyE2EAdapter({ ...demoBrowserOptions(), runtime });
    for (const identityId of ['alice', 'bob', 'admin', 'alice']) {
      const result = await adapter.observe(context, { ...workflow, identityId });
      expect(result.outcome).toBe('COMPLETED');
      expect(result.evidence.find(item => item.kind === 'identity-session')?.facts.reused).toBe(identityId === 'alice' && runtime.sessions.length === 4);
    }
    expect(runtime.start.mock.calls.map(([request]) => !!request.state)).toEqual([false, false, false, true]);
    expect(runtime.sessions[3]!.perform.mock.calls.some(([action]) => action.action === 'fill')).toBe(false);
    expect(runtime.sessions.every(session => session.close.mock.calls.length === 1)).toBe(true);
  });

  it('discards expired and failed-verification sessions and logs in in a fresh context', async () => {
    const store = new MemorySessionStore(), binding = new BrowserScope(context.project).binding(context.project, alice);
    await store.save({ binding, sessionRef: 'opaque', expiresAt: Date.now() + 60_000, state });
    let verified = 0;
    const runtime = fakeRuntime({ verify: () => ++verified !== 1 });
    const adapter = new TesterArmyE2EAdapter({ ...demoBrowserOptions(), runtime, sessionStore: store });
    const result = await adapter.observe(context, workflow);
    expect(result.outcome).toBe('COMPLETED');
    expect(runtime.start.mock.calls.map(([request]) => !!request.state)).toEqual([true, false]);
    expect(runtime.sessions[0]!.close).toHaveBeenCalledOnce();
    await store.save({ binding, sessionRef: 'expired', expiresAt: 0, state });
    await adapter.observe(context, workflow);
    expect(runtime.start.mock.calls.at(-1)![0].state).toBeUndefined();
  });

  it('binds cached sessions to the project, exact origins, identity and roles', async () => {
    const runtime = fakeRuntime(), adapter = new TesterArmyE2EAdapter({ ...demoBrowserOptions(), runtime });
    await adapter.observe(context, workflow);
    for (const changed of [
      { ...context, project: { ...context.project, id: 'other' } },
      { ...context, project: { ...context.project, allowedOrigins: [...context.project.allowedOrigins, 'http://localhost:3000'] } },
      { ...context, identities: [{ ...alice, roles: ['admin'] }] },
    ]) await adapter.observe(changed, workflow);
    expect(runtime.start.mock.calls.every(([request]) => !request.state)).toBe(true);
  });

  it('rejects unknown identities and goals before launching a browser', async () => {
    const runtime = fakeRuntime(), adapter = new TesterArmyE2EAdapter({ ...demoBrowserOptions(), runtime });
    for (const item of [{ ...workflow, identityId: 'unknown' }, { ...workflow, goal: 'execute arbitrary code' }]) {
      expect((await adapter.observe(context, item)).outcome).toBe('SKIPPED');
    }
    expect(runtime.start).not.toHaveBeenCalled();
  });

  it('validates all actions before launching, including a later external navigation', async () => {
    const runtime = fakeRuntime(), adapter = new TesterArmyE2EAdapter({ runtime, resolveGoal: () => [
      { action: 'navigate', url: '/' }, { action: 'navigate', url: 'http://evil.example' },
    ] });
    const result = await adapter.observe(context, { ...workflow, identityId: anonymous.id });
    expect(result.diagnostics[0]?.code).toBe('scope-denied');
    expect(runtime.start).not.toHaveBeenCalled();
  });

  it('rejects credentials without authentication configuration before target access', async () => {
    const runtime = fakeRuntime(), adapter = new TesterArmyE2EAdapter({ runtime, resolveGoal: () => [{ action: 'navigate', url: '/' }] });
    expect((await adapter.observe(context, workflow)).outcome).toBe('SKIPPED');
    expect(runtime.start).not.toHaveBeenCalled();
  });

  it('fails rejected logins, preserves safe evidence and closes the browser', async () => {
    const runtime = fakeRuntime({ verify: () => false });
    const result = await new TesterArmyE2EAdapter({ ...demoBrowserOptions(), runtime }).observe(context, workflow);
    expect(result.outcome).toBe('FAILED');
    expect(result.diagnostics[0]?.code).toBe('authentication-failed');
    expect(runtime.sessions[0]!.close).toHaveBeenCalledOnce();
    expect(result.evidence.some(item => item.kind === 'identity-session')).toBe(false);
  });

  it('does not save a session if a workflow logs out or switches identities', async () => {
    let count = 0;
    const runtime = fakeRuntime({ verify: () => ++count === 1 }), store = new MemorySessionStore();
    const save = vi.spyOn(store, 'save');
    const result = await new TesterArmyE2EAdapter({ ...demoBrowserOptions(), runtime, sessionStore: store }).observe(context, workflow);
    expect(result.diagnostics[0]?.code).toBe('authentication-failed');
    expect(save).not.toHaveBeenCalled();
  });

  it('keeps raw tool failures and resolver exceptions out of results', async () => {
    const runtime = fakeRuntime({ perform: async () => { throw new Error('password=alice123 private-session-cookie'); } });
    const result = await new TesterArmyE2EAdapter({ ...demoBrowserOptions(), runtime }).observe(context, workflow);
    expect(result.diagnostics[0]?.code).toBe('authentication-failed');
    expect(JSON.stringify(result)).not.toMatch(/alice123|private-session-cookie|password=/);
    const failedBrowser = await new TesterArmyE2EAdapter({ runtime, resolveGoal: () => [{ action: 'navigate', url: '/' }] })
      .observe(context, { ...workflow, identityId: 'anonymous' });
    expect(failedBrowser.diagnostics[0]?.code).toBe('browser-failed');
    const rejected = await new TesterArmyE2EAdapter({ resolveGoal: () => { throw new Error('secret'); } }).observe(context, workflow);
    expect(JSON.stringify(rejected)).not.toContain('secret');
  });

  it('redacts query values, credentials, session values and fragments while keeping statuses and provenance', async () => {
    const runtime = fakeRuntime({ perform: async (_action, request) => request.onNetwork({
      url: 'http://127.0.0.1:3000/api/orders/102?password=alice123&token=private-session-cookie#secret',
      method: 'GET', status: 200, resourceType: 'fetch', blocked: false,
    }) });
    const result = await new TesterArmyE2EAdapter({ ...demoBrowserOptions(), runtime }).observe(context, workflow);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toMatch(/alice123|private-session-cookie|#secret/);
    expect(result.evidence.some(item => item.kind === 'http-response' && item.facts.status === 200)).toBe(true);
    expect(result.endpoints[0]?.path).toBe('/api/orders/102');
    expect(result.endpoints[0]?.authentication).toBe('unknown');
    expect(result.evidence.every(item => item.projectId === context.project.id && item.identityId === 'alice' && item.producerId === 'tester-army-e2e-adapter')).toBe(true);
    expect(Object.isFrozen(result.evidence[0]!.facts)).toBe(true);
  });

  it('marks scope blocks and truncated network evidence as failed, never silently complete', async () => {
    const runtime = fakeRuntime({ perform: async (_action, request) => {
      for (let index = 0; index < 5; index++) request.onNetwork({ url: 'http://evil.example/path?token=secret', method: 'GET', resourceType: 'fetch', status: null, blocked: true });
    } });
    const result = await new TesterArmyE2EAdapter({ runtime, maxNetworkRecords: 2,
      resolveGoal: () => [{ action: 'navigate', url: '/' }] }).observe(context, { ...workflow, identityId: 'anonymous' });
    expect(result.outcome).toBe('FAILED');
    expect(result.diagnostics.map(item => item.code)).toEqual(['scope-denied', 'network-limit']);
    expect(result.evidence.filter(item => item.kind === 'http-request')).toHaveLength(2);
    expect(result.evidence.at(-1)?.facts.blockedCount).toBe(5);
    expect(result.evidence.at(-1)?.facts.droppedCount).toBe(3);
  });

  it('bounds execution, cleans up and can run another workflow after a timeout', async () => {
    let first = true;
    const runtime = fakeRuntime({ perform: async () => { if (first) { first = false; await new Promise(() => undefined); } } });
    const adapter = new TesterArmyE2EAdapter({ runtime, timeoutMs: 25, resolveGoal: () => [{ action: 'navigate', url: '/' }] });
    const result = await adapter.observe(context, { ...workflow, identityId: 'anonymous' });
    expect(result.diagnostics[0]?.code).toBe('timeout');
    expect(runtime.sessions[0]!.close).toHaveBeenCalledOnce();
    expect((await adapter.observe(context, { ...workflow, identityId: 'anonymous' })).outcome).toBe('COMPLETED');
  });

  it('supports explicit session invalidation', async () => {
    const runtime = fakeRuntime(), adapter = new TesterArmyE2EAdapter({ ...demoBrowserOptions(), runtime });
    await adapter.observe(context, workflow); await adapter.forgetSession(context.project, alice); await adapter.observe(context, workflow);
    expect(runtime.start.mock.calls.every(([request]) => !request.state)).toBe(true);
  });

  it('correlates runtime observations with existing framework endpoint IDs', async () => {
    const runtime = fakeRuntime({ perform: async (_action, request) => request.onNetwork({ url: 'http://127.0.0.1:3000/api/orders/102', method: 'GET', status: 200, resourceType: 'fetch', blocked: false }) });
    const endpoint = { id: 'orders', componentId: 'app', method: 'GET' as const, path: '/api/orders/:id', authentication: 'required' as const, parameters: [], roles: [], evidenceIds: [] };
    const result = await new TesterArmyE2EAdapter({ runtime, resolveGoal: () => [{ action: 'navigate', url: '/' }] })
      .observe({ ...context, endpoints: [endpoint] }, { ...workflow, identityId: 'anonymous' });
    expect(result.endpoints).toHaveLength(0);
    expect(result.evidence.filter(item => item.kind === 'http-response').every(item => item.endpointId === 'orders')).toBe(true);
  });

  it('works through the core orchestrator with unique evidence across identities and repeated runs', async () => {
    const adapter = new TesterArmyE2EAdapter({ ...demoBrowserOptions(), runtime: fakeRuntime() });
    const report = await new AgentOOrchestrator({ plugins: [], browser: adapter }).run({ project: context.project,
      identities: context.identities, workflows: [workflow, { ...workflow, id: 'again' }] });
    expect(report.context.evidence.length).toBeGreaterThan(2);
    expect(new Set(report.context.evidence.map(item => item.id)).size).toBe(report.context.evidence.length);
  });
});

describe('structured browser plans', () => {
  it('executes typed actions and returns core results without deriving a verdict', async () => {
    const runtime = fakeRuntime(), result = await new TesterArmyE2EAdapter({ runtime }).execute(context, { ...plan,
      steps: [{ ...plan.steps[0]!, parameters: { url: '/orders', response: { url: '/api/orders', method: 'GET', status: 200 } } }],
    });
    expect(result.outcome).toBe('COMPLETED'); expect(result.planId).toBe(plan.id);
    expect(result.evidence.length).toBeGreaterThan(0);
    expect(JSON.stringify(result)).not.toContain('CONFIRMED');
    expect(runtime.sessions[0]?.perform.mock.calls[0]?.[0]).toEqual({ action: 'navigate', url: '/orders', response: { url: '/api/orders', method: 'GET', status: 200 } });
  });
  it('rejects unsupported actions, capabilities, identity selectors and out-of-scope targets before execution', async () => {
    const runtime = fakeRuntime(), adapter = new TesterArmyE2EAdapter({ runtime });
    for (const invalid of [
      { ...plan, targetUrl: 'http://evil.example' }, { ...plan, requiredCapabilities: ['unsupported'] },
      { ...plan, steps: [{ ...plan.steps[0]!, action: 'eval' }] },
      { ...plan, identityIds: ['alice', 'bob'] }, { ...plan, identityIds: ['unknown'] },
      { ...plan, steps: [...plan.steps, { ...plan.steps[0]!, parameters: { url: 'http://evil.example' } }] },
      { ...plan, steps: [{ ...plan.steps[0]!, parameters: { url: '/orders', response: { url: 'http://evil.example' } } }] },
      { ...plan, steps: [{ ...plan.steps[0]!, parameters: { url: '/orders', response: { url: '/orders', status: '200' } } }] },
    ]) expect((await adapter.execute(context, invalid)).outcome).toBe('SKIPPED');
    expect(runtime.start).not.toHaveBeenCalled();
  });
  it('runs explicitly selected identities in isolated contexts', async () => {
    const runtime = fakeRuntime(), adapter = new TesterArmyE2EAdapter({ ...demoBrowserOptions(), runtime });
    const result = await adapter.execute(context, { ...plan, identityIds: ['alice', 'bob'], steps: [
      { ...plan.steps[0]!, parameters: { url: '/orders', identityId: 'alice' } },
      { ...plan.steps[0]!, id: 'bob', parameters: { url: '/orders', identityId: 'bob' } },
    ] });
    expect(result.outcome).toBe('COMPLETED'); expect(runtime.start).toHaveBeenCalledTimes(2);
    expect(new Set(result.evidence.map(item => item.identityId))).toEqual(new Set(['alice', 'bob']));
  });
});

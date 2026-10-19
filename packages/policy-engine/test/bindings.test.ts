import { describe, expect, it, vi } from 'vitest';
import type { AnalysisContext, BrowserWorkflowRuntimeDriver, ExecutionGuard } from '@agento/core';
import { CapabilityRegistry } from '@agento/capability-registry';
import { AuthorizationProbe, CookieSecurityProbe, CrossOriginProbe, DeterministicRequestExecutor, NormalizedCookieAnalyzer,
  NormalizedHeaderAnalyzer, NormalizedResponseComparator, ProbeRegistry, RuntimeAuthenticationManager, SQLInjectionProbe,
  WorkflowBrowserController, XSSProbe } from '@agento/runtime';
import type { CapabilityCatalog, RequestExecutor, ScannerRequest, TransportRequest } from '@agento/runtime';
import { PolicyEngine } from '../src/index.js';
import { config, collector, origin, request, response, setup } from './helpers.js';

describe('guarded capability bindings', () => {
  it('refuses a browser or authentication adapter without network guard support', async () => {
    for (const capability of ['browser-controller', 'authentication-manager'] as const) {
      const input = request({ requiredCapabilities: [capability] });
      const port = capability === 'browser-controller' ? { withSession: vi.fn() } : { establishSession: vi.fn() };
      const { resolution } = await setup({ [capability]: port }, input);
      const engine = new PolicyEngine(config()), execute = vi.fn();
      await expect(engine.run(input, resolution, execute)).rejects.toThrow('guard-unsupported');
      expect(execute).not.toHaveBeenCalled(); expect(engine.audit().at(-1)?.code).toBe('guard-unsupported');
    }
  });
  it('applies scanner restrictions to its injected executor and revokes it afterwards', async () => {
    const input = request({ requiredCapabilities: ['request-executor', 'sql-scanner'] });
    const send = vi.fn<RequestExecutor['execute']>(async input => response(input));
    let retained: ScannerRequest;
    const scan = vi.fn(async (input: ScannerRequest) => {
      retained = input;
      await input.executor.execute(input.request);
      await expect(input.executor.execute({ ...input.request, method: 'POST' })).rejects.toThrow('method-denied');
      await expect(input.executor.execute({ ...input.request, url: 'https://evil.test' })).rejects.toThrow('target-denied');
      expect(input.project.allowedOrigins).toEqual([origin]);
      return { technique: 'boolean' as const, dbmsFingerprint: null, observedDifference: false };
    });
    const registry = new CapabilityRegistry().register({ metadata: { id: 'runtime', capabilities: ['request-executor'], supportedCwes: 'all', protocols: ['https'], risk: 'passive' }, capabilities: { 'request-executor': { execute: send } } })
      .register({ metadata: { id: 'scanner', capabilities: ['sql-scanner'], supportedCwes: 'all', protocols: ['https'], risk: 'active' }, capabilities: { 'sql-scanner': { scan } } });
    const resolution = await registry.resolvePlan({ ...input.plan, cweId: 'CWE-89' });
    const engine = new PolicyEngine(config({ allowedMethods: ['GET', 'POST'], tools: { runtime: {}, scanner: { allowedMethods: ['GET'], maxRequests: 1 } } }));
    await engine.run(input, resolution, async e => {
      await e.capabilities.get('sql-scanner').scan({ project: { ...input.project, name: 'Shop', mode: 'black-box', languages: [] },
        request: { url: origin }, parameter: { name: 'q', location: 'query' }, canary: 'test', maxRequests: 8,
        executor: e.capabilities.get('request-executor') });
    });
    expect(send).toHaveBeenCalledOnce();
    await expect(retained!.executor.execute({ url: origin })).rejects.toThrow('execution-closed');
    expect(engine.audit().filter(item => item.operation === 'request' && item.outcome === 'ALLOW')).toHaveLength(1);
  });
  it('runs the unchanged SQL probe and rule through a guarded mock scanner', async () => {
    const { CWE89Plugin } = await import('@agento/cwe');
    const probe = new SQLInjectionProbe(), registry = new CapabilityRegistry({ probes: new ProbeRegistry().register('sql-injection', probe) });
    const scan = vi.fn(async (input: ScannerRequest) => {
      await input.executor.execute(input.request);
      return { technique: 'boolean' as const, dbmsFingerprint: null, observedDifference: false };
    });
    registry.register({ metadata: { id: 'runtime', capabilities: ['request-executor', 'response-collector', 'response-comparator', 'sql-scanner'], supportedCwes: 'all', protocols: ['https'], risk: 'active' },
      capabilities: { 'request-executor': { execute: async input => response(input) }, 'response-collector': collector,
        'response-comparator': new NormalizedResponseComparator(), 'sql-scanner': { scan } } });
    const input = request({ probeId: 'sql-injection', requiredCapabilities: ['probe:sql-injection'], risk: 'active' });
    const resolution = await registry.resolveProbe('sql-injection', { cweId: 'CWE-89', targetUrl: input.plan.targetUrl, risk: 'active' });
    const engine = new PolicyEngine(config());
    await engine.run(input, resolution, async execution => {
      const project = { ...input.project, allowedOrigins: execution.allowedOrigins, name: 'Shop', mode: 'black-box' as const, languages: [] };
      const evidence = await probe.execute({ project, capabilities: execution.capabilities, request: { url: `${origin}/search?q=base` }, parameter: { name: 'q', location: 'query' }, signal: execution.signal });
      const verdict = await new CWE89Plugin().evaluate([evidence], { projectId: project.id, targetUrl: `${origin}/search?q=base`, method: 'GET', parameter: { name: 'q', location: 'query' } });
      expect(verdict.status).toBe('REJECTED'); expect(evidence.outcome).toBe('COMPLETED');
    });
    expect(scan).toHaveBeenCalledOnce();
    expect(engine.audit().filter(item => item.operation === 'request' && item.code === 'allowed')).toHaveLength(5);
  });
  it('guards Alice and Bob session initialization and their private HTTP clients', async () => {
    const identities = ['alice', 'bob'].map(id => ({ id, label: id, roles: ['customer'], authentication: 'session-cookie' as const }));
    const input = request({ requiredCapabilities: ['authentication-manager'] });
    const project = { ...input.project, name: 'Shop', mode: 'black-box' as const, languages: [] };
    const context: AnalysisContext = { project, identities, components: [], endpoints: [], resources: [], signals: [], evidence: [] };
    const starts: string[] = [];
    const driver = (guard?: ExecutionGuard): BrowserWorkflowRuntimeDriver => ({ id: 'mock-driver', capabilities: ['browser-workflow'],
      withGuard: next => driver(next), observe: async () => ({ endpoints: [], resources: [], signals: [], evidence: [] }),
      execute: async () => { throw new Error('unused'); },
      runWorkflow: async (_context, workflow, callback) => {
        guard?.assertActive(); guard?.assertRequest({ url: `${origin}/login`, method: 'GET' }); starts.push(workflow.identityId);
        await callback({ signal: guard?.signal ?? new AbortController().signal, persona: identities.find(i => i.id === workflow.identityId)!,
          inspect: async () => ({ url: origin, controls: [] }), perform: async () => undefined, fillCredential: async () => undefined,
          assertUrl: value => new URL(value, origin).href, network: () => [], readCookies: async () => [{ name: 'sid', value: `PRIVATE_${workflow.identityId}`, domain: 'shop.test', path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'Lax' }] });
        return { outcome: 'COMPLETED', diagnostics: [], endpoints: [], resources: [], signals: [], evidence: [] };
      } });
    const send = vi.fn(async (_request: TransportRequest) => ({ status: 200, headers: {}, body: Buffer.from('owner'), truncated: false, firstByteMs: 1 }));
    const manager = new RuntimeAuthenticationManager({ identities, browser: new WorkflowBrowserController({ context, driver: driver() }),
      http: { baseUrl: origin, allowedOrigins: [origin], transport: { send } } });
    const { resolution } = await setup({ 'authentication-manager': manager }, input);
    const engine = new PolicyEngine(config());
    const sessions = await engine.run(input, resolution, async execution => {
      const sessions = [];
      for (const identity of identities) {
        const session = await execution.capabilities.get('authentication-manager').establishSession(identity);
        await session.http.execute({ url: `${origin}/orders` }); sessions.push(session);
        await expect(session.http.execute({ url: `${origin}/orders`, method: 'POST' })).rejects.toThrow();
      }
      return sessions;
    });
    expect(starts).toEqual(['alice', 'bob']); expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls.map(call => call[0].headers.cookie)).toEqual(['sid=PRIVATE_alice', 'sid=PRIVATE_bob']);
    await expect(sessions[0]!.http.execute({ url: origin })).rejects.toThrow();
    expect(JSON.stringify(engine.audit())).not.toMatch(/PRIVATE_|orders|login/);
    await manager.close();
  });
  it('injects the runtime HTTP gate before the transport and checks response redirects', async () => {
    const assertRequest = vi.fn(() => { throw new Error('refused'); }), send = vi.fn();
    const guard: ExecutionGuard = { assertActive: () => undefined, assertRequest, assertRedirect: () => undefined };
    const http = new DeterministicRequestExecutor({ baseUrl: origin, allowedOrigins: [origin], transport: { send }, executionGuard: guard });
    await expect(http.execute({ url: origin })).rejects.toThrow('refused'); expect(send).not.toHaveBeenCalled();
  });
});

describe('planner compatibility across the seven rules', () => {
  for (const fixed of [false, true]) it.each(['CWE-639', 'CWE-862', 'CWE-942', 'CWE-1004', 'CWE-614', 'CWE-79', 'CWE-89'])(
    'checks existing %s structured plans without changing their contents', async cweId => {
      const { candidate, bindings } = await import('./planner-fixture.js');
      const { rule, context, hypothesis, planner } = await candidate(cweId, fixed);
      const plan = (await planner.plan(context, hypothesis, bindings)).plans[0]!;
      const before = JSON.stringify(plan);
      const probes = new ProbeRegistry().register('authorization', new AuthorizationProbe()).register('cookie-security', new CookieSecurityProbe())
        .register('cross-origin', new CrossOriginProbe()).register('xss', new XSSProbe()).register('sql-injection', new SQLInjectionProbe());
      const ports: Partial<CapabilityCatalog> = { 'request-executor': { execute: async input => response(input) }, 'response-collector': collector,
        'response-comparator': new NormalizedResponseComparator(), 'cookie-analyzer': new NormalizedCookieAnalyzer(), 'header-analyzer': new NormalizedHeaderAnalyzer(),
        'authentication-manager': { establishSession: vi.fn() }, 'cookie-inspector': { inspect: vi.fn() }, 'browser-controller': { withSession: vi.fn() },
        'sql-scanner': { scan: vi.fn() }, 'xss-scanner': { scan: vi.fn() } };
      const registry = new CapabilityRegistry({ probes }).register({ metadata: { id: 'runtime', capabilities: Object.keys(ports) as (keyof CapabilityCatalog)[], supportedCwes: 'all', protocols: ['https'], risk: 'active' }, capabilities: ports });
      const resolution = await registry.resolvePlan(plan);
      const engine = new PolicyEngine(config({ tools: { runtime: {} } }));
      expect(engine.review({ project: context.project, plan }, resolution.report).outcome).toBe('ALLOW');
      expect(JSON.stringify(plan)).toBe(before); expect(rule.cweId).toBe(cweId);
    });
});

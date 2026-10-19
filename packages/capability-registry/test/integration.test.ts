import type { AnalysisContext, BrowserWorkflowRuntimeDriver, Evidence, JsonValue, Project } from '@agento/core';
import { CWE639Plugin, CWE862Plugin, CWE942Plugin, CWE1004Plugin, CWE614Plugin, CWE79Plugin, CWE89Plugin } from '@agento/cwe';
import { buildApplicationSecurityModel } from '@agento/security-model';
import { SecurityTestPlanner } from '@agento/test-planner';
import { AuthorizationProbe, RuntimeAuthenticationManager, SQLInjectionProbe, WorkflowBrowserController } from '@agento/runtime';
import type { TransportRequest } from '@agento/runtime';
import { describe, expect, it, vi } from 'vitest';
import { CapabilityRegistry } from '../src/index.js';
import { probes, runtime, scanner, targetUrl, tool } from './helpers.js';

const project: Project = { id: 'shop', name: 'Shop', mode: 'code-aware', baseUrl: 'https://shop.test',
  allowedOrigins: ['https://shop.test'], languages: ['typescript'] };
const authorization = { resourceId: 'order', ownerIdentityId: 'alice', attackerIdentityId: 'bob',
  attackerIsUnauthorized: true, anonymousIsUnauthorized: true };
function fixtures(fixed: boolean) {
  const options = { sensitiveCookieNames: ['sid'], untrustedOrigins: ['https://untrusted.test'], authorizationPolicies: [authorization] };
  const rules = [new CWE639Plugin(options), new CWE862Plugin(options), new CWE942Plugin(options),
    new CWE1004Plugin(options), new CWE614Plugin(options), new CWE79Plugin(options), new CWE89Plugin(options)];
  const evidence = (id: string, facts: Record<string, JsonValue>, extra: Partial<Evidence> = {}): Evidence => ({
    id, projectId: project.id, producerId: 'fixture', kind: 'source-location', capturedAt: '2026-10-19T00:00:00Z',
    endpointId: 'orders', summary: 'Synthetic observation', facts, ...extra,
  });
  const context = buildApplicationSecurityModel({ project, identities: [
    { id: 'alice', label: 'Alice', roles: ['customer'], authentication: 'session-cookie' },
    { id: 'bob', label: 'Bob', roles: ['customer'], authentication: 'session-cookie' },
  ], contributions: [{ source: 'source', components: [{ id: 'service', projectId: project.id, name: 'Service', kind: 'service' }],
    endpoints: [{ id: 'orders', componentId: 'service', method: 'GET', path: '/orders/:id', authentication: 'required',
      roles: ['customer'], parameters: [{ name: 'id', location: 'path', required: true }, { name: 'q', location: 'query', required: false }],
      evidenceIds: ['route'] }],
    resources: [{ id: 'order', projectId: project.id, type: 'Order', externalKey: 'PRIVATE_KEY', ownerIdentityId: 'alice',
      endpointId: 'orders', evidenceIds: ['owner'] }],
    evidence: [evidence('route', { observation: 'route' }),
      evidence('owner', { resourceId: 'order', ownerIdentityId: 'alice' }, { kind: 'resource-ownership', identityId: 'alice' }),
      evidence('guard', { observation: 'authorization-guard', enforcement: fixed ? 'observed' : 'conditional' }),
      evidence('cookie', { observation: 'session', options: { name: 'sid', cookie: { httpOnly: fixed, secure: fixed } } }),
      evidence('cors', { observation: 'cors', options: { origin: fixed ? ['https://trusted.test'] : '*', credentials: true } }),
      evidence('sql', { observation: 'database-operation', interpolated: !fixed, placeholders: fixed ? 1 : 0 }),
      evidence('xss', { observation: 'static-candidate', cweId: 'CWE-79', sources: [], sink: { kind: 'html' } })],
    signals: [{ id: 'xss-signal', projectId: project.id, producerId: 'fixture', cweIds: ['CWE-79'], endpointId: 'orders',
      summary: 'Synthetic candidate', evidenceIds: ['xss'] }] }] });
  return { context, rules, planner: new SecurityTestPlanner({ plugins: rules }) };
}

describe('existing plans, probes and rules', () => {
  for (const fixed of [false, true]) {
    it.each(['CWE-639', 'CWE-862', 'CWE-942', 'CWE-1004', 'CWE-614', 'CWE-79', 'CWE-89'])(
      `resolves a real %s planner output (fixed fixture: ${fixed})`, async cweId => {
        const { context, rules, planner } = fixtures(fixed);
        const rule = rules.find(rule => rule.cweId === cweId)!;
        const hypothesis = (await rule.detectCandidates(context))[0]!;
        expect(hypothesis).toBeDefined();
        const plan = (await planner.plan(context, hypothesis, { inputs: [
          { name: 'id', location: 'path', valueRef: 'order-key' }, { name: 'q', location: 'query', valueRef: 'baseline-query' },
        ] })).plans[0]!;
        expect(plan.readiness).toBe('READY');
        const before = JSON.stringify(plan);
        const { registry, execute, ports } = runtime();
        registry.register(tool('sql-port')).register(tool('xss-port', { capabilities: ['xss-scanner'], supportedCwes: ['CWE-79'] }, {
          capabilities: { 'xss-scanner': { scan: vi.fn(async () => ({ executionConfirmed: false, domSinkReached: false })) } },
        }));
        const result = await registry.resolvePlan(JSON.parse(before));
        expect(result.report.status).toBe('READY'); expect(result.report.probeId).toBe(plan.probeId);
        expect(result.report.risk).toBe('active');
        for (const capability of plan.requiredCapabilities.filter(capability => !capability.startsWith('probe:'))) {
          expect(result.report.selections.find(item => item.capability === capability)?.selectedToolId).not.toBeNull();
        }
        expect(JSON.stringify(plan)).toBe(before);
        expect(execute).not.toHaveBeenCalled(); expect(ports['authentication-manager']!.establishSession).not.toHaveBeenCalled();
        expect(ports['browser-controller']!.withSession).not.toHaveBeenCalled();
        expect(JSON.stringify(result.report)).not.toMatch(/PRIVATE_KEY|order-key|baseline-query/);
      });
  }

  it('replaces a selected scanner with a mock through the same SQL probe and CWE rule', async () => {
    let installed = true;
    const primary = scanner(), replacement = scanner();
    const { registry, execute } = runtime(new CapabilityRegistry({ probes: probes() }));
    registry.register(tool('preferred-adapter', { priority: 10 }, { capabilities: { 'sql-scanner': primary },
      checkAvailability: async () => installed }));
    registry.register(tool('replacement-adapter', {}, { capabilities: { 'sql-scanner': replacement } }));
    const probe = new SQLInjectionProbe(), rule = new CWE89Plugin();
    const collect = async () => {
      const resolved = await registry.resolveProbe('sql-injection', { cweId: rule.cweId, targetUrl, risk: 'active' });
      expect(resolved.report.status).toBe('READY');
      const evidence = await probe.execute({ project, capabilities: resolved.capabilities!,
        request: { url: targetUrl }, parameter: { name: 'q', location: 'query' } });
      const verdict = await rule.evaluate([evidence], { projectId: project.id, targetUrl, method: 'GET', parameter: { name: 'q', location: 'query' } });
      return { resolved, evidence, verdict };
    };
    const first = await collect(); installed = false; const second = await collect();
    expect(first.resolved.report.selections.find(item => item.capability === 'sql-scanner')!.selectedToolId).toBe('preferred-adapter');
    expect(second.resolved.report.selections.find(item => item.capability === 'sql-scanner')!.selectedToolId).toBe('replacement-adapter');
    expect(first.verdict.status).toBe('REJECTED'); expect(second.verdict.status).toBe(first.verdict.status);
    expect(primary.scan).toHaveBeenCalledOnce(); expect(replacement.scan).toHaveBeenCalledOnce();
    expect(execute).toHaveBeenCalledTimes(8);
    expect(JSON.stringify(second.evidence)).not.toMatch(/PRIVATE_RESPONSE_BODY|PRIVATE_COOKIE|private-input/);
  });

  it('passes only the scoped probe executor to a selected scanner port', async () => {
    // Use the objective scanner contract to issue one request through the existing guarded probe executor.
    const { registry, execute } = runtime();
    registry.register(tool('delegated', {}, { capabilities: { 'sql-scanner': { scan: async input => {
      expect(input.maxRequests).toBeGreaterThan(0);
      await input.executor.execute(input.request);
      return { technique: 'boolean', dbmsFingerprint: null, observedDifference: false };
    } } } }));
    const result = await registry.resolveProbe('sql-injection', { cweId: 'CWE-89', targetUrl, risk: 'active' });
    await new SQLInjectionProbe().execute({ project, capabilities: result.capabilities!,
      request: { url: targetUrl }, parameter: { name: 'q', location: 'query' } });
    expect(execute).toHaveBeenCalledTimes(5);
  });

  it('binds browser and authentication adapters for an unchanged multi-user authorization probe', async () => {
    const identities = [
      { id: 'alice', label: 'Alice', roles: ['customer'], authentication: 'session-cookie' as const },
      { id: 'bob', label: 'Bob', roles: ['customer'], authentication: 'session-cookie' as const },
    ];
    const context: AnalysisContext = { project, identities, components: [], endpoints: [], resources: [], signals: [], evidence: [] };
    const driver: BrowserWorkflowRuntimeDriver = { id: 'mock-browser-driver', capabilities: ['browser-workflow'],
      observe: async () => ({ endpoints: [], resources: [], signals: [], evidence: [] }),
      execute: async () => { throw new Error('Core execution is not used'); },
      runWorkflow: vi.fn<BrowserWorkflowRuntimeDriver['runWorkflow']>(async (_context, workflow, callback) => {
        await callback({ signal: new AbortController().signal, persona: identities.find(item => item.id === workflow.identityId)!,
          inspect: async () => ({ url: project.baseUrl, controls: [] }), perform: async () => undefined,
          fillCredential: async () => undefined, assertUrl: url => new URL(url, project.baseUrl).href, network: () => [],
          readCookies: async () => [{ name: 'sid', value: `PRIVATE_${workflow.identityId}`, domain: 'shop.test', path: '/',
            expires: -1, httpOnly: true, secure: true, sameSite: 'Lax' }],
        });
        return { outcome: 'COMPLETED', diagnostics: [], endpoints: [], resources: [], signals: [], evidence: [] };
      }),
    };
    const browser = new WorkflowBrowserController({ driver, context });
    const send = vi.fn(async (_request: TransportRequest) => ({ status: 200, headers: {}, body: Buffer.from('PRIVATE_OWNER_MARKER'), truncated: false, firstByteMs: 1 }));
    const auth = new RuntimeAuthenticationManager({ browser, identities,
      http: { baseUrl: project.baseUrl, allowedOrigins: project.allowedOrigins, transport: { send } } });
    try {
      const host = new CapabilityRegistry({ probes: probes() });
      const { ports } = runtime();
      host.register({ metadata: { id: 'request-runtime', capabilities: ['request-executor', 'response-collector', 'response-comparator'],
        supportedCwes: 'all', protocols: ['https'], risk: 'active' }, capabilities: {
        'request-executor': ports['request-executor']!, 'response-collector': ports['response-collector']!,
        'response-comparator': ports['response-comparator']!,
      } });
      host.register({ metadata: { id: 'session-adapter', capabilities: ['browser-controller', 'authentication-manager'],
        supportedCwes: ['CWE-639', 'CWE-862'], protocols: ['https'], risk: 'active' },
      capabilities: { 'browser-controller': browser, 'authentication-manager': auth } });
      const resolution = await host.resolveProbe('authorization', { cweId: 'CWE-639', targetUrl, risk: 'active', optionalCapabilities: ['browser-controller'] });
      expect(resolution.report.status).toBe('READY'); expect(driver.runWorkflow).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled();
      const evidence = await new AuthorizationProbe().execute({ project, capabilities: resolution.capabilities!, owner: identities[0]!, attacker: identities[1]!,
        resource: { id: 'order', ownerIdentityId: 'alice', request: { url: targetUrl }, ownerMarkers: ['PRIVATE_OWNER_MARKER'] } });
      expect(evidence.ownerIdentityId).toBe('alice'); expect(evidence.attackerIdentityId).toBe('bob');
      expect(vi.mocked(driver.runWorkflow).mock.calls.map(call => call[1].identityId)).toEqual(['alice', 'bob']);
      expect(send).toHaveBeenCalledTimes(2);
      expect(vi.mocked(send).mock.calls.map(call => call[0].headers.cookie)).toEqual(['sid=PRIVATE_alice', 'sid=PRIVATE_bob']);
      expect(JSON.stringify(evidence)).not.toMatch(/PRIVATE_/);
    } finally { await auth.close(); }
  });
});

import { describe, expect, it, vi } from 'vitest';
import type { AuthSession, BrowserSession, CookieEvidence, HttpRequest, RequestExecutor,
  ProbeContext, SecurityProbe, TestIdentity } from '../src/index.js';
import { AuthorizationProbe, CapabilityRegistry, CookieSecurityProbe, CrossOriginProbe,
  NormalizedCookieAnalyzer, NormalizedHeaderAnalyzer, NormalizedResponseCollector,
  NormalizedResponseComparator, ProbeRegistry, RuntimeError, SQLInjectionProbe, XSSProbe } from '../src/index.js';
import { context as analysis, identities, origin } from './helpers.js';

declare module '../src/probes/registry.js' {
  interface ProbeCatalog { 'test-observation': SecurityProbe<ProbeContext, { readonly count: number }> }
}
const collector = new NormalizedResponseCollector();
function response(body = 'public', status = 200, headers: Record<string, readonly string[]> = {}, truncated = false,
  url = `${origin}/search?q=private-query`) {
  return collector.collect({ url, method: 'GET' }, { status, headers, body: Buffer.from(body), truncated, firstByteMs: 1 },
    { startedAt: '2026-10-18T00:00:00.000Z', firstByteMs: 1, durationMs: 2 });
}
function setup(execute = vi.fn<RequestExecutor['execute']>(async () => response())) {
  const capabilities = new CapabilityRegistry().register('request-executor', { execute })
    .register('response-collector', collector).register('cookie-analyzer', new NormalizedCookieAnalyzer())
    .register('header-analyzer', new NormalizedHeaderAnalyzer()).register('response-comparator', new NormalizedResponseComparator());
  return { capabilities, project: analysis.project, execute };
}
const point = { name: 'q', location: 'query' } as const;
const request = { url: '/search?q=ordinary&keep=1' };
const cookie: CookieEvidence = { name: 'sid', value: '[REDACTED]', domain: '127.0.0.1', path: '/',
  hostOnly: true, httpOnly: true, secure: false, sameSite: 'Lax', expiresAt: null, maxAge: null, partitioned: false, source: 'jar' };
function authenticate(capabilities: CapabilityRegistry, execute: (identity: string, request: HttpRequest) => ReturnType<RequestExecutor['execute']>) {
  const sessions: AuthSession[] = [], closes: ReturnType<typeof vi.fn>[] = [];
  const establishSession = vi.fn(async (identity: TestIdentity): Promise<AuthSession> => {
    const close = vi.fn(async () => undefined); closes.push(close);
    const page: BrowserSession = { id: `page-${identity.id}`, identityId: identity.id,
      inspect: async () => ({ url: origin, controls: [] }), perform: async () => undefined,
      network: () => [], cookies: async () => [cookie], transferCookies: async () => [], importCookies: async () => undefined };
    const session: AuthSession = { id: `session-${identity.id}`, identityId: identity.id, expiresAt: '2099-01-01',
      http: { execute: input => execute(identity.id, input) }, withBrowser: async callback => callback(page),
      cookies: async () => [cookie], network: () => [], close };
    sessions.push(session); return session;
  });
  capabilities.register('authentication-manager', { establishSession });
  capabilities.register('cookie-inspector', { inspect: session => session.cookies() });
  return { establishSession, sessions, closes };
}

describe('probe registration and capability dispatch', () => {
  it('registers five typed probes and an independently added family', async () => {
    const registry = new ProbeRegistry().register('cookie-security', new CookieSecurityProbe())
      .register('cross-origin', new CrossOriginProbe()).register('authorization', new AuthorizationProbe())
      .register('xss', new XSSProbe()).register('sql-injection', new SQLInjectionProbe());
    registry.register('test-observation', { metadata: () => ({ id: 'test-observation', requiredCapabilities: [], optionalCapabilities: [] }),
      supports: () => true, execute: async () => Object.freeze({ count: 7 }) });
    expect(await registry.get('test-observation').execute(setup())).toEqual({ count: 7 });
    expect(registry.list()).toHaveLength(6);
    expect(Object.isFrozen(registry.list()[0]!.requiredCapabilities)).toBe(true);
    expect(() => registry.register('cookie-security', new CookieSecurityProbe())).toThrow('invalid-request');
    expect(() => new ProbeRegistry().get('xss')).toThrow('unsupported-capability');
    const empty = { project: analysis.project, capabilities: new CapabilityRegistry(), request, parameter: point };
    expect(new XSSProbe().supports(empty)).toBe(false);
    await expect(new XSSProbe().execute(empty)).rejects.toThrow('unsupported-capability');
    expect(() => empty.capabilities.get('request-executor')).toThrow('unsupported-capability');
    expect(() => setup().capabilities.register('response-collector', collector)).toThrow('invalid-request');
  });
  it('rejects out-of-scope, credential-bearing and mutating targets before network or authentication', async () => {
    const state = setup(), auth = authenticate(state.capabilities, async () => response());
    for (const badRequest of [{ url: 'https://forbidden.test/' }, { url: '/', headers: { Authorization: 'private' } },
      { url: '/', method: 'DELETE' }]) {
      await expect(new CookieSecurityProbe().execute({ ...state, request: badRequest, identities })).rejects.toBeInstanceOf(RuntimeError);
    }
    expect(state.execute).not.toHaveBeenCalled(); expect(auth.establishSession).not.toHaveBeenCalled();
  });
  it('sanitizes capability failures and preserves cancellation', async () => {
    const state = setup(vi.fn(async () => { throw new Error('private-cookie password'); }));
    await expect(new CookieSecurityProbe().execute({ ...state, request })).rejects.toThrow(/^transport-failed$/);
    await expect(new SQLInjectionProbe().execute({ ...setup(), request, parameter: point,
      signal: AbortSignal.abort() })).rejects.toThrow('cancelled');
  });
  it('projects public fields even when custom adapters return extra private properties', async () => {
    const capabilities = new CapabilityRegistry().register('request-executor', { execute: async () => response() })
      .register('response-collector', { collect: collector.collect.bind(collector), evidence: input => ({
        ...collector.evidence(input), privateRawBody: 'private-adapter-output',
      }) }).register('response-comparator', { compare: (left, right) => ({
        ...new NormalizedResponseComparator().compare(left, right), privateBody: 'private-adapter-output',
      }) });
    const evidence = await new SQLInjectionProbe().execute({ project: analysis.project, capabilities, request, parameter: point });
    expect(JSON.stringify(evidence)).not.toContain('private-adapter-output');
  });
});

describe('cookie investigation', () => {
  it('collects anonymous and authenticated metadata once and freezes redacted reusable evidence', async () => {
    const state = setup(vi.fn(async () => response('private response body', 200, {
      'set-cookie': ['theme=secret-theme; Path=/; SameSite=None; Secure'], authorization: ['private-token'],
    })));
    const auth = authenticate(state.capabilities, async () => response('private-account', 200, {
      'set-cookie': ['sid=private-session; HttpOnly; Path=/; SameSite=Lax'],
    }));
    const evidence = await new CookieSecurityProbe().execute({ ...state, request, identities: identities.slice(0, 1) });
    expect(evidence.outcome).toBe('COMPLETED'); expect(state.execute).toHaveBeenCalledTimes(1);
    expect(auth.establishSession).toHaveBeenCalledTimes(1); expect(auth.closes[0]).toHaveBeenCalledTimes(1);
    expect(evidence.observations[0]!.cookies[0]).toMatchObject({ secure: true, httpOnly: false, sameSite: 'None' });
    expect(evidence.observations[1]!.cookies[0]).toMatchObject({ httpOnly: true, secure: false, value: '[REDACTED]' });
    expect(Object.isFrozen(evidence.observations[1]!.cookies[0])).toBe(true);
    const serialized = JSON.stringify(evidence);
    for (const secret of ['secret-theme', 'private-session', 'private response body', 'private-query', 'private-token']) expect(serialized).not.toContain(secret);
    expect(() => (evidence.observations as unknown[]).push({})).toThrow();
  });
  it('closes the active session when cookie inspection fails and rejects duplicate identities', async () => {
    const state = setup(), auth = authenticate(state.capabilities, async () => { throw new Error('private login secret'); });
    await expect(new CookieSecurityProbe().execute({ ...state, request, identities: [identities[0]!] })).rejects.toThrow(/^transport-failed$/);
    expect(auth.closes[0]).toHaveBeenCalledTimes(1);
    await expect(new CookieSecurityProbe().execute({ ...setup(), request, identities: [identities[0]!, identities[0]!] }))
      .rejects.toThrow('unsupported-capability');
  });
  it('retains browser-only Secure cookies alongside the HTTP jar metadata', async () => {
    const state = setup(); authenticate(state.capabilities, async () => response());
    const browserCookie = { ...cookie, name: 'browser-secure', secure: true, source: 'browser' as const };
    state.capabilities.register('browser-controller', { withSession: async (identity, execute) => execute({
      id: 'browser', identityId: identity.id, perform: async () => undefined,
      inspect: async () => ({ url: origin, controls: [] }), cookies: async () => [browserCookie], network: () => [],
      transferCookies: async () => [], importCookies: async () => undefined,
    }) });
    const evidence = await new CookieSecurityProbe().execute({ ...state, request, identities: [identities[0]!] });
    expect(evidence.observations[1]!.cookies).toContainEqual(expect.objectContaining({ name: 'browser-secure', secure: true, source: 'browser' }));
    expect(Object.isFrozen(browserCookie)).toBe(false);
  });
});

describe('cross-origin investigation', () => {
  it('uses uncredentialed preflights and session-backed actual requests without navigating to Origin values', async () => {
    const state = setup(vi.fn(async input => response('', 204, { 'access-control-allow-origin': [input.headers!.Origin!],
      'access-control-allow-credentials': ['true'], 'access-control-allow-headers': ['x-probe, content-type'] })));
    const actual = vi.fn(async (_identity: string, input: HttpRequest) => response('', 200,
      { 'access-control-allow-origin': [input.headers!.Origin!], 'access-control-allow-credentials': ['true'] }));
    const auth = authenticate(state.capabilities, actual);
    const evidence = await new CrossOriginProbe().execute({ ...state, request: { url: '/account' }, identity: identities[0]!,
      origins: ['null', 'https://outside.invalid'], requestedHeaders: ['x-probe'] });
    expect(state.execute).toHaveBeenCalledTimes(2); expect(actual).toHaveBeenCalledTimes(2);
    for (const [input] of state.execute.mock.calls) {
      expect(input.method).toBe('OPTIONS'); expect(input.headers).not.toHaveProperty('Cookie');
      expect(new URL(input.url).origin).toBe(origin);
    }
    expect(evidence.observations[0]).toMatchObject({ requestedOrigin: 'null', credentialMode: 'session',
      preflight: { cors: { allowHeaders: ['x-probe', 'content-type'] } }, actual: { cors: { allowCredentials: [true] } } });
    expect(auth.closes[0]).toHaveBeenCalledTimes(1);
  });
  it.each(['https://outside.invalid/path', 'https://user:secret@outside.invalid', 'file:///tmp', 'null\r\nCookie: private'])(
    'rejects malformed Origin %s before sending anything', async badOrigin => {
      const state = setup();
      await expect(new CrossOriginProbe().execute({ ...state, request, origins: [badOrigin] })).rejects.toThrow('invalid-request');
      expect(state.execute).not.toHaveBeenCalled();
    });
});

describe('cross-persona authorization investigation', () => {
  const resource = { id: 'order-101', ownerIdentityId: 'alice', request: { url: '/api/orders/101' }, ownerMarkers: ['private-owner-address'] };
  it.each([true, false])('compares owner, attacker and anonymous responses with shared access %s', async shared => {
    const state = setup(vi.fn(async () => response('login required', 401)));
    const auth = authenticate(state.capabilities, async identity => identity === 'alice' || shared
      ? response('{"address":"private-owner-address"}') : response('denied', 403));
    const evidence = await new AuthorizationProbe().execute({ ...state, owner: identities[0]!, attacker: identities[1]!, resource });
    expect(evidence.attackerComparison.ownerMarkersMatch).toBe(shared);
    expect(evidence.attacker.status).toBe(shared ? 200 : 403); expect(evidence.anonymous.status).toBe(401);
    expect(evidence.anonymousComparison.ownerMarkersMatch).toBe(false);
    expect(auth.sessions.map(session => session.identityId)).toEqual(['alice', 'bob']);
    expect(auth.closes.every(close => close.mock.calls.length === 1)).toBe(true);
    expect(JSON.stringify(evidence)).not.toContain('private-owner-address');
    expect(evidence).not.toHaveProperty('verdict'); expect(evidence).not.toHaveProperty('cweId');
  });
  it('discovers the resource through the authenticated owner capability', async () => {
    const state = setup(); authenticate(state.capabilities, async () => response('private-owner-address'));
    const discoverResource = vi.fn(async (owner: AuthSession) => {
      expect(owner.identityId).toBe('alice'); await owner.withBrowser(async page => page.inspect()); return resource;
    });
    await new AuthorizationProbe().execute({ ...state, owner: identities[0]!, attacker: identities[1]!, discoverResource });
    expect(discoverResource).toHaveBeenCalledTimes(1);
  });
  it('refuses same-identity comparisons, unbound ownership and discovered scope escapes; always closes sessions', async () => {
    const state = setup(), auth = authenticate(state.capabilities, async () => response());
    await expect(new AuthorizationProbe().execute({ ...state, owner: identities[0]!, attacker: identities[0]!, resource }))
      .rejects.toThrow('invalid-request');
    await expect(new AuthorizationProbe().execute({ ...state, owner: identities[0]!, attacker: identities[1]!,
      resource: { ...resource, ownerIdentityId: 'bob' } })).rejects.toThrow('invalid-request');
    expect(auth.establishSession).not.toHaveBeenCalled();
    await expect(new AuthorizationProbe().execute({ ...state, owner: identities[0]!, attacker: identities[1]!,
      discoverResource: async () => ({ ...resource, request: { url: 'https://outside.invalid/' } }) })).rejects.toThrow('scope-denied');
    expect(auth.closes[0]).toHaveBeenCalledTimes(1); expect(state.execute).not.toHaveBeenCalled();
  });
  it('marks truncated comparisons as unknown instead of equal or negative', () => {
    const comparison = new NormalizedResponseComparator().compare(response('same'), response('same', 200, {}, true), ['same']);
    expect(comparison).toMatchObject({ bodyEqual: null, ownerMarkersMatch: null });
  });
});

describe('injection investigations', () => {
  it('records inert literal HTML reflection while keeping execution and DOM reach unknown without a scanner', async () => {
    const state = setup(vi.fn(async input => response(new URL(input.url).searchParams.get('q')!, 200, { 'content-type': ['text/html'] })));
    const evidence = await new XSSProbe().execute({ ...state, request, parameter: point });
    expect(evidence.literalReflection).toBe(true); expect(evidence.reflectionContexts).toContain('html');
    expect(evidence.executionConfirmed).toBeNull(); expect(evidence.domSinkReached).toBeNull();
    expect(evidence.diagnostics).toEqual(['browser-unavailable', 'scanner-unavailable']);
    expect(state.execute).toHaveBeenCalledTimes(2);
    for (const [input] of state.execute.mock.calls) expect(new URL(input.url).searchParams.get('keep')).toBe('1');
    expect(JSON.stringify(evidence)).not.toContain('agento-canary');
    expect(evidence.injected.url).toContain('REDACTED');
  });
  it('keeps escaped reflection distinct from execution and incomplete absence unknown', async () => {
    for (const truncated of [false, true]) {
      const state = setup(vi.fn(async input => response(new URL(input.url).searchParams.get('q')!.replaceAll('<', '&lt;'), 200, {}, truncated)));
      const evidence = await new XSSProbe().execute({ ...state, request, parameter: point });
      expect(evidence.literalReflection).toBe(truncated ? null : false);
      expect(evidence.executionConfirmed).toBeNull();
    }
  });
  it('uses a browser capability and normalized scanner output, enforces scanner request budgets and revokes retained capabilities', async () => {
    const state = setup();
    let visited = '', retained: RequestExecutor | undefined;
    state.capabilities.register('browser-controller', { withSession: async (_identity, execute) => execute({
      id: 'anonymous', identityId: 'probe-anonymous', perform: async action => { if (action.action === 'navigate') visited = action.url; },
      inspect: async () => ({ url: visited, visibleTextSummary: new URL(visited).searchParams.get('q')!, controls: [] }),
      cookies: async () => [], network: () => [], transferCookies: async () => [], importCookies: async () => undefined,
    }) });
    state.capabilities.register('xss-scanner', { scan: async input => {
      retained = input.executor;
      await expect(input.executor.execute({ url: 'https://outside.invalid/' })).rejects.toThrow('scope-denied');
      for (let index = 0; index < 7; index++) await input.executor.execute(input.request);
      await expect(input.executor.execute(input.request)).rejects.toThrow('record-limit');
      return { executionConfirmed: true, domSinkReached: true, privateRawOutput: 'private-token' };
    } });
    const evidence = await new XSSProbe().execute({ ...state, request, parameter: point,
      anonymousIdentity: { id: 'guest', label: 'Guest', roles: [], authentication: 'anonymous' } });
    expect(evidence.browser?.canaryVisible).toBe(true); expect(evidence.executionConfirmed).toBe(true);
    expect(JSON.stringify(evidence)).not.toContain('private-token');
    await expect(retained!.execute({ url: `${origin}/search?q=x` })).rejects.toThrow('session-closed');
  });
  it.each(['json-body', 'form-body'] as const)('mutates only the declared %s parameter', async location => {
    const state = setup(vi.fn(async input => response(input.body!)));
    const json = location === 'json-body';
    await new XSSProbe().execute({ ...state, request: { url: '/search', method: 'POST',
      headers: { 'Content-Type': json ? 'application/json' : 'application/x-www-form-urlencoded' },
      body: json ? '{"q":"original","keep":"private-preserved"}' : 'q=original&keep=private-preserved' },
      parameter: { name: 'q', location } });
    const mutated = state.execute.mock.calls[1]![0].body!;
    expect(json ? JSON.parse(mutated).keep : new URLSearchParams(mutated).get('keep')).toBe('private-preserved');
    expect(mutated).toContain('agento');
  });
  it('reports syntax markers and boolean deltas without a vulnerability verdict', async () => {
    const state = setup(vi.fn(async input => {
      const q = new URL(input.url).searchParams.get('q')!;
      return response(q.endsWith("'1'='2") ? 'none' : q.endsWith("'1'='1") ? 'match' : q.endsWith("'")
        ? 'SQLITE_ERROR: unrecognized token' : 'baseline', q.endsWith("'") ? 500 : 200);
    }));
    const evidence = await new SQLInjectionProbe().execute({ ...state, request, parameter: point });
    expect(state.execute).toHaveBeenCalledTimes(4);
    expect(evidence.observations[0]).toMatchObject({ technique: 'error', dbmsFingerprint: 'SQLite', response: { status: 500 } });
    expect(evidence.booleanComparison.bodyEqual).toBe(false); expect(evidence.scanner).toBeNull();
    expect(evidence.diagnostics).toEqual(['scanner-unavailable']);
    expect(evidence).not.toHaveProperty('vulnerable');
  });
  it('accepts normalized SQL scanner evidence without importing a tool', async () => {
    const state = setup();
    state.capabilities.register('sql-scanner', { scan: async () => ({ technique: 'boolean', dbmsFingerprint: 'PostgreSQL', observedDifference: false }) });
    const evidence = await new SQLInjectionProbe().execute({ ...state, request, parameter: point });
    expect(evidence.outcome).toBe('COMPLETED'); expect(evidence.scanner?.observedDifference).toBe(false);
  });
  it('sanitizes scanner failure, closes authenticated sessions and revokes the scanner executor', async () => {
    const state = setup(), auth = authenticate(state.capabilities, async () => response());
    let retained: RequestExecutor | undefined;
    state.capabilities.register('xss-scanner', { scan: async input => { retained = input.executor; throw new Error('private-scanner-output'); } });
    await expect(new XSSProbe().execute({ ...state, request, parameter: point, identity: identities[0]! }))
      .rejects.toThrow(/^transport-failed$/);
    expect(auth.closes[0]).toHaveBeenCalledTimes(1);
    await expect(retained!.execute({ url: `${origin}/search?q=x` })).rejects.toThrow('session-closed');
  });
  it('requires a configured anonymous persona and rejects malformed scanner observations', async () => {
    const state = setup(), withSession = vi.fn(async () => { throw new Error('unexpected anonymous session'); });
    state.capabilities.register('browser-controller', { withSession });
    const evidence = await new XSSProbe().execute({ ...state, request, parameter: point });
    expect(evidence.diagnostics).toContain('browser-unavailable'); expect(withSession).not.toHaveBeenCalled();
    state.capabilities.register('sql-scanner', { scan: async () => ({ technique: 'error', dbmsFingerprint: null,
      observedDifference: 'yes' as unknown as boolean }) });
    await expect(new SQLInjectionProbe().execute({ ...state, request, parameter: point })).rejects.toThrow('invalid-request');
  });
  it('rejects malformed injection points and stops after cancellation between requests', async () => {
    for (const parameter of [{ name: 'missing', location: 'query' }, { name: 'q', location: 'cookie' }]) {
      const state = setup();
      await expect(new XSSProbe().execute({ ...state, request, parameter: parameter as typeof point })).rejects.toThrow('invalid-request');
      expect(state.execute).not.toHaveBeenCalled();
    }
    const controller = new AbortController(), state = setup(vi.fn(async () => { controller.abort(); return response(); }));
    await expect(new SQLInjectionProbe().execute({ ...state, request, parameter: point, signal: controller.signal })).rejects.toThrow('cancelled');
    expect(state.execute).toHaveBeenCalledTimes(1);
  });
});

import { describe, expect, it } from 'vitest';
import type { Project } from '@agento/core';
import type { CookieEvidence, HeaderEvidence, HttpResponseEvidence, NetworkEvidence } from '@agento/runtime';
import { fromRuntimeSnapshot } from '../src/index.js';
import type { RuntimeSnapshot } from '../src/index.js';

const project: Project = { id: 'runtime-shop', name: 'Shop', mode: 'black-box', baseUrl: 'https://shop.test',
  allowedOrigins: ['https://shop.test', 'https://api.shop.test'], languages: [] };
const capturedAt = '2026-10-18T00:00:00.000Z';
const response = (extra: Partial<HttpResponseEvidence> = {}): HttpResponseEvidence => ({
  responseId: 'response-1', url: 'https://shop.test/orders/102', method: 'GET', status: 200,
  body: { sha256: 'a'.repeat(64), byteLength: 50, truncated: false },
  timings: { startedAt: capturedAt, firstByteMs: 2, durationMs: 5 }, ...extra,
});
const headers = (responseId = 'response-1'): HeaderEvidence => ({ responseId,
  cors: { allowOrigin: ['https://shop.test', ''], allowCredentials: [true, null, false],
    allowMethods: ['GET', 'OPTIONS'], allowHeaders: ['Content-Type'], exposeHeaders: ['X-Count'], maxAge: [120, null] },
  security: { 'x-frame-options': ['DENY'] },
  caching: { cacheControl: [], pragma: [], vary: ['Origin'], expires: [], age: [] },
});
const cookie = (extra: Partial<CookieEvidence> = {}): CookieEvidence => ({ name: 'sid', value: '[REDACTED]',
  domain: 'shop.test', path: '/', hostOnly: true, httpOnly: true, secure: true, sameSite: 'Lax', expiresAt: null,
  maxAge: null, partitioned: false, source: 'response', responseId: 'response-1', ...extra,
});
const network = (extra: Partial<NetworkEvidence> = {}): NetworkEvidence => ({ sessionId: 'session-alice', identityId: 'alice',
  source: 'browser', url: 'https://shop.test/orders/102', method: 'GET', status: 200, blocked: false, ...extra });
const snapshot = (extra: Partial<RuntimeSnapshot> = {}): RuntimeSnapshot => ({ producerId: 'normalized-runtime', capturedAt, ...extra });

describe('public runtime contributions', () => {
  it('wraps safe projections and associates CORS and cookies by response ID without inferring identity or authentication', () => {
    const input = snapshot({ responses: [response()], headers: [headers()], cookies: [cookie()], network: [network()] });
    const result = fromRuntimeSnapshot(project, input);
    expect(result.source).toBe('runtime');
    expect(result.components).toHaveLength(1);
    expect(result.endpoints).toHaveLength(1);
    expect(result.evidence).toHaveLength(4);
    const endpoint = result.endpoints![0]!;
    expect(endpoint).toMatchObject({ method: 'GET', path: '/orders/102', authentication: 'unknown', roles: [] });
    expect(result.endpointOrigins![endpoint.id]).toBe('https://shop.test');
    expect(endpoint.evidenceIds).toEqual(result.evidence!.map(item => item.id).sort());
    for (const item of result.evidence!) {
      expect(item).toMatchObject({ projectId: project.id, producerId: input.producerId, capturedAt, endpointId: endpoint.id });
      expect(item.facts).toMatchObject({ url: 'https://shop.test/orders/102', origin: 'https://shop.test' });
      expect(item.identityId).toBe(item.facts.observation === 'network' ? 'alice' : undefined);
    }
    expect(result.evidence!.find(item => item.facts.observation === 'cors')!.facts.options).toEqual(headers().cors);
    expect(result.evidence!.find(item => item.facts.observation === 'cookie')!.facts).toMatchObject({
      name: 'sid', httpOnly: true, secure: true, sameSite: 'Lax', value: '[REDACTED]', responseId: 'response-1',
    });
    expect(result.resources).toBeUndefined();
    expect(result.facts).toBeUndefined();
    expect(JSON.parse(JSON.stringify(result))).toEqual(result);
  });

  it('redacts every URL query value and removes credentials and fragments while preserving query names and input data', () => {
    const privateUrl = 'https://private-user:private-password@shop.test/orders/102?token=private-token&view=private-view&view=private-second#private-fragment';
    const input = snapshot({ responses: [response({ url: privateUrl })], network: [network({ url: privateUrl })] });
    const before = structuredClone(input);
    const result = fromRuntimeSnapshot(project, input);
    for (const item of result.evidence!) {
      const url = new URL(item.facts.url as string);
      expect(url.username).toBe(''); expect(url.password).toBe(''); expect(url.hash).toBe('');
      expect([...url.searchParams.entries()]).toEqual([
        ['token', '[REDACTED]'], ['view', '[REDACTED]'], ['view', '[REDACTED]'],
      ]);
    }
    expect(result.endpoints![0]!.parameters).toEqual([
      { name: 'token', location: 'query', required: false }, { name: 'view', location: 'query', required: false },
    ]);
    expect(JSON.stringify(result)).not.toMatch(/private-user|private-password|private-token|private-view|private-second|private-fragment/);
    expect(input).toEqual(before);
  });

  it('copies only public allowlisted fields and forcibly redacts cookie values even when runtime types are bypassed', () => {
    const unsafeResponse = { ...response(), privateData: 'private-response-extra', headers: { authorization: 'private-authorization' },
      body: { ...response().body, data: 'private-raw-body', secret: 'private-body-extra' },
      timings: { ...response().timings, privateData: 'private-timing-extra' } } as unknown as HttpResponseEvidence;
    const unsafeHeaders = { ...headers(), security: { 'content-security-policy': ['private-security-header'] },
      caching: { privateData: 'private-cache-header' }, privateData: 'private-header-extra',
      cors: { ...headers().cors, privateData: 'private-cors-extra' } } as unknown as HeaderEvidence;
    const unsafeCookie = { ...cookie(), value: 'private-cookie-value', privateData: 'private-cookie-extra',
      session: { secret: 'private-cookie-session' } } as unknown as CookieEvidence;
    const unsafeNetwork = { ...network(), privateData: 'private-network-extra', headers: { cookie: 'private-network-cookie' } } as unknown as NetworkEvidence;
    const input = snapshot({ responses: [unsafeResponse], headers: [unsafeHeaders], cookies: [unsafeCookie], network: [unsafeNetwork] });
    const result = fromRuntimeSnapshot(project, input);
    expect(JSON.stringify(result)).not.toContain('private-');
    expect(result.evidence!.find(item => item.facts.observation === 'http-response')!.facts).toEqual({
      observation: 'http-response', responseId: 'response-1', url: 'https://shop.test/orders/102', origin: 'https://shop.test',
      method: 'GET', status: 200, body: response().body, timings: response().timings,
    });
    const cors = result.evidence!.find(item => item.facts.observation === 'cors')!.facts;
    expect(Object.keys(cors).sort()).toEqual(['observation', 'options', 'origin', 'responseId', 'url']);
    expect(cors.options).toEqual(headers().cors);
    expect(result.evidence!.find(item => item.facts.observation === 'cookie')!.facts.value).toBe('[REDACTED]');
    expect(unsafeCookie.value).toBe('private-cookie-value');
  });

  it('retains blocked, incomplete and unsupported-method network observations without creating endpoints', () => {
    const result = fromRuntimeSnapshot(project, snapshot({ network: [
      network({ url: 'https://outside.test/blocked?token=secret', blocked: true }),
      network({ url: 'https://shop.test/incomplete', status: null }),
      network({ url: 'https://shop.test/extension', method: 'PROPFIND' }),
    ] }));
    expect(result.endpoints).toEqual([]);
    expect(result.components).toEqual([]);
    expect(result.evidence).toHaveLength(3);
    expect(result.evidence!.every(item => item.endpointId === undefined)).toBe(true);
    expect(result.evidence!.find(item => item.facts.blocked === true)!.facts.status).toBe(200);
    expect(JSON.stringify(result)).not.toContain('secret');
  });

  it('keeps orphaned CORS and cookie projections without assigning them to an unrelated response or network session', () => {
    const result = fromRuntimeSnapshot(project, snapshot({ responses: [response()], network: [network()],
      headers: [headers('unknown-response')], cookies: [cookie({ responseId: 'unknown-response', sessionId: 'session-alice' })] }));
    const orphans = result.evidence!.filter(item => item.facts.responseId === 'unknown-response');
    expect(orphans).toHaveLength(2);
    for (const item of orphans) {
      expect(item.endpointId).toBeUndefined(); expect(item.identityId).toBeUndefined();
      expect(item.facts.url).toBeUndefined(); expect(item.facts.origin).toBeUndefined();
    }
    expect(result.endpoints![0]!.evidenceIds).toHaveLength(2);
  });

  it('keeps equal paths on separate origins and methods distinct while merging repeated observations of one route', () => {
    const result = fromRuntimeSnapshot(project, snapshot({ responses: [
      response({ url: 'https://shop.test/orders/102?z=one' }),
      response({ responseId: 'response-2', url: 'https://api.shop.test/orders/102' }),
      response({ responseId: 'response-3', url: 'https://shop.test/orders/102?a=two' }),
    ], network: [network({ method: 'POST' })] }));
    expect(result.endpoints).toHaveLength(3);
    expect(result.components).toHaveLength(2);
    expect(new Set(result.endpoints!.map(item => item.id)).size).toBe(3);
    const get = result.endpoints!.find(item => item.method === 'GET' && result.endpointOrigins![item.id] === 'https://shop.test')!;
    expect(get.evidenceIds).toHaveLength(2);
    expect(get.parameters.map(item => item.name)).toEqual(['a', 'z']);
    expect(new Set(result.endpoints!.map(item => `${item.method} ${result.endpointOrigins![item.id]} ${item.path}`))).toEqual(new Set([
      'GET https://shop.test /orders/102', 'GET https://api.shop.test /orders/102', 'POST https://shop.test /orders/102',
    ]));
  });

  it('deduplicates identical public response snapshots without duplicating evidence references', () => {
    const single = fromRuntimeSnapshot(project, snapshot({ responses: [response()] }));
    const repeated = fromRuntimeSnapshot(project, snapshot({ responses: [response(), structuredClone(response())] }));
    expect(repeated).toEqual(single);
    expect(repeated.endpoints![0]!.evidenceIds).toHaveLength(1);
  });

  it.each([
    ['URL', response({ url: 'https://api.shop.test/orders/102' })],
    ['method', response({ method: 'POST' })],
    ['status', response({ status: 404 })],
    ['body', response({ body: { sha256: 'b'.repeat(64), byteLength: 50, truncated: false } })],
    ['timing', response({ timings: { startedAt: capturedAt, firstByteMs: 3, durationMs: 5 } })],
  ])('rejects reused response IDs with conflicting %s before associating headers and cookies', (_label, conflicting) => {
    const input = snapshot({ responses: [response(), conflicting], headers: [headers()], cookies: [cookie()] });
    expect(() => fromRuntimeSnapshot(project, input)).toThrow('Invalid public runtime snapshot');
    expect(() => fromRuntimeSnapshot(project, { ...input, responses: [...input.responses!].reverse() })).toThrow('Invalid public runtime snapshot');
  });

  it('rejects reused response IDs even when sanitization makes their different query values look identical', () => {
    const input = snapshot({ responses: [
      response({ url: 'https://shop.test/orders/102?token=private-first' }),
      response({ url: 'https://shop.test/orders/102?token=private-second' }),
    ], headers: [headers()], cookies: [cookie()] });
    expect(() => fromRuntimeSnapshot(project, input)).toThrow('Invalid public runtime snapshot');
  });

  it('produces identical public contributions when the snapshot collections are reordered', () => {
    const input = snapshot({ responses: [
      response({ url: 'https://shop.test/orders/102?z=first' }),
      response({ responseId: 'response-2', url: 'https://api.shop.test/orders/103' }),
      response({ responseId: 'response-3', url: 'https://shop.test/orders/102?a=last' }),
    ], headers: [headers(), headers('response-2')], cookies: [cookie(), cookie({ name: 'preference', responseId: 'response-2' })],
    network: [network(), network({ url: 'https://api.shop.test/orders/103', identityId: 'bob', sessionId: 'session-bob' })] });
    const reordered = { ...input, responses: [...input.responses!].reverse(), headers: [...input.headers!].reverse(),
      cookies: [...input.cookies!].reverse(), network: [...input.network!].reverse() };
    const expected = fromRuntimeSnapshot(project, input);
    expect(fromRuntimeSnapshot(project, reordered)).toEqual(expected);
    expect(JSON.stringify(fromRuntimeSnapshot(project, reordered))).toBe(JSON.stringify(expected));
    expect(fromRuntimeSnapshot({ ...project, id: 'other-project' }, input).endpoints![0]!.id).not.toBe(expected.endpoints![0]!.id);
  });

  const malformed: readonly [string, unknown][] = [
    ['missing producer', { producerId: undefined }], ['missing capture time', { capturedAt: undefined }], ['non-object snapshot', null],
    ['invalid response collection', { responses: {} }], ['null response collection', { responses: null }],
    ['invalid response URL', { responses: [response({ url: 'invalid private-token' })] }],
    ['non-HTTP response URL', { responses: [response({ url: 'file:///private-response' })] }],
    ['invalid status', { responses: [response({ status: 0 })] }],
    ['nonfinite timing', { responses: [response({ timings: { startedAt: capturedAt, firstByteMs: Infinity, durationMs: 1 } })] }],
    ['negative body length', { responses: [response({ body: { sha256: 'a'.repeat(64), byteLength: -1, truncated: false } })] }],
    ['raw response body', { responses: [{ ...response(), body: { data: 'private-body' } }] }],
    ['invalid boolean', { responses: [{ ...response(), body: { ...response().body, truncated: 'private-value' } }] }],
    ['invalid CORS credentials', { headers: [{ ...headers(), cors: { ...headers().cors, allowCredentials: ['private-value'] } }] }],
    ['invalid CORS collection', { headers: [{ ...headers(), cors: { ...headers().cors, allowOrigin: null } }] }],
    ['invalid cookie source', { cookies: [{ ...cookie(), source: 'private-source' }] }],
    ['invalid cookie SameSite', { cookies: [{ ...cookie(), sameSite: 'private-same-site' }] }],
    ['missing cookie domain', { cookies: [{ ...cookie(), domain: '' }] }],
    ['invalid network source', { network: [{ ...network(), source: 'private-source' }] }],
    ['invalid network status', { network: [network({ status: 600 })] }],
    ['invalid network method', { network: [network({ method: 'GET private-token' })] }],
  ];
  it.each(malformed)('rejects malformed input (%s) without exposing private values in errors', (_label, values) => {
    const input = values === null ? null : { ...snapshot(), ...values as object };
    let error: unknown;
    try { fromRuntimeSnapshot(project, input as RuntimeSnapshot); } catch (caught) { error = caught; }
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe('Invalid public runtime snapshot');
    expect((error as Error).message).not.toContain('private-');
  });
});

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  AuthorizationProbe, CapabilityRegistry, CookieSecurityProbe, CrossOriginProbe, DeterministicRequestExecutor,
  NormalizedCookieAnalyzer, NormalizedHeaderAnalyzer, NormalizedResponseCollector, NormalizedResponseComparator,
  SQLInjectionProbe, XSSProbe, type AuthenticationManager,
} from '@agento/runtime';
import { CWE79Plugin, CWE89Plugin, CWE639Plugin, CWE862Plugin, CWE942Plugin, CWE1004Plugin, CWE614Plugin, toCoreEvidence } from '../src/index.js';
import { context, policy, project, scope } from './helpers.js';

const suite = process.env.AGENTO_CWE_INTEGRATION === '1' ? describe : describe.skip;
suite('rules consuming actual probe output over loopback HTTP', () => {
  let server: Server, origin: string, mode: 'vulnerable' | 'fixed';
  beforeAll(async () => {
    server = createServer((req, res) => {
      const target = new URL(req.url!, origin), identity = req.headers['x-test-identity'];
      if (target.pathname === '/cookies') {
        res.setHeader('Set-Cookie', `sid=private-session; Path=/; SameSite=Lax${mode === 'fixed' ? '; HttpOnly; Secure' : ''}`);
        res.end('Cookie metadata'); return;
      }
      if (target.pathname === '/cors') {
        res.setHeader('Access-Control-Allow-Origin', mode === 'fixed' ? 'https://trusted.test' : String(req.headers.origin));
        res.setHeader('Access-Control-Allow-Credentials', 'true'); res.setHeader('Access-Control-Allow-Methods', 'GET');
        res.setHeader('Access-Control-Allow-Headers', 'x-agento-probe');
        res.statusCode = req.method === 'OPTIONS' ? 204 : 200; res.end(req.method === 'OPTIONS' ? undefined : 'Private profile'); return;
      }
      if (target.pathname === '/orders/1') {
        if (mode === 'fixed' && identity !== 'alice') { res.statusCode = identity ? 403 : 401; res.end('Denied'); }
        else res.end('private-owner-marker'); return;
      }
      const query = target.searchParams.get('q') ?? '';
      if (target.pathname === '/sql') {
        if (mode === 'vulnerable' && query.includes("' AND '1'='2")) res.end('No rows');
        else if (mode === 'vulnerable' && query.endsWith("'")) { res.statusCode = 500; res.end('SQLITE_ERROR: syntax error'); }
        else res.end('Product rows'); return;
      }
      res.setHeader('Content-Type', 'text/html');
      res.end(mode === 'fixed' ? query.replaceAll('<', '&lt;').replaceAll('>', '&gt;') : query);
    });
    await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    if (server) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
  });
  it.each(['vulnerable', 'fixed'] as const)('interprets all five real probe families in %s mode', async selected => {
    mode = selected;
    const targetProject = { ...project, baseUrl: origin, allowedOrigins: [origin] };
    const executor = new DeterministicRequestExecutor({ baseUrl: origin, allowedOrigins: [origin] });
    const manager: AuthenticationManager = { establishSession: async identity => ({
      id: `session:${identity.id}`, identityId: identity.id, expiresAt: new Date(Date.now() + 60_000).toISOString(),
      http: { execute: request => executor.execute({ ...request, headers: { ...request.headers, 'x-test-identity': identity.id } }) },
      withBrowser: async () => { throw new Error('Browser unavailable'); }, cookies: async () => [], network: () => [], close: async () => {},
    }) };
    const capabilities = new CapabilityRegistry().register('request-executor', executor)
      .register('response-collector', new NormalizedResponseCollector()).register('cookie-analyzer', new NormalizedCookieAnalyzer())
      .register('header-analyzer', new NormalizedHeaderAnalyzer()).register('response-comparator', new NormalizedResponseComparator())
      .register('authentication-manager', manager);
    const common = { project: targetProject, capabilities }, identities = context().identities;
    const ruleScope = (path: string) => ({ ...scope, targetUrl: `${origin}${path}` });
    const cookie = await new CookieSecurityProbe().execute({ ...common, request: { url: '/cookies' } });
    expect((await new CWE1004Plugin().evaluate([cookie], ruleScope('/cookies'))).status).toBe(selected === 'vulnerable' ? 'CONFIRMED' : 'REJECTED');
    expect((await new CWE614Plugin().evaluate([cookie], ruleScope('/cookies'))).status).toBe('NOT_REPRODUCED');
    const cors = await new CrossOriginProbe().execute({ ...common, request: { url: '/cors' }, identity: identities[0]!, origins: ['https://unapproved.invalid'] });
    expect((await new CWE942Plugin().evaluate([cors], ruleScope('/cors'))).status).toBe(selected === 'vulnerable' ? 'CONFIRMED' : 'REJECTED');
    const access = await new AuthorizationProbe().execute({ ...common, owner: identities[0]!, attacker: identities[1]!,
      resource: { id: policy.resourceId, ownerIdentityId: policy.ownerIdentityId, request: { url: '/orders/1' }, ownerMarkers: ['private-owner-marker'] } });
    for (const plugin of [new CWE639Plugin(), new CWE862Plugin()]) {
      expect((await plugin.evaluate([access], ruleScope('/orders/1'))).status).toBe(selected === 'vulnerable' ? 'CONFIRMED' : 'REJECTED');
    }
    const xss = await new XSSProbe().execute({ ...common, request: { url: '/xss?q=product' }, parameter: { name: 'q', location: 'query' } });
    expect(xss.literalReflection).toBe(selected === 'vulnerable');
    expect((await new CWE79Plugin().evaluate([xss], ruleScope('/xss'))).status).toBe('NOT_REPRODUCED');
    const sql = await new SQLInjectionProbe().execute({ ...common, request: { url: '/sql?q=product' }, parameter: { name: 'q', location: 'query' } });
    expect((await new CWE89Plugin().evaluate([sql], ruleScope('/sql'))).status).toBe(selected === 'vulnerable' ? 'CONFIRMED' : 'NOT_REPRODUCED');
    const publicRecords = [cookie, cors, access, xss, sql].map(item => toCoreEvidence(item));
    expect(JSON.stringify(publicRecords)).not.toMatch(/private-session|private-owner-marker|x-test-identity/);
  });
});

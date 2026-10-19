import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { BrowserController, HttpTransport, RuntimeCookie, TransportRequest } from '@agento/runtime';
import type { A01ScanOptions } from '../src/index.js';

export type Mode = 'vulnerable' | 'fixed' | 'uniform' | 'owner-denied' | 'anonymous-only' | 'truncated';
export function setup(mode: Mode = 'vulnerable', failLogin = false) {
  const repositoryPath = mkdtempSync(join(tmpdir(), 'agento-a01-unit-'));
  writeFileSync(join(repositoryPath, 'package.json'), '{"dependencies":{"express":"*"}}');
  writeFileSync(join(repositoryPath, 'app.js'), `import express from 'express';
const app = express();
function requireAuth(req, res, next) { if (!req.session.user) return res.status(401).json({error: 'Denied'}); next(); }
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user) return res.status(401).json({error: 'Denied'});
  const fixed = isFixedMode(req);
  if (fixed) { if (req.session.user.role !== 'admin') return res.status(403).json({error: 'Denied'}); }
  next();
}
app.get('/api/orders/:id', requireAuth, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (isFixedMode(req) && order.user_id !== req.session.user.id) return res.status(403).json({error: 'Denied'});
  res.json(order);
});
app.get('/api/admin/users', requireAdmin, (req, res) => { res.json(db.prepare('SELECT * FROM users').all()); });
app.get('/unselected', (req, res) => { res.json({ok: true}); });
`);
  const origin = 'https://target.test', calls: TransportRequest[] = [], logins: string[] = [], closed: string[] = [];
  const cookies: RuntimeCookie[] = [];
  const browser: BrowserController = { withSession: async () => { throw new Error('unguarded browser'); },
    withGuard: guard => ({ withSession: async (identity, callback) => {
      guard.assertActive(); guard.assertRequest({ url: `${origin}/login`, method: 'POST' }); logins.push(identity.id);
      if (failLogin) throw new Error('private-login-failure-password');
      const cookie: RuntimeCookie = { name: 'test-session', value: `private-session-${identity.id}`, domain: 'target.test', path: '/',
        hostOnly: true, httpOnly: true, secure: true, sameSite: 'Strict', expiresAt: null, maxAge: null, partitioned: false };
      cookies.push(cookie);
      const id = `isolated-${identity.id}-${logins.length}`;
      try { return await callback({ id, identityId: identity.id, perform: async () => {}, inspect: async () => ({ url: origin, controls: [] }),
        cookies: async () => [], transferCookies: async () => [cookie], importCookies: async () => {}, network: () => [] }); }
      finally { closed.push(id); }
    } }) };
  const transport: HttpTransport = { send: async request => {
    calls.push(request);
    const route = new URL(request.url).pathname, cookie = request.headers.cookie ?? '';
    const identity = ['alice', 'bob', 'admin'].find(id => cookie.includes(`private-session-${id}`));
    const owner = route.startsWith('/api/orders/') ? identity === 'alice' : identity === 'admin';
    const denied = mode === 'owner-denied' && owner || mode === 'fixed' && !owner
      || route.startsWith('/api/orders/') && !identity || mode === 'anonymous-only' && identity === 'bob';
    const body = denied ? 'Access denied' : mode === 'uniform' ? '{"ok":true}'
      : route.startsWith('/api/orders/') ? '{"private-order":"owner-only-order-content"}' : '{"private-admin":"admin-only-user-content"}';
    return { status: denied ? 403 : 200, headers: { 'content-type': ['application/json'] }, body: Buffer.from(body), firstByteMs: 1,
      truncated: mode === 'truncated' && !owner };
  } };
  const personas = ['alice', 'bob', 'admin'].map(id => ({ id, label: id, roles: [id === 'admin' ? 'admin' : 'customer'], authentication: 'session-cookie' as const }));
  const options: A01ScanOptions = { project: { id: 'a01-unit', name: 'A01 fixture', mode: 'code-aware', repositoryPath,
    baseUrl: origin, allowedOrigins: [origin], languages: ['javascript'] },
    targets: [{ path: '/api/orders/:id', cweId: 'CWE-639', resourceId: 'owned-order', ownerIdentityId: 'alice', attackerIdentityId: 'bob',
      attackerIsUnauthorized: true, anonymousIsUnauthorized: true, pathValues: { id: '102' }, ownerMarkers: ['owner-only-order-content'] },
    { path: '/api/admin/users', cweId: 'CWE-862', resourceId: 'admin-users', ownerIdentityId: 'admin', attackerIdentityId: 'bob',
      attackerIsUnauthorized: true, anonymousIsUnauthorized: true, ownerMarkers: ['admin-only-user-content'] }],
    target: { id: 'unit-target', baseOrigins: [origin], personas }, browser, transport,
    policy: { allowedOrigins: [origin], allowedMethods: ['GET', 'POST'], maxRequestsPerExecution: 20,
      tools: { 'a01-http': {}, 'a01-auth': {} }, approval: { risks: [], severities: [] } } };
  return { options, calls, logins, closed, cookies, repositoryPath };
}

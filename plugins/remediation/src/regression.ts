import { RemediationError } from './contracts.js';

// Public seeded storefront accounts are test fixtures, not host credentials.
const harness = String.raw`import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer, request, type Server } from 'node:https';
import type { IncomingHttpHeaders } from 'node:http';
import { describe, it, beforeAll, afterAll } from 'vitest';

// Run only in an isolated copy. Supply a localhost certificate and its key.
// These are public demo accounts. No production credentials or databases are used.
process.env.DB_PATH = ':memory:';
let server: Server, port: number, certificate: Buffer, db: { close(): void };
beforeAll(async () => {
  assert.ok(process.env.AGENTO_TEST_TLS_KEY && process.env.AGENTO_TEST_TLS_CERT, 'Supply local TLS fixture paths');
  certificate = readFileSync(process.env.AGENTO_TEST_TLS_CERT);
  const { createApp } = await import('../src/app.js');
  const database = await import('../src/db/database.js');
  db = database.db;
  database.initDatabase();
  const { setSecurityMode } = await import('../src/config.js');
  setSecurityMode('vulnerable'); // A caller must not be able to switch the defense off.
  server = createServer({ key: readFileSync(process.env.AGENTO_TEST_TLS_KEY), cert: certificate }, createApp());
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  port = address.port;
});
afterAll(async () => {
  if (server?.listening) await new Promise<void>(resolve => server.close(() => resolve()));
  db?.close();
});
type Reply = { status: number; headers: IncomingHttpHeaders; text: string; json: any };
async function exchange(path: string, options: { method?: string; body?: Record<string, string>; cookie?: string; origin?: string } = {}): Promise<Reply> {
  const data = options.body ? JSON.stringify(options.body) : undefined;
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { 'X-Security-Mode': 'vulnerable' };
    if (data) { headers['Content-Type'] = 'application/json'; headers['Content-Length'] = String(Buffer.byteLength(data)); }
    if (options.cookie) headers.Cookie = options.cookie;
    if (options.origin) headers.Origin = options.origin;
    const req = request({ hostname: '127.0.0.1', port, path, method: options.method ?? 'GET', headers, ca: certificate, agent: false }, res => {
      const chunks: Buffer[] = [];
      res.on('data', chunk => chunks.push(Buffer.from(chunk)));
      res.on('error', reject);
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        try { resolve({ status: res.statusCode!, headers: res.headers, text, json: res.headers['content-type']?.includes('application/json') ? JSON.parse(text) : null }); }
        catch (error) { reject(error); }
      });
    });
    req.on('error', reject);
    req.setTimeout(3000, () => req.destroy(new Error('Local test request timed out')));
    req.end(data);
  });
}
async function login(username: 'alice' | 'bob' | 'admin') {
  const reply = await exchange('/api/auth/login', { method: 'POST', body: { username, password: username + '123' } });
  assert.equal(reply.status, 200);
  const cookies = reply.headers['set-cookie'] ?? [];
  const cookie = cookies.map(value => value.split(';')[0]).join('; ');
  assert.ok(cookie.includes('agento_sid='), 'Login must issue a session');
  return { ...reply, cookies, cookie };
}
`;

const cases: Readonly<Record<string, string>> = {
  'CWE-1004': String.raw`
  it('security: all authentication cookies have HttpOnly', async () => {
    const reply = await login('alice');
    for (const name of ['auth_token', 'agento_sid']) {
      const cookie = reply.cookies.find(value => value.startsWith(name + '='));
      assert.ok(cookie && /;\s*HttpOnly(?:;|$)/i.test(cookie), name + ' needs HttpOnly');
    }
  });`,
  'CWE-614': String.raw`
  it('security: all authentication cookies have Secure over HTTPS', async () => {
    const reply = await login('alice');
    for (const name of ['auth_token', 'agento_sid']) {
      const cookie = reply.cookies.find(value => value.startsWith(name + '='));
      assert.ok(cookie && /;\s*Secure(?:;|$)/i.test(cookie), name + ' needs Secure');
    }
  });`,
  'CWE-942': String.raw`
  it('security: untrusted and null origins receive no credential grant', async () => {
    for (const origin of ['https://untrusted.invalid', 'null', 'http://localhost:3000.untrusted.invalid']) {
      const reply = await exchange('/api/products', { origin });
      assert.equal(reply.status, 200);
      assert.equal(reply.headers['access-control-allow-origin'], undefined);
      assert.equal(reply.headers['access-control-allow-credentials'], undefined);
    }
  });
  it('normal: trusted origin, preflight, and same-origin product requests still work', async () => {
    for (const origin of ['http://localhost:3000', 'http://127.0.0.1:3000']) {
      const reply = await exchange('/api/products', { origin });
      assert.equal(reply.headers['access-control-allow-origin'], origin);
      assert.equal(reply.headers['access-control-allow-credentials'], 'true');
      const preflight = await exchange('/api/products', { origin, method: 'OPTIONS' });
      assert.equal(preflight.status, 204);
      assert.equal(preflight.headers['access-control-allow-origin'], origin);
    }
    assert.equal((await exchange('/api/products')).status, 200);
  });`,
  'CWE-639': String.raw`
  it('security: a second customer cannot read the owner order', async () => {
    const bob = await login('bob');
    const reply = await exchange('/api/orders/101', { cookie: bob.cookie });
    assert.ok([403, 404].includes(reply.status));
    assert.equal(reply.json.order, undefined);
    assert.equal((await exchange('/api/orders/101')).status, 401);
  });
  it('normal: each owner and the administrator retain order access', async () => {
    for (const [username, id] of [['alice', 101], ['bob', 201], ['admin', 101]] as const) {
      const user = await login(username);
      const reply = await exchange('/api/orders/' + id, { cookie: user.cookie });
      assert.equal(reply.status, 200);
      assert.equal(reply.json.order.id, id);
    }
  });`,
  'CWE-862': String.raw`
  it('security: customers and anonymous callers cannot use administrative routes', async () => {
    for (const username of ['alice', 'bob'] as const) {
      const user = await login(username);
      for (const path of ['/api/admin/users', '/api/admin/stats']) {
        assert.equal((await exchange(path, { cookie: user.cookie })).status, 403);
        assert.equal((await exchange(path)).status, 401);
      }
    }
  });
  it('normal: administrator routes still return users and statistics', async () => {
    const user = await login('admin');
    const users = await exchange('/api/admin/users', { cookie: user.cookie });
    const stats = await exchange('/api/admin/stats', { cookie: user.cookie });
    assert.equal(users.status, 200);
    assert.ok(users.json.users.some((item: { username: string }) => item.username === 'alice'));
    assert.equal(stats.status, 200);
    assert.ok(stats.json.stats.totalUsers >= 3);
  });`,
  'CWE-79': String.raw`
  it('security: encode markup in the HTML text node', async () => {
    const value = '<img src=x onerror="alert(1)">';
    const reply = await exchange('/search?q=' + encodeURIComponent(value));
    assert.equal(reply.status, 200);
    assert.ok(!reply.text.includes('<span id="search-query-target">' + value));
    assert.ok(reply.text.includes('<span id="search-query-target">&lt;img src=x onerror=&quot;alert(1)&quot;&gt;</span>'));
  });
  it('normal: ordinary text and product search results still render', async () => {
    const reply = await exchange('/search?q=SecureKey');
    assert.equal(reply.status, 200);
    assert.ok(reply.text.includes('<span id="search-query-target">SecureKey</span>'));
    assert.ok(reply.text.includes('SecureKey YubiStick'));
  });`,
  'CWE-89': String.raw`
  it('security: SQL syntax remains a literal search value', async () => {
    for (const value of ["' OR 1=1 --", "' UNION SELECT id, username, password, role, email, full_name FROM users --", "O'Reilly"]) {
      const reply = await exchange('/api/search?q=' + encodeURIComponent(value));
      assert.equal(reply.status, 200);
      assert.deepEqual(reply.json.results, []);
      assert.equal(reply.json.rawExecutedQuery, undefined);
    }
  });
  it('normal: product search still returns matching products', async () => {
    const reply = await exchange('/api/search?q=SecureKey');
    assert.equal(reply.status, 200);
    assert.ok(reply.json.results.some((item: { name: string }) => item.name === 'SecureKey YubiStick'));
  });`,
};

export function regressionTest(cweId: string): string {
  const body = cases[cweId];
  if (!body) throw new RemediationError('unsupported-source');
  const session = ['CWE-614', 'CWE-1004'].includes(cweId) ? String.raw`
  it('normal: HTTPS login and session reuse still work', async () => {
    const user = await login('alice');
    const me = await exchange('/api/auth/me', { cookie: user.cookie });
    assert.equal(me.status, 200);
    assert.equal(me.json.authenticated, true);
    assert.equal(me.json.user.username, 'alice');
    assert.equal((await exchange('/api/products')).status, 200);
  });` : '';
  return `${harness}\ndescribe('${cweId} Express security regression', () => {${body}${session}\n});\n`;
}

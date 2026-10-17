import { createServer, type Server, type RequestListener } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AnalysisContext } from '@agento/core';
import { TesterArmyE2EAdapter, demoBrowserOptions, DEMO_IDENTITIES } from '@agento/tool-e2e-browser';
import { DeterministicRequestExecutor, NormalizedCookieAnalyzer, NormalizedHeaderAnalyzer,
  NormalizedResponseCollector, RuntimeAuthenticationManager, SessionCookieInspector, SessionNetworkObserver, WorkflowBrowserController } from '../src/index.js';

const suite = process.env.AGENTO_RUNTIME_INTEGRATION === '1' ? describe : describe.skip;
suite('live HTTP and Chromium runtime capabilities', () => {
  let server: Server, trap: Server, origin: string, trapOrigin: string, forbidden = 0;
  let appServer: Server, appOrigin: string, db: { close(): void };
  const oldDatabase = process.env.DB_PATH;
  beforeAll(async () => {
    trap = createServer((_request, response) => { forbidden++; response.end('outside scope'); });
    trapOrigin = await listen(trap);
    server = createServer((request, response) => {
      if (request.url === '/redirect') { response.writeHead(302, { Location: `${trapOrigin}/private` }); response.end(); return; }
      if (request.url === '/large') { response.end(Buffer.alloc(256_000, 42)); return; }
      if (request.url === '/slow') { response.writeHead(200); response.write('start'); setTimeout(() => response.end('finish'), 100); return; }
      if (request.url === '/broken') { response.writeHead(200, { 'Content-Length': '1000' }); response.write('incomplete'); response.destroy(); return; }
      response.setHeader('Set-Cookie', ['sid=private-cookie; Path=/; HttpOnly; SameSite=Lax', 'theme=dark; Expires=Wed, 09 Jun 2038 10:18:14 GMT']);
      response.setHeader('Access-Control-Allow-Origin', 'https://client.test');
      response.setHeader('Cache-Control', 'private, max-age=60');
      response.setHeader('X-Content-Type-Options', 'nosniff');
      const data: Buffer[] = []; request.on('data', chunk => data.push(chunk));
      request.on('end', () => response.end(Buffer.concat(data).length ? Buffer.concat(data) : Buffer.from([0, 255, 1, 2])));
    });
    origin = await listen(server);
    process.env.DB_PATH = ':memory:';
    const applicationPath = new URL('../../../demo-apps/demo-app-01/src/app.ts', import.meta.url).pathname;
    const databasePath = new URL('../../../demo-apps/demo-app-01/src/db/database.ts', import.meta.url).pathname;
    const demo: { createApp(): RequestListener } = await import(applicationPath);
    const database: { db: { close(): void }; initDatabase(): void } = await import(databasePath);
    db = database.db; database.initDatabase();
    const app = demo.createApp();
    appServer = createServer((request, response) => {
      if (request.url === '/runtime-http-cookie' || request.url === '/runtime-browser-cookie') {
        const name = request.url === '/runtime-http-cookie' ? 'http-transfer' : 'browser-transfer';
        response.setHeader('Set-Cookie', `${name}=private-transfer-value; HttpOnly; Path=/; SameSite=Lax`);
        response.end('<p id="cookie-ready">Done</p>'); return;
      }
      if (request.url === '/runtime-read-cookies') { response.end(request.headers.cookie ?? ''); return; }
      app(request, response);
    });
    appOrigin = await listen(appServer);
  }, 30_000);
  afterAll(async () => {
    await Promise.all([close(server), close(trap), close(appServer)]); db?.close();
    if (oldDatabase === undefined) delete process.env.DB_PATH; else process.env.DB_PATH = oldDatabase;
  });
  const client = (baseUrl: string, extra: Partial<ConstructorParameters<typeof DeterministicRequestExecutor>[0]> = {}) =>
    new DeterministicRequestExecutor({ baseUrl, allowedOrigins: [baseUrl], ...extra });
  it('collects live binary responses, repeated cookies, headers and timings without any scanner', async () => {
    const result = await client(origin).execute({ url: '/' });
    expect([...Buffer.from(result.body.data, 'base64')]).toEqual([0, 255, 1, 2]);
    expect(result.timings.durationMs).toBeGreaterThanOrEqual(result.timings.firstByteMs);
    expect(result.headers['set-cookie']).toHaveLength(2);
    const cookies = await new NormalizedCookieAnalyzer().analyze(result);
    expect(cookies[0]).toMatchObject({ name: 'sid', httpOnly: true, sameSite: 'Lax', value: '[REDACTED]' });
    expect((await new NormalizedHeaderAnalyzer().analyze(result)).cors.allowOrigin).toEqual(['https://client.test']);
    expect(JSON.stringify(new NormalizedResponseCollector().evidence(result))).not.toContain('private-cookie');
    const post = await client(origin).execute({ url: '/', method: 'POST', body: 'exact body' });
    expect(Buffer.from(post.body.data, 'base64').toString()).toBe('exact body');
  });
  it('returns redirects without contacting the forbidden origin and rejects explicit scope escape', async () => {
    const before = forbidden;
    expect((await client(origin).execute({ url: '/redirect' })).status).toBe(302);
    await expect(client(origin).execute({ url: trapOrigin })).rejects.toMatchObject({ code: 'scope-denied' });
    expect(forbidden).toBe(before);
  });
  it('bounds live bodies, times out during streaming and reports incomplete connections', async () => {
    const large = await client(origin, { maxBodyBytes: 32 }).execute({ url: '/large' });
    expect(large.body).toMatchObject({ byteLength: 32, truncated: true });
    await expect(client(origin, { timeoutMs: 25 }).execute({ url: '/slow' })).rejects.toMatchObject({ code: 'timeout' });
    await expect(client(origin).execute({ url: '/broken' })).rejects.toMatchObject({ code: 'transport-failed' });
  });
  it('authenticates Alice/Bob/Admin in Chromium and reuses each isolated cookie identity over HTTP', async () => {
    const context: AnalysisContext = { project: { id: 'runtime-live', name: 'Runtime', mode: 'black-box', baseUrl: appOrigin,
      allowedOrigins: [appOrigin], languages: [] }, identities: DEMO_IDENTITIES, components: [], endpoints: [], resources: [], signals: [], evidence: [] };
    const browser = new WorkflowBrowserController({ driver: new TesterArmyE2EAdapter(demoBrowserOptions()), context });
    const manager = new RuntimeAuthenticationManager({ browser, identities: DEMO_IDENTITIES, http: { baseUrl: appOrigin, allowedOrigins: [appOrigin] } });
    let stage = 'establish';
    try {
      for (const identity of DEMO_IDENTITIES) {
        stage = `establish ${identity.id}`;
        const session = await manager.establishSession(identity);
        stage = `http ${identity.id}`;
        const result = await session.http.execute({ url: '/api/auth/me' });
        expect(result.status).toBe(200);
        expect(JSON.parse(Buffer.from(result.body.data, 'base64').toString()).user.username).toBe(identity.id);
        const cookies = await new SessionCookieInspector().inspect(session);
        expect(cookies.some(cookie => cookie.name === 'agento_sid')).toBe(true);
        expect(cookies.every(cookie => cookie.value === '[REDACTED]')).toBe(true);
        await session.http.execute({ url: '/runtime-http-cookie' });
        stage = `reopen browser ${identity.id}`;
        await session.withBrowser(async page => {
          expect((await page.cookies()).some(cookie => cookie.name === 'http-transfer')).toBe(true);
          await page.perform({ action: 'navigate', url: '/runtime-browser-cookie' });
          stage = `navigate ${identity.id}`;
          await page.perform({ action: 'navigate', url: '/orders.html' });
          stage = `wait for orders ${identity.id}`;
          await page.perform({ action: 'wait-visible', selector: '#orders-table-body tr:first-child' });
        });
        const transferred = await session.http.execute({ url: '/runtime-read-cookies' });
        expect(Buffer.from(transferred.body.data, 'base64').toString()).toContain('browser-transfer=private-transfer-value');
        stage = `network ${identity.id}`;
        const network = await new SessionNetworkObserver().observe(session);
        expect(network.some(item => item.source === 'browser' && item.url === `${appOrigin}/api/orders` && item.status === 200)).toBe(true);
        expect(network.some(item => item.source === 'http' && item.url === `${appOrigin}/api/auth/me`)).toBe(true);
        expect(JSON.stringify({ cookies, network })).not.toMatch(/sess_alice|sess_bob|sess_admin|alice123|bob123|admin123/);
      }
    } catch (error) { throw new Error(stage, { cause: error }); } finally { await manager.close(); }
  }, 90_000);
  it('fails a real rejected login without returning a usable session', async () => {
    const context: AnalysisContext = { project: { id: 'bad-runtime-live', name: 'Runtime', mode: 'black-box', baseUrl: appOrigin,
      allowedOrigins: [appOrigin], languages: [] }, identities: DEMO_IDENTITIES, components: [], endpoints: [], resources: [], signals: [], evidence: [] };
    const driver = new TesterArmyE2EAdapter({ ...demoBrowserOptions(), credentials: async () => ({ username: 'alice', password: 'private-wrong-password' }) });
    const manager = new RuntimeAuthenticationManager({ browser: new WorkflowBrowserController({ driver, context }),
      identities: DEMO_IDENTITIES, http: { baseUrl: appOrigin, allowedOrigins: [appOrigin] } });
    try { await expect(manager.establishSession(DEMO_IDENTITIES[0]!)).rejects.toMatchObject({ code: 'authentication-failed' }); }
    finally { await manager.close(); }
  }, 30_000);
});
async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}
async function close(server?: Server): Promise<void> {
  if (server) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
}

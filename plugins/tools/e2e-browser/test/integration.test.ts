import { createServer, type RequestListener, type Server } from 'node:http';
import { mkdtemp, rm, lstat, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AnalysisContext } from '@agento/core';
import { TesterArmyE2EAdapter, DEMO_IDENTITIES, demoBrowserOptions, FileSessionStore } from '../src/index.js';
import { anonymous } from './helpers.js';

const suite = process.env.AGENTO_BROWSER_INTEGRATION === '1' ? describe : describe.skip;
type DemoApplication = RequestListener & {
  get(path: string, handler: (request: unknown, response: { redirect(url: string): void; send(body: string): void }) => unknown): void;
};
suite('real e2e / Chromium workflows against the local storefront', () => {
  let server: Server, trap: Server, origin: string, trapOrigin: string, files: string;
  let forbiddenRequests = 0;
  let database: { close(): void };
  let context: AnalysisContext;
  const previousDbPath = process.env.DB_PATH;
  beforeAll(async () => {
    process.env.DB_PATH = ':memory:';
    // Import the real controlled target only for this opt-in local integration suite.
    const appPath = new URL('../../../../demo-apps/demo-app-01/src/app.ts', import.meta.url).pathname;
    const dbPath = new URL('../../../../demo-apps/demo-app-01/src/db/database.ts', import.meta.url).pathname;
    const demo: { createApp(): DemoApplication } = await import(appPath);
    const db: { db: { close(): void }; initDatabase(): void } = await import(dbPath);
    database = db.db; db.initDatabase();
    const app = demo.createApp();
    trap = createServer((_request, response) => { forbiddenRequests++; response.end('outside scope'); });
    trapOrigin = await listen(trap);
    app.get('/scope/redirect', (_request, response) => response.redirect(`${trapOrigin}/redirected?token=private`));
    app.get('/scope/chain', (_request, response) => response.redirect('/scope/redirect'));
    app.get('/scope/popup-chain', (_request, response) => response.send('<body><script>window.open("/scope/chain"); setTimeout(() => document.body.dataset.done = "true", 300)</script></body>'));
    app.get('/scope/frame-chain', (_request, response) => response.send('<body><iframe src="/scope/chain"></iframe><script>setTimeout(() => document.body.dataset.done = "true", 300)</script></body>'));
    app.get('/scope/inside', (_request, response) => response.redirect('/scope/done'));
    app.get('/scope/done', (_request, response) => response.send('<p id="done">Done</p>'));
    for (const [path, script] of [
      ['fetch', `fetch('${trapOrigin}/fetch').catch(() => {}).finally(() => document.body.dataset.done = 'true')`],
      ['popup', `window.open('${trapOrigin}/popup'); setTimeout(() => document.body.dataset.done = 'true', 200)`],
      ['frame', `const frame = document.createElement('iframe'); frame.src = '${trapOrigin}/frame'; document.body.append(frame); setTimeout(() => document.body.dataset.done = 'true', 200)`],
      ['navigation', `location.href = '${trapOrigin}/navigation'`],
      ['websocket', `const socket = new WebSocket('${trapOrigin.replace('http:', 'ws:')}/socket'); socket.onerror = () => document.body.dataset.done = 'true'; socket.onclose = () => document.body.dataset.done = 'true'`],
    ]) app.get(`/scope/${path}`, (_request, response) => response.send(`<body><script>${script}</script></body>`));
    server = createServer(app); origin = await listen(server);
    files = await mkdtemp(join(tmpdir(), 'agento-browser-live-'));
    context = { project: { id: 'demo-live', name: 'Demo', mode: 'black-box', baseUrl: origin, allowedOrigins: [origin], languages: [] },
      components: [], endpoints: [], identities: [...DEMO_IDENTITIES, anonymous], resources: [], signals: [], evidence: [] };
  }, 30_000);
  afterAll(async () => {
    await Promise.all([close(server), close(trap)]);
    database?.close(); if (files) await rm(files, { recursive: true, force: true });
    if (previousDbPath === undefined) delete process.env.DB_PATH; else process.env.DB_PATH = previousDbPath;
  });

  it('logs in as Alice, Bob, and Admin, opens the newest order and records the actual UI API call', async () => {
    const adapter = new TesterArmyE2EAdapter(demoBrowserOptions());
    for (const [identityId, order] of [['alice', '102'], ['bob', '201'], ['admin', '301']]) {
      const result = await adapter.observe(context, { id: identityId!, identityId: identityId!, goal: 'open newest order' });
      expect(result.diagnostics).toEqual([]); expect(result.outcome).toBe('COMPLETED');
      expect(result.evidence.some(item => item.kind === 'http-response' && item.facts.url === `${origin}/api/orders/${order}` && item.facts.status === 200)).toBe(true);
      expect(result.evidence.find(item => item.kind === 'browser-observation')?.facts.url).toBe(`${origin}/orders.html`);
      expect(result.endpoints.some(endpoint => endpoint.path === `/api/orders/${order}`)).toBe(true);
      expect(JSON.stringify(result)).not.toMatch(/alice123|bob123|admin123|sess_alice|sess_bob|sess_admin|sessionToken|Set-Cookie/);
    }
    const reused = await adapter.observe(context, { id: 'alice-again', identityId: 'alice', goal: 'Login as Alice and open her newest order.' });
    expect(reused.outcome).toBe('COMPLETED');
    expect(reused.evidence.find(item => item.kind === 'identity-session')?.facts.reused).toBe(true);
    expect(reused.evidence.some(item => item.facts.url === `${origin}/api/auth/login`)).toBe(false);
  }, 60_000);

  it('restores a saved authentication state in a new adapter instance and captures an opt-in masked screenshot', async () => {
    const options = { ...demoBrowserOptions(), sessionStore: new FileSessionStore(join(files, 'sessions')) };
    const first = await new TesterArmyE2EAdapter(options).observe(context, { id: 'first', identityId: 'alice', goal: 'open newest order' });
    expect(first.outcome).toBe('COMPLETED');
    const result = await new TesterArmyE2EAdapter({ ...options, screenshot: { directory: join(files, 'screenshots'), maskSelectors: ['#cookie-status-display'] } })
      .observe(context, { id: 'saved', identityId: 'alice', goal: 'open newest order' });
    expect(result.outcome).toBe('COMPLETED');
    expect(result.evidence.find(item => item.kind === 'identity-session')?.facts.reused).toBe(true);
    const artifact = result.evidence.find(item => item.kind === 'screenshot')?.artifactRef;
    expect(artifact).toBeTruthy(); expect((await lstat(artifact!)).size).toBeGreaterThan(1000);
    expect((await lstat(artifact!)).mode & 0o777).toBe(0o600);
  }, 30_000);

  it('rejects a real failed login promptly and never runs the order goal', async () => {
    const result = await new TesterArmyE2EAdapter({ ...demoBrowserOptions(),
      credentials: async () => ({ username: 'alice', password: 'incorrect-private-password' }),
    }).observe(context, { id: 'bad-login', identityId: 'alice', goal: 'open newest order' });
    expect(result.outcome).toBe('FAILED');
    expect(result.diagnostics[0]?.code).toBe('authentication-failed');
    expect(result.evidence.some(item => item.facts.status === 401 && item.facts.url === `${origin}/api/auth/login`)).toBe(true);
    expect(result.evidence.some(item => item.facts.url === `${origin}/api/orders`)).toBe(false);
    expect(JSON.stringify(result)).not.toContain('incorrect-private-password');
  }, 20_000);

  it('re-authenticates a genuinely invalid saved cookie in a fresh browser context', async () => {
    const { MemorySessionStore } = await import('../src/index.js');
    const { BrowserScope } = await import('../src/policy.js');
    const store = new MemorySessionStore();
    const binding = new BrowserScope(context.project).binding(context.project, DEMO_IDENTITIES[0]!);
    await store.save({ binding, sessionRef: 'stale', expiresAt: Date.now() + 60_000,
      state: { format: 'playwright-storage-state', version: 1, data: { cookies: [{ name: 'agento_sid', value: 'invalid-private-cookie',
        domain: '127.0.0.1', path: '/', expires: -1, httpOnly: false, secure: false, sameSite: 'Lax' }], origins: [] } } });
    const result = await new TesterArmyE2EAdapter({ ...demoBrowserOptions(), sessionStore: store })
      .observe(context, { id: 'stale', identityId: 'alice', goal: 'open newest order' });
    expect(result.outcome).toBe('COMPLETED');
    expect(result.evidence.find(item => item.kind === 'identity-session')?.facts.reused).toBe(false);
    expect(result.evidence.some(item => item.facts.url === `${origin}/api/auth/login` && item.facts.status === 200)).toBe(true);
    expect(JSON.stringify(result)).not.toContain('invalid-private-cookie');
  }, 20_000);

  it('allows an in-scope redirect and records both response statuses', async () => {
    const result = await new TesterArmyE2EAdapter({ resolveGoal: () => [
      { action: 'navigate', url: '/scope/inside' }, { action: 'wait-visible', selector: '#done' },
    ] }).observe(context, { id: 'inside', identityId: 'anonymous', goal: 'inside' });
    expect(result.outcome).toBe('COMPLETED');
    expect(result.evidence.some(item => item.kind === 'http-response' && item.facts.status === 302)).toBe(true);
    expect(result.evidence.some(item => item.facts.url === `${origin}/scope/done` && item.facts.status === 200)).toBe(true);
  }, 20_000);

  it('runs the built standalone CLI and emits only normalized JSON', async () => {
    const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
    const outputFile = join(files, 'cli-observation.json');
    const { stdout } = await promisify(execFile)(process.execPath, [cli, '--url', origin, '--allow-origin', origin,
      '--identity', 'alice', '--goal', 'open newest order', '--output', outputFile], { timeout: 20_000, maxBuffer: 2_097_152 });
    const result = JSON.parse(stdout);
    expect(result.outcome).toBe('COMPLETED');
    expect(result.evidence.some((item: { facts: { url?: string; status?: number } }) => item.facts.url === `${origin}/api/orders/102` && item.facts.status === 200)).toBe(true);
    expect(stdout).not.toMatch(/alice123|sess_alice|sessionToken/);
    const saved = JSON.parse(await readFile(outputFile, 'utf8'));
    expect(saved.outcome).toBe('COMPLETED');
    expect(saved.evidence).toHaveLength(result.evidence.length);
  }, 25_000);

  for (const path of ['redirect', 'chain', 'popup-chain', 'frame-chain', 'fetch', 'popup', 'frame', 'navigation', 'websocket']) {
    it(`blocks outside-scope ${path} traffic before it reaches the forbidden server`, async () => {
      const before = forbiddenRequests;
      const result = await new TesterArmyE2EAdapter({ timeoutMs: 5000, resolveGoal: () => ['redirect', 'chain', 'navigation'].includes(path)
        ? [{ action: 'navigate', url: `/scope/${path}` }]
        : [{ action: 'navigate', url: `/scope/${path}` }, { action: 'wait-visible', selector: 'body[data-done=true]' }],
      }).observe(context, { id: path, identityId: 'anonymous', goal: path });
      expect(result.outcome).toBe('FAILED');
      expect(result.diagnostics.some(item => item.code === 'scope-denied')).toBe(true);
      expect(result.evidence.some(item => item.facts.blocked === true)).toBe(true);
      expect(forbiddenRequests).toBe(before);
    }, 15_000);
  }
});

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}
async function close(server?: Server): Promise<void> {
  if (server) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
}

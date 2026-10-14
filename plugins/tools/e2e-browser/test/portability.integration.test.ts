import { createServer, type RequestListener, type Server } from 'node:http';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { AddressInfo } from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AnalysisContext, TargetApplicationProfile } from '@agento/core';
import { TesterArmyE2EAdapter, storefrontBrowserOptions, purchasesBrowserOptions, FileSessionStore, MemorySessionStore } from '../src/index.js';
import { anonymous } from './helpers.js';

const suite = process.env.AGENTO_BROWSER_INTEGRATION === '1' ? describe : describe.skip;
suite('cross-project e2e / Chromium portability', () => {
  let storefront: Server, purchases: Server, trap: Server, shopOrigin: string, purchaseOrigin: string, trapOrigin: string, directory: string;
  let db: { close(): void };
  let counters: { logins: number };
  let forbiddenRequests = 0;
  const oldDbPath = process.env.DB_PATH;
  const shopContext = (): AnalysisContext => contextFor(shopOrigin, storefrontBrowserOptions([shopOrigin]).target!);
  const purchaseContext = (): AnalysisContext => contextFor(purchaseOrigin, purchasesBrowserOptions([purchaseOrigin]).target!);
  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'agento-portability-'));
    trap = createServer((_request, response) => { forbiddenRequests++; response.end('outside scope'); });
    trapOrigin = await listen(trap);
    const fixture: { createPurchasesFixture(options: { forbiddenOrigin: string }): { server: Server; counters: typeof counters } }
      = await import(new URL('./fixtures/purchases.mjs', import.meta.url).pathname);
    const second = fixture.createPurchasesFixture({ forbiddenOrigin: trapOrigin });
    purchases = second.server; counters = second.counters;
    purchaseOrigin = await listen(purchases);
    process.env.DB_PATH = ':memory:';
    const demo: { createApp(): RequestListener } = await import(new URL('../../../../demo-apps/demo-app-01/src/app.ts', import.meta.url).pathname);
    const database: { db: typeof db; initDatabase(): void } = await import(new URL('../../../../demo-apps/demo-app-01/src/db/database.ts', import.meta.url).pathname);
    db = database.db; database.initDatabase();
    storefront = createServer(demo.createApp()); shopOrigin = await listen(storefront);
  });
  afterAll(async () => {
    const received = forbiddenRequests;
    await Promise.all([storefront, purchases, trap].filter(Boolean).map(close));
    db?.close();
    if (directory) await rm(directory, { recursive: true, force: true });
    if (oldDbPath === undefined) delete process.env.DB_PATH; else process.env.DB_PATH = oldDbPath;
    expect(received).toBe(0);
  });

  for (const [shopPersona, purchasePersona, shopKey, purchaseKey] of [
    ['alice', 'buyer-one', '102', 'BUY-302'], ['bob', 'buyer-two', '201', 'BUY-711'], ['admin', 'manager', '301', 'MGR-900'],
  ] as const) it(`runs the same high-level goal for ${shopPersona} and ${purchasePersona} with the same adapter class`, async () => {
    const first = await new TesterArmyE2EAdapter(storefrontBrowserOptions([shopOrigin])).observe(shopContext(),
      { id: 'equivalent-goal', identityId: shopPersona, goal: 'open newest order' });
    const second = await new TesterArmyE2EAdapter(purchasesBrowserOptions([purchaseOrigin])).observe(purchaseContext(),
      { id: 'equivalent-goal', identityId: purchasePersona, goal: 'open newest order' });
    expect(first.diagnostics).toEqual([]); expect(second.diagnostics).toEqual([]);
    expect(first.outcome).toBe('COMPLETED'); expect(second.outcome).toBe('COMPLETED');
    const shopApi = first.evidence.find(item => item.kind === 'http-response' && item.facts.url === `${shopOrigin}/api/orders/${shopKey}`)!;
    const purchaseApi = second.evidence.find(item => item.kind === 'http-response' && item.facts.url === `${purchaseOrigin}/api/v1/purchases/${purchaseKey}`)!;
    expect(shopApi.facts.status).toBe(200); expect(purchaseApi.facts.status).toBe(200);
    expect(Object.keys(shopApi).sort()).toEqual(Object.keys(purchaseApi).sort());
    expect(Object.keys(shopApi.facts).sort()).toEqual(Object.keys(purchaseApi.facts).sort());
    expect(purchaseApi.facts).toMatchObject({ origin: purchaseOrigin, personaId: purchasePersona, headers: { 'content-type': 'application/json', 'x-content-type-options': 'nosniff' } });
    expect(second.endpoints.some(endpoint => endpoint.path === `/api/v1/purchases/${purchaseKey}`)).toBe(true);
    expect(first.signals).toEqual([]); expect(second.signals).toEqual([]);
    expect(second.evidence.every(item => item.identityId === purchasePersona && item.producerId === 'tester-army-e2e-adapter')).toBe(true);
    expect(Object.isFrozen(second.evidence[0]!.facts)).toBe(true);
    expect(JSON.stringify(second)).not.toMatch(/BuyerOne!42|BuyerTwo!42|Manager!42|purchase-session|eyJhbGci/);
  }, 30_000);

  it('restores cookie and JWT-backed SPA sessions in fresh adapters and isolates target plus persona in one private file store', async () => {
    const sessionStore = new FileSessionStore(join(directory, 'sessions'));
    for (const [origin, options, ctx, ids] of [
      [shopOrigin, storefrontBrowserOptions([shopOrigin]), shopContext(), ['alice', 'bob']],
      [purchaseOrigin, purchasesBrowserOptions([purchaseOrigin]), purchaseContext(), ['buyer-one', 'buyer-two']],
    ] as const) {
      for (const identityId of ids) {
        const initial = await new TesterArmyE2EAdapter({ ...options, sessionStore }).observe(ctx, { id: origin, identityId, goal: 'open newest order' });
        expect(initial.outcome).toBe('COMPLETED');
        expect(initial.evidence.find(item => item.kind === 'identity-session')?.facts.reused).toBe(false);
      }
      for (const identityId of ids) {
        const reused = await new TesterArmyE2EAdapter({ ...options, sessionStore,
          credentials: async () => { throw new Error('Cached credentials should suffice'); } }).observe(ctx, { id: origin, identityId, goal: 'open newest order' });
        expect(reused.diagnostics).toEqual([]); expect(reused.outcome).toBe('COMPLETED');
        expect(reused.evidence.find(item => item.kind === 'identity-session')?.facts.reused).toBe(true);
      }
    }
    expect(await readdir(join(directory, 'sessions'))).toHaveLength(4);
    const before = counters.logins;
    const separate = await new TesterArmyE2EAdapter({ ...purchasesBrowserOptions([purchaseOrigin], 'separate-target'), sessionStore })
      .observe(purchaseContext(), { id: 'target-isolation', identityId: 'buyer-one', goal: 'open newest order' });
    expect(separate.outcome).toBe('COMPLETED');
    expect(separate.evidence.find(item => item.kind === 'identity-session')?.facts.reused).toBe(false);
    expect(counters.logins).toBe(before + 1);
    expect(await readdir(join(directory, 'sessions'))).toHaveLength(5);
  }, 60_000);

  it('recovers a stale JWT in a fresh browser and refuses invalid target credentials', async () => {
    const sessionStore = new MemorySessionStore();
    const options = purchasesBrowserOptions([purchaseOrigin]);
    const ctx = purchaseContext(), goal = { id: 'recover', identityId: 'buyer-one', goal: 'open newest order' };
    const captured: string[] = [];
    const save = sessionStore.save.bind(sessionStore);
    sessionStore.save = async session => { captured.push(session.binding); await save(session); };
    expect((await new TesterArmyE2EAdapter({ ...options, sessionStore }).observe(ctx, goal)).outcome).toBe('COMPLETED');
    const cached = (await sessionStore.load(captured[0]!))!;
    const data = cached.state.data as { cookies: unknown[]; origins: { origin: string; localStorage: { name: string; value: string }[] }[] };
    await sessionStore.save({ ...cached, state: { ...cached.state, data: { ...data,
      origins: data.origins.map(entry => ({ ...entry, localStorage: entry.localStorage.map(item => ({ ...item, value: 'invalid-jwt' })) })) } } });
    const recovered = await new TesterArmyE2EAdapter({ ...options, sessionStore }).observe(ctx, goal);
    expect(recovered.outcome).toBe('COMPLETED');
    expect(recovered.evidence.find(item => item.kind === 'identity-session')?.facts.reused).toBe(false);
    const invalid = await new TesterArmyE2EAdapter({ ...options, credentials: async () => ({ username: 'buyer.one', password: 'wrong' }) }).observe(ctx, goal);
    expect(invalid.outcome).toBe('FAILED'); expect(invalid.diagnostics[0]?.code).toBe('authentication-failed');
  }, 40_000);

  it('runs the second configured fixture through the built CLI', async () => {
    const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
    const { stdout } = await promisify(execFile)(process.execPath, [cli, '--target', 'purchases', '--url', purchaseOrigin,
      '--allow-origin', purchaseOrigin, '--identity', 'buyer-two', '--goal', 'open newest order'], { timeout: 20_000, maxBuffer: 2_097_152 });
    const result = JSON.parse(stdout);
    expect(result.outcome).toBe('COMPLETED');
    expect(result.evidence.some((item: { facts: { url?: string; status?: number } }) => item.facts.url === `${purchaseOrigin}/api/v1/purchases/BUY-711` && item.facts.status === 200)).toBe(true);
    expect(stdout).not.toMatch(/BuyerTwo!42|eyJhbGci/);
  }, 25_000);

  it('refuses identity and role mismatches even after a successful login', async () => {
    const options = purchasesBrowserOptions([purchaseOrigin]);
    const authentication = options.target!.authentication![0]!;
    for (const expectedIdentity of ['another-persona', 'buyer-one']) {
      const profile = { ...options.target!, authentication: [{ id: authentication.id, prepare: (persona: import('@agento/core').Persona) => {
        const prepared = authentication.prepare(persona);
        return { ...prepared, verification: { url: '/workspace', identitySelector: '[data-account]', expectedIdentity,
          role: { selector: '[data-role]', expected: 'owner' } } };
      } }] };
      const result = await new TesterArmyE2EAdapter({ ...options, target: profile }).observe(purchaseContext(),
        { id: 'wrong-verification', identityId: 'buyer-one', goal: 'open newest order' });
      expect(result.outcome).toBe('FAILED'); expect(result.diagnostics[0]?.code).toBe('authentication-failed');
      expect(result.evidence.some(item => item.facts.url === `${purchaseOrigin}/api/v1/purchases`)).toBe(false);
    }
  }, 20_000);

  it('retains structured plans and submits a standard HTML form in the real browser', async () => {
    const result = await new TesterArmyE2EAdapter({ target: { id: 'form-plan', baseOrigins: [purchaseOrigin], personas: [anonymous] } })
      .execute({ ...purchaseContext(), identities: [anonymous] }, { id: 'structured', hypothesisId: 'fixture', cweId: 'CWE-639',
        executor: 'browser', targetUrl: purchaseOrigin, identityIds: [anonymous.id], risk: 'passive', requiredCapabilities: ['browser-workflow'], steps: [
          { id: 'visit', action: 'navigate', parameters: { url: '/sign-in' }, expectedObservation: 'Form visible' },
          { id: 'handle', action: 'fill', parameters: { selector: '[name=handle]', value: 'buyer.one' }, expectedObservation: 'Handle entered' },
          { id: 'passphrase', action: 'fill', parameters: { selector: '[name=passphrase]', value: 'BuyerOne!42' }, expectedObservation: 'Passphrase entered' },
          { id: 'submit', action: 'submit', parameters: { selector: 'form[data-auth]', response: { url: '/api/v1/session', method: 'POST', status: 200 } }, expectedObservation: 'Successful form submission' },
          { id: 'destination', action: 'wait-url', parameters: { url: '/workspace' }, expectedObservation: 'Workspace loaded' },
          { id: 'identity', action: 'wait-visible', parameters: { selector: '[data-account]' }, expectedObservation: 'Account label rendered' },
        ] });
    expect(result.outcome).toBe('COMPLETED');
    expect(result.evidence.some(item => item.facts.url === `${purchaseOrigin}/api/v1/session` && item.facts.status === 200)).toBe(true);
    expect(JSON.stringify(result)).not.toMatch(/BuyerOne!42|eyJhbGci/);
  }, 20_000);

  for (const path of ['chain', 'fetch', 'popup', 'frame', 'worker', 'websocket']) it(`enforces the second target's scope for ${path}`, async () => {
    const ctx = { ...purchaseContext(), identities: [anonymous] };
    const target = { id: 'purchase-scope', baseOrigins: [purchaseOrigin], personas: [anonymous] };
    const result = await new TesterArmyE2EAdapter({ target, timeoutMs: 4000, resolveGoal: () => [
      { action: 'navigate', url: `/escape/${path}` },
      ...(path === 'chain' ? [] : [{ action: 'wait-visible' as const, selector: 'body[data-done=true]' }]),
    ] }).observe(ctx, { id: path, identityId: anonymous.id, goal: 'scope fixture' });
    expect(result.outcome).toBe('FAILED');
    expect(result.diagnostics.map(item => item.code)).toContain('scope-denied');
    expect(forbiddenRequests).toBe(0);
  }, 10_000);

  it('blocks service worker installation in the second target', async () => {
    const ctx = { ...purchaseContext(), identities: [anonymous] };
    const result = await new TesterArmyE2EAdapter({ target: { id: 'sw-scope', baseOrigins: [purchaseOrigin], personas: [anonymous] },
      resolveGoal: () => [{ action: 'navigate', url: '/escape/service-worker' }, { action: 'wait-visible', selector: 'body[data-done=true]' }],
    }).observe(ctx, { id: 'sw', identityId: anonymous.id, goal: 'service worker fixture' });
    expect(result.outcome).toBe('COMPLETED');
    expect(result.evidence.some(item => item.facts.url === `${purchaseOrigin}/sw.js`)).toBe(false);
    expect(forbiddenRequests).toBe(0);
  }, 10_000);

  it('refuses the other target origin as a direct action before browser launch', async () => {
    const ctx = { ...purchaseContext(), identities: [anonymous], project: { ...purchaseContext().project, allowedOrigins: [purchaseOrigin, shopOrigin] } };
    const result = await new TesterArmyE2EAdapter({ target: { id: 'restricted-purchase', baseOrigins: [purchaseOrigin], personas: [anonymous] },
      resolveGoal: () => [{ action: 'navigate', url: shopOrigin }],
    }).observe(ctx, { id: 'direct', identityId: anonymous.id, goal: 'scope fixture' });
    expect(result.outcome).toBe('SKIPPED'); expect(result.diagnostics[0]?.code).toBe('scope-denied');
  });
});

function contextFor(origin: string, target: TargetApplicationProfile): AnalysisContext {
  return { project: { id: 'shared-project', name: 'Portability fixture', mode: 'black-box', baseUrl: origin, allowedOrigins: [origin], languages: [] },
    identities: target.personas ?? [], components: [], endpoints: [], resources: [], signals: [], evidence: [] };
}
async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}
async function close(server: Server): Promise<void> {
  server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
}

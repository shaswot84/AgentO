import { createServer, type RequestListener, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AnalysisContext } from '@agento/core';
import { DEMO_IDENTITIES, demoBrowserOptions, TesterArmyE2EAdapter } from '@agento/tool-e2e-browser';
import {
  AuthorizationProbe, CapabilityRegistry, CookieSecurityProbe, CrossOriginProbe, DeterministicRequestExecutor,
  NormalizedCookieAnalyzer, NormalizedHeaderAnalyzer, NormalizedResponseCollector, NormalizedResponseComparator,
  RuntimeAuthenticationManager, SessionCookieInspector, SQLInjectionProbe, WorkflowBrowserController, XSSProbe,
} from '../src/index.js';

const suite = process.env.AGENTO_RUNTIME_INTEGRATION === '1' ? describe : describe.skip;
suite('reusable probes against the real storefront and Chromium', () => {
  let server: Server, origin: string, database: { close(): void }, setMode: (mode: 'vulnerable' | 'fixed') => void;
  const oldDatabase = process.env.DB_PATH;
  beforeAll(async () => {
    process.env.DB_PATH = ':memory:';
    const appPath = new URL('../../../demo-apps/demo-app-01/src/app.ts', import.meta.url).pathname;
    const dbPath = new URL('../../../demo-apps/demo-app-01/src/db/database.ts', import.meta.url).pathname;
    const configPath = new URL('../../../demo-apps/demo-app-01/src/config.ts', import.meta.url).pathname;
    const app: { createApp(): RequestListener } = await import(appPath);
    const db: { db: { close(): void }; initDatabase(): void } = await import(dbPath);
    const config: { setSecurityMode: typeof setMode } = await import(configPath);
    database = db.db; db.initDatabase(); setMode = config.setSecurityMode;
    server = createServer(app.createApp());
    await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    if (server) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
    database?.close();
    if (oldDatabase === undefined) delete process.env.DB_PATH; else process.env.DB_PATH = oldDatabase;
  });
  it.each(['vulnerable', 'fixed'] as const)('collects all five evidence families in %s mode', async mode => {
    setMode(mode);
    const context: AnalysisContext = { project: { id: `probes-${mode}`, name: 'Probe integration', mode: 'black-box',
      baseUrl: origin, allowedOrigins: [origin], languages: [] }, identities: DEMO_IDENTITIES,
      components: [], endpoints: [], resources: [], signals: [], evidence: [] };
    const browser = new WorkflowBrowserController({ driver: new TesterArmyE2EAdapter(demoBrowserOptions()), context });
    const manager = new RuntimeAuthenticationManager({ browser, identities: DEMO_IDENTITIES,
      http: { baseUrl: origin, allowedOrigins: [origin] } });
    const capabilities = new CapabilityRegistry()
      .register('request-executor', new DeterministicRequestExecutor({ baseUrl: origin, allowedOrigins: [origin] }))
      .register('response-collector', new NormalizedResponseCollector()).register('header-analyzer', new NormalizedHeaderAnalyzer())
      .register('cookie-analyzer', new NormalizedCookieAnalyzer()).register('response-comparator', new NormalizedResponseComparator())
      .register('authentication-manager', manager).register('cookie-inspector', new SessionCookieInspector())
      .register('browser-controller', browser);
    const common = { project: context.project, capabilities };
    try {
      const cookies = await new CookieSecurityProbe().execute({ ...common, request: { url: '/' }, identities: [DEMO_IDENTITIES[0]!] });
      const sessionCookie = cookies.observations[1]!.cookies.find(cookie => cookie.name === 'auth_token');
      expect(sessionCookie).toMatchObject({ httpOnly: mode === 'fixed', value: '[REDACTED]', secure: mode === 'fixed' });
      const cors = await new CrossOriginProbe().execute({ ...common, request: { url: '/api/auth/me' },
        identity: DEMO_IDENTITIES[0]!, origins: ['null', 'https://unapproved.invalid'] });
      expect(cors.observations[1]!.actual.cors.allowOrigin).toEqual(mode === 'fixed' ? ['null'] : ['https://unapproved.invalid']);
      const authorization = await new AuthorizationProbe().execute({ ...common, owner: DEMO_IDENTITIES[0]!, attacker: DEMO_IDENTITIES[1]!,
        discoverResource: async owner => {
          await owner.withBrowser(async page => {
            await page.perform({ action: 'navigate', url: '/orders.html' });
            await page.perform({ action: 'wait-visible', selector: '#orders-table-body tr:first-child' });
          });
          const response = await owner.http.execute({ url: '/api/orders' });
          const order = JSON.parse(Buffer.from(response.body.data, 'base64').toString())[0];
          expect(order.user_id).toBe(1);
          return { id: `order-${order.id}`, ownerIdentityId: owner.identityId, request: { url: `/api/orders/${order.id}` },
            ownerMarkers: [order.shipping_address] };
        } });
      expect(authorization.owner.status).toBe(200); expect(authorization.anonymous.status).toBe(401);
      expect(authorization.attacker.status).toBe(mode === 'fixed' ? 403 : 200);
      expect(authorization.attackerComparison.ownerMarkersMatch).toBe(mode === 'vulnerable');
      const xss = await new XSSProbe().execute({ ...common, request: { url: '/search?q=laptop' },
        identity: DEMO_IDENTITIES[0]!, parameter: { name: 'q', location: 'query' } });
      expect(xss.literalReflection).toBe(mode === 'vulnerable'); expect(xss.browser?.canaryVisible).toBe(true);
      expect(xss.executionConfirmed).toBeNull();
      const sql = await new SQLInjectionProbe().execute({ ...common, request: { url: '/api/search?q=Laptop' }, parameter: { name: 'q', location: 'query' } });
      expect(sql.observations[0]!.response.status).toBe(mode === 'fixed' ? 200 : 500);
      expect(sql.observations[0]!.errorIndicators.length > 0).toBe(mode === 'vulnerable');
      expect(sql.scanner).toBeNull();
      const serialized = JSON.stringify({ cookies, cors, authorization, xss, sql });
      expect(serialized).not.toMatch(/alice123|bob123|sess_alice|sess_bob|rawExecutedQuery|shipping_address/);
      for (const evidence of [cookies, cors, authorization, xss, sql]) expect(Object.isFrozen(evidence)).toBe(true);
    } finally { await manager.close(); }
  }, 120_000);
});

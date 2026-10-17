import { describe, expect, it, vi } from 'vitest';
import type { BrowserSession, TransportRequest } from '../src/index.js';
import { RuntimeAuthenticationManager, SessionCookieInspector, SessionNetworkObserver, WorkflowBrowserController } from '../src/index.js';
import { context, fakeDriver, identities, origin, raw } from './helpers.js';

function setup(overrides: Partial<ConstructorParameters<typeof RuntimeAuthenticationManager>[0]> = {}) {
  const fake = fakeDriver();
  const browser = new WorkflowBrowserController({ driver: fake.driver, context });
  const send = vi.fn(async (_request: TransportRequest) => raw());
  const manager = new RuntimeAuthenticationManager({ browser, identities, http: { baseUrl: origin, allowedOrigins: [origin], transport: { send } }, ...overrides });
  return { ...fake, browser, send, manager };
}
describe('browser runtime and authentication sessions', () => {
  it('runs guarded actions, exposes immutable observations and revokes escaped handles', async () => {
    const { browser, perform } = setup(); let escaped: BrowserSession | undefined;
    await browser.withSession(identities[0]!, async session => {
      escaped = session; await session.perform({ action: 'navigate', url: '/account' });
      const cookies = await new SessionCookieInspector().inspect(session);
      expect(cookies[0]).toMatchObject({ name: 'sid', value: '[REDACTED]', source: 'browser' });
      expect(Object.isFrozen(cookies[0])).toBe(true);
      expect(JSON.stringify(await new SessionNetworkObserver().observe(session))).not.toContain('private-alice');
    });
    expect(perform).toHaveBeenCalledOnce();
    await expect(escaped!.inspect()).rejects.toMatchObject({ code: 'session-closed' });
    await expect(escaped!.transferCookies()).rejects.toMatchObject({ code: 'session-closed' });
  });
  it('rejects outside-scope actions and wrong identities before browser execution', async () => {
    const { browser, perform, driver } = setup();
    await expect(browser.withSession(identities[0]!, async session => session.perform({ action: 'navigate', url: 'https://external.test/' }))).rejects.toMatchObject({ code: 'scope-denied' });
    expect(perform).not.toHaveBeenCalled();
    const count = vi.mocked(driver.runWorkflow).mock.calls.length;
    await expect(browser.withSession({ ...identities[0]!, roles: ['admin'] }, async () => undefined)).rejects.toMatchObject({ code: 'authentication-failed' });
    expect(vi.mocked(driver.runWorkflow).mock.calls).toHaveLength(count);
  });
  it('establishes independent Alice/Bob/Admin sessions and reuses matching sessions', async () => {
    const { manager, send, driver } = setup();
    for (const identity of identities) {
      const session = await manager.establishSession(identity);
      expect(await manager.establishSession(identity)).toBe(session);
      await session.http.execute({ url: '/api/me' });
      expect(send.mock.lastCall?.[0].headers.cookie).toBe(`sid=private-${identity.id}`);
      expect(JSON.stringify(await session.cookies())).not.toContain(`private-${identity.id}`);
      expect((await new SessionNetworkObserver().observe(session)).every(record => record.identityId === identity.id)).toBe(true);
    }
    expect(driver.runWorkflow).toHaveBeenCalledTimes(3); await manager.close();
  });
  it('deduplicates concurrent establishment and bounds session capacity', async () => {
    const { manager, driver } = setup({ maxSessions: 1 });
    const one = manager.establishSession(identities[0]!), two = manager.establishSession(identities[0]!);
    await expect(manager.establishSession(identities[1]!)).rejects.toMatchObject({ code: 'session-limit' });
    expect(await one).toBe(await two); expect(driver.runWorkflow).toHaveBeenCalledOnce(); await manager.close();
  });
  it('transfers HTTP cookie rotations into the browser and browser cookies back to HTTP', async () => {
    const { manager, cookies, send } = setup();
    send.mockResolvedValueOnce(raw({ 'set-cookie': ['sid=rotated; Path=/; HttpOnly', 'theme=dark; Path=/'] }));
    const session = await manager.establishSession(identities[0]!);
    await session.http.execute({ url: '/rotate' });
    await session.withBrowser(async browser => {
      expect(cookies.get('alice')?.find(cookie => cookie.name === 'sid')?.value).toBe('rotated');
      const incoming = await browser.transferCookies();
      await browser.importCookies(incoming.map(cookie => ({ ...cookie, value: cookie.name === 'sid' ? 'browser-rotated' : cookie.value })));
    });
    await session.http.execute({ url: '/api/me' });
    expect(send.mock.lastCall?.[0].headers.cookie).toContain('sid=browser-rotated'); await manager.close();
  });
  it('blocks caller credential overrides and closes/expunges sessions on expiry', async () => {
    const { manager, send } = setup({ ttlMs: 30 });
    const session = await manager.establishSession(identities[0]!);
    await expect(session.http.execute({ url: '/', headers: { Authorization: 'private' } })).rejects.toMatchObject({ code: 'invalid-request' });
    await expect(session.http.execute({ url: 'https://external.test/' })).rejects.toMatchObject({ code: 'scope-denied' });
    expect(send).not.toHaveBeenCalled();
    await new Promise(resolve => setTimeout(resolve, 40));
    await expect(session.cookies()).rejects.toMatchObject({ code: 'session-closed' });
    const fresh = await manager.establishSession(identities[0]!); expect(fresh.id).not.toBe(session.id);
    await fresh.close(); await expect(fresh.http.execute({ url: '/' })).rejects.toMatchObject({ code: 'session-closed' });
    await manager.close(); await expect(manager.establishSession(identities[0]!)).rejects.toMatchObject({ code: 'session-closed' });
  });
  it('stops on record exhaustion before sending another HTTP request', async () => {
    const { manager, send } = setup({ maxNetworkRecords: 2 });
    const session = await manager.establishSession(identities[0]!);
    await session.http.execute({ url: '/' });
    await expect(session.http.execute({ url: '/' })).rejects.toMatchObject({ code: 'record-limit' });
    expect(send).toHaveBeenCalledOnce(); await manager.close();
  });
  it('aborts an in-flight HTTP exchange and queued work when a session closes', async () => {
    const { manager, send } = setup();
    let entered!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    send.mockImplementationOnce(async () => { entered(); return new Promise(() => undefined); });
    const session = await manager.establishSession(identities[0]!);
    const inflight = session.http.execute({ url: '/' });
    const queued = session.http.execute({ url: '/' });
    const assertions = [expect(inflight).rejects.toMatchObject({ code: 'session-closed' }), expect(queued).rejects.toMatchObject({ code: 'session-closed' })];
    await started; await session.close(); await Promise.all(assertions);
    expect(send).toHaveBeenCalledOnce(); await manager.close();
  });
  it('does not commit browser cookie state if final driver authentication fails', async () => {
    const { manager, driver, send, cookies } = setup();
    const session = await manager.establishSession(identities[0]!);
    const original = vi.mocked(driver.runWorkflow).getMockImplementation()!;
    vi.mocked(driver.runWorkflow).mockImplementationOnce(async (...args) => ({ ...await original(...args), outcome: 'FAILED',
      diagnostics: [{ code: 'authentication-failed', message: 'sanitized' }] }));
    await expect(session.withBrowser(async () => {
      cookies.get('alice')![0] = { ...cookies.get('alice')![0]!, value: 'wrong-account' };
    })).rejects.toMatchObject({ code: 'authentication-failed' });
    await session.http.execute({ url: '/' });
    expect(send.mock.lastCall?.[0].headers.cookie).toBe('sid=private-alice'); await manager.close();
  });
  it('refuses nested session operations promptly instead of deadlocking its queue', async () => {
    const { manager, send } = setup();
    const session = await manager.establishSession(identities[0]!);
    await session.withBrowser(async () => {
      await expect(session.http.execute({ url: '/' })).rejects.toMatchObject({ code: 'invalid-request' });
      await expect(session.withBrowser(async () => undefined)).rejects.toMatchObject({ code: 'invalid-request' });
    });
    expect(send).not.toHaveBeenCalled(); await manager.close();
  });
  it('reports missing cookie capabilities and unsupported authentication transports explicitly', async () => {
    const fake = fakeDriver(); const original = vi.mocked(fake.driver.runWorkflow).getMockImplementation()!;
    vi.mocked(fake.driver.runWorkflow).mockImplementation(async (ctx, flow, execute, target) => original(ctx, flow, async port => {
      const { readCookies: _read, ...legacy } = port; await execute(legacy);
    }, target));
    const browser = new WorkflowBrowserController({ driver: fake.driver, context });
    await expect(browser.withSession(identities[0]!, async session => session.cookies())).rejects.toMatchObject({ code: 'unsupported-capability' });
    const bearer = { ...identities[0]!, authentication: 'jwt' as const };
    const { manager } = setup({ identities: [bearer] });
    await expect(manager.establishSession(bearer)).rejects.toMatchObject({ code: 'unsupported-capability' }); await manager.close();
  });
});

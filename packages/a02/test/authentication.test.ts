import { describe, expect, it } from 'vitest';
import { DeterministicRequestExecutor, type HttpRequest } from '@agento/runtime';
import type { ExecutionGuard } from '@agento/core';
import { HttpCookieAuthenticationManager } from '../src/index.js';

const identity = { id: 'alice', label: 'Alice', roles: [], authentication: 'session-cookie' as const };
function host(login: () => Promise<HttpRequest>, status = 200, cookie = 'auth=private-cookie; Secure; HttpOnly; Path=/') {
  const requests: HttpRequest[] = [];
  let active = true;
  const guard: ExecutionGuard = { assertActive: () => { if (!active) throw new Error('closed'); },
    assertRequest: () => { if (!active) throw new Error('closed'); }, assertRedirect: () => {} };
  const executor = new DeterministicRequestExecutor({ baseUrl: 'https://target.invalid', allowedOrigins: ['https://target.invalid'],
    transport: { send: async request => { requests.push(request); return { status, headers: cookie ? { 'set-cookie': [cookie] } : {},
      body: new Uint8Array(), truncated: false, firstByteMs: 1 }; } } });
  const root = new HttpCookieAuthenticationManager({ executor, login }), manager = root.withGuard(guard);
  return { root, manager, requests, revoke: () => { active = false; } };
}
const login = async (): Promise<HttpRequest> => ({ url: '/login', method: 'POST', body: 'private-password' });
describe('guarded HTTP cookie login', () => {
  it('keeps sessions isolated, exposes only redacted cookies and revokes closed handles', async () => {
    const { root, manager, requests } = host(login);
    const first = await manager.establishSession(identity), second = await manager.establishSession({ ...identity, id: 'bob' });
    expect(first.id).not.toBe(second.id);
    expect(JSON.stringify(await first.cookies())).not.toContain('private-cookie');
    await first.http.execute({ url: '/account' });
    expect(requests.at(-1)?.headers?.cookie).toBe('auth=private-cookie');
    await first.close();
    await expect(first.http.execute({ url: '/account' })).rejects.toMatchObject({ code: 'session-closed' });
    await second.http.execute({ url: '/account' });
    await manager.close();
    await expect(second.cookies()).rejects.toMatchObject({ code: 'session-closed' });
    await root.close();
  });
  it.each([401, 500])('rejects failed login status %i', async status => {
    const { manager } = host(login, status);
    await expect(manager.establishSession(identity)).rejects.toMatchObject({ code: 'authentication-failed' });
    await manager.close();
  });
  it('rejects successful login without usable session cookies', async () => {
    const { manager } = host(login, 200, '');
    await expect(manager.establishSession(identity)).rejects.toMatchObject({ code: 'authentication-failed' });
    await manager.close();
  });
  it.each([
    { url: 'https://other.invalid/login', method: 'POST' },
    { url: '/login', method: 'GET' },
    { url: '/login', method: 'POST', headers: { cookie: 'private-cookie' } },
  ])('refuses invalid login requests before access: %j', async request => {
    const { manager, requests } = host(async () => request);
    await expect(manager.establishSession(identity)).rejects.toMatchObject({ code: 'authentication-failed' });
    expect(requests).toHaveLength(0); await manager.close();
  });
  it('rechecks execution after the private credential callback resolves', async () => {
    let resolve!: (request: HttpRequest) => void;
    const { manager, revoke, requests } = host(() => new Promise(done => { resolve = done; }));
    const work = manager.establishSession(identity); revoke(); resolve(await login());
    await expect(work).rejects.toMatchObject({ code: 'authentication-failed' });
    expect(requests).toHaveLength(0); await manager.close();
  });
});

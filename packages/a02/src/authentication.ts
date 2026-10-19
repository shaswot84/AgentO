import { randomUUID } from 'node:crypto';
import type { ExecutionGuard } from '@agento/core';
import { DeterministicRequestExecutor, RuntimeError, SessionCookieJar } from '@agento/runtime';
import type { AuthenticationManager, AuthSession, HttpRequest, TestIdentity } from '@agento/runtime';

export interface HttpCookieAuthenticationOptions {
  readonly executor: DeterministicRequestExecutor;
  /** Private host callback. Return a same-origin JSON/form login request. */
  readonly login: (identity: TestIdentity) => Promise<HttpRequest>;
}

/** A small HTTP cookie login adapter. Each policy binding and identity gets a fresh jar. */
export class HttpCookieAuthenticationManager implements AuthenticationManager {
  private readonly sessions = new Set<AuthSession>();
  private closed = false;
  constructor(private readonly options: HttpCookieAuthenticationOptions, private readonly guard?: ExecutionGuard) {}
  withGuard(guard: ExecutionGuard): HttpCookieAuthenticationManager {
    if (this.closed) throw new RuntimeError('session-closed');
    return new HttpCookieAuthenticationManager({ ...this.options, executor: this.options.executor.withGuard(guard) }, guard);
  }
  async establishSession(identity: TestIdentity): Promise<AuthSession> {
    const active = () => {
      if (this.closed) throw new RuntimeError('session-closed');
      this.guard?.assertActive();
    };
    active();
    if (!this.guard || identity.authentication !== 'session-cookie') throw new RuntimeError('unsupported-capability');
    const jar = new SessionCookieJar(this.options.executor.scope), id = `a02-session:${randomUUID()}`;
    try {
      const login = await this.options.login(structuredClone(identity));
      active();
      const target = new URL(this.options.executor.scope.assert(login.url));
      if (target.origin !== new URL(this.options.executor.scope.baseUrl).origin
        || login.method !== 'POST' || Object.keys(login.headers ?? {}).some(key => /^(cookie|authorization)$/i.test(key))) {
        throw new RuntimeError('authentication-failed');
      }
      const response = await this.options.executor.execute({ ...login, url: target.href });
      active();
      if (response.status < 200 || response.status > 299 || response.body.truncated) throw new RuntimeError('authentication-failed');
      jar.update(response);
      if (!jar.privateCookies().length) throw new RuntimeError('authentication-failed');
      let closed = false;
      const expiresAt = new Date(Date.now() + 60_000).toISOString();
      const check = () => {
        active();
        if (closed || Date.now() >= Date.parse(expiresAt)) throw new RuntimeError('session-closed');
      };
      const session: AuthSession = {
        id, identityId: identity.id, expiresAt,
        http: { execute: async request => {
          check();
          if (Object.keys(request.headers ?? {}).some(key => /^(cookie|authorization)$/i.test(key))) throw new RuntimeError('invalid-request');
          const url = this.options.executor.scope.assert(request.url), cookie = jar.header(url);
          const result = await this.options.executor.execute({ ...request, url,
            headers: { ...request.headers, ...(cookie ? { cookie } : {}) } });
          check(); jar.update(result); return result;
        } },
        cookies: async () => { check(); return jar.inspect(id); },
        network: () => { check(); return []; },
        withBrowser: async () => { throw new RuntimeError('unsupported-capability'); },
        close: async () => { closed = true; jar.clear(); this.sessions.delete(session); },
      };
      this.sessions.add(session);
      return Object.freeze(session);
    } catch {
      jar.clear(); throw new RuntimeError('authentication-failed');
    }
  }
  async close(): Promise<void> {
    this.closed = true;
    await Promise.all([...this.sessions].map(session => session.close()));
  }
}

import { randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import type { ExecutionGuard } from '@agento/core';
import type { AuthSession, AuthenticationManager, BrowserController, BrowserSession, HttpRequest, HttpResponse,
  NetworkEvidence, RequestExecutor, RuntimeCookie, TestIdentity } from './contracts.js';
import { SessionCookieJar } from './cookies.js';
import { DeterministicRequestExecutor, type HttpExecutorOptions } from './http.js';
import { evidenceUrl, freeze, limit, RuntimeError, RuntimeScope } from './safety.js';

export interface SessionManagerOptions {
  readonly browser: BrowserController;
  readonly http: HttpExecutorOptions;
  readonly identities: readonly TestIdentity[];
  readonly ttlMs?: number;
  readonly maxSessions?: number;
  readonly maxNetworkRecords?: number;
  readonly maxCookies?: number;
}
/** Session-cookie transfer only. Other authentication transports need an explicit binding. */
export class RuntimeAuthenticationManager implements AuthenticationManager {
  private readonly sessions = new Map<string, AuthSession>();
  private readonly pending = new Map<string, Promise<AuthSession>>();
  private readonly identities: readonly TestIdentity[];
  private readonly scope: RuntimeScope;
  private readonly ttlMs: number;
  private readonly maximum: number;
  private readonly networkMaximum: number;
  private readonly httpOptions: HttpExecutorOptions;
  private disposed = false;
  constructor(private readonly options: SessionManagerOptions) {
    this.identities = freeze(structuredClone(options.identities));
    if (new Set(this.identities.map(identity => identity.id)).size !== this.identities.length) throw new RuntimeError('invalid-request');
    this.scope = new RuntimeScope(options.http.baseUrl, options.http.allowedOrigins);
    this.httpOptions = { ...options.http, allowedOrigins: [...options.http.allowedOrigins] };
    this.ttlMs = limit(options.ttlMs ?? 1_800_000, 86_400_000);
    this.maximum = limit(options.maxSessions ?? 20, 1000);
    this.networkMaximum = limit(options.maxNetworkRecords ?? 500, 10_000);
  }
  withGuard(guard: ExecutionGuard): RuntimeAuthenticationManager {
    if (!this.options.browser.withGuard) throw new RuntimeError('unsupported-capability');
    const browser = this.options.browser.withGuard(guard);
    const previous = this.httpOptions.executionGuard;
    return new RuntimeAuthenticationManager({ ...this.options, browser, http: { ...this.httpOptions,
      executionGuard: previous ? {
        signal: previous.signal ? AbortSignal.any([previous.signal, ...(guard.signal ? [guard.signal] : [])]) : guard.signal ?? new AbortController().signal,
        assertActive: () => { previous.assertActive(); guard.assertActive(); },
        assertRequest: request => { previous.assertRequest(request); guard.assertRequest(request); },
        assertRedirect: (from, to) => { previous.assertRedirect(from, to); guard.assertRedirect(from, to); },
      } : guard } });
  }
  establishSession(identity: TestIdentity): Promise<AuthSession> {
    if (this.disposed) return Promise.reject(new RuntimeError('session-closed'));
    const registered = this.identities.find(item => item.id === identity.id);
    if (!registered || registered.authentication !== identity.authentication
      || JSON.stringify([...registered.roles].sort()) !== JSON.stringify([...identity.roles].sort())
      || registered.credentialsRef !== identity.credentialsRef
      || registered.authenticationStrategyId !== identity.authenticationStrategyId
      || registered.expectedRole !== identity.expectedRole) return Promise.reject(new RuntimeError('authentication-failed'));
    if (!['anonymous', 'session-cookie'].includes(registered.authentication)) return Promise.reject(new RuntimeError('unsupported-capability'));
    const cached = this.sessions.get(identity.id);
    if (cached && Date.parse(cached.expiresAt) > Date.now()) return Promise.resolve(cached);
    if (cached) { void cached.close(); this.sessions.delete(identity.id); }
    const waiting = this.pending.get(identity.id);
    if (waiting) return waiting;
    if (this.sessions.size + this.pending.size >= this.maximum) return Promise.reject(new RuntimeError('session-limit'));
    const pending = this.create(registered).then(session => { this.sessions.set(identity.id, session); return session; })
      .finally(() => { this.pending.delete(identity.id); });
    this.pending.set(identity.id, pending); return pending;
  }
  private async create(identity: TestIdentity): Promise<AuthSession> {
    const id = `runtime-auth:${randomUUID()}`, jar = new SessionCookieJar(this.scope, this.options.maxCookies);
    const transport = new DeterministicRequestExecutor(this.httpOptions);
    const records: NetworkEvidence[] = [];
    const controller = new AbortController();
    let closed = false, expires = Infinity, tail: Promise<unknown> = Promise.resolve();
    let expiryTimer: ReturnType<typeof setTimeout> | undefined;
    const queueContext = new AsyncLocalStorage<symbol>();
    let activeTask: symbol | undefined;
    const assertActive = () => {
      if (closed || Date.now() >= expires) { closed = true; controller.abort(); jar.clear(); throw new RuntimeError('session-closed'); }
    };
    const serial = <T>(execute: () => Promise<T>): Promise<T> => {
      if (activeTask && queueContext.getStore() === activeTask) return Promise.reject(new RuntimeError('invalid-request'));
      const work = tail.then(() => {
        assertActive(); const token = Symbol(); activeTask = token;
        return queueContext.run(token, async () => {
          try { return await execute(); } finally { activeTask = undefined; }
        });
      });
      tail = work.catch(() => undefined); return work;
    };
    const append = (incoming: readonly NetworkEvidence[]) => {
      if (records.length + incoming.length > this.networkMaximum) throw new RuntimeError('record-limit');
      records.push(...incoming.map(record => freeze({ ...record, sessionId: id, identityId: identity.id })));
    };
    const browserRun = async <T>(execute: (session: BrowserSession) => Promise<T>, initializing = false): Promise<T> => {
      let stagedCookies: readonly RuntimeCookie[] = [], stagedRecords: readonly NetworkEvidence[] = [];
      const result = await this.options.browser.withSession(identity, async browser => {
        assertActive();
        if (!initializing) await browser.importCookies(jar.privateCookies(this.scope.baseUrl));
        let active = true;
        const guard = () => { assertActive(); if (!active) throw new RuntimeError('session-closed'); };
        const session: BrowserSession = Object.freeze<BrowserSession>({ id, identityId: identity.id,
          inspect: async () => { guard(); const page = await browser.inspect(); guard(); return page; },
          perform: async action => { guard(); await browser.perform(action); guard(); },
          network: () => { guard(); return browser.network(); },
          cookies: async () => { guard(); const cookies = await browser.cookies(); guard(); return cookies; },
          transferCookies: async () => { guard(); const cookies = await browser.transferCookies(); guard(); return cookies; },
          importCookies: async cookies => { guard(); await browser.importCookies(cookies); guard(); },
        });
        try {
          const value = await execute(session); guard();
          stagedCookies = await browser.transferCookies(); guard();
          stagedRecords = browser.network(); return value;
        } finally { active = false; }
      });
      assertActive();
      if (records.length + stagedRecords.length > this.networkMaximum) throw new RuntimeError('record-limit');
      jar.replaceFromBrowser(stagedCookies, this.scope.baseUrl);
      if (identity.authentication !== 'anonymous' && !jar.privateCookies(this.scope.baseUrl).length) throw new RuntimeError('unsupported-capability');
      append(stagedRecords); return result;
    };
    const http: RequestExecutor = Object.freeze({ execute: (request: HttpRequest) => {
      const copy = { ...request, ...(request.headers ? { headers: { ...request.headers } } : {}) };
      return serial(async (): Promise<HttpResponse> => {
        if (records.length >= this.networkMaximum) throw new RuntimeError('record-limit');
        if (Object.keys(copy.headers ?? {}).some(key => ['cookie', 'authorization'].includes(key.toLowerCase()))) throw new RuntimeError('invalid-request');
        const url = this.scope.assert(copy.url), cookie = jar.header(url);
        const signal = copy.signal ? AbortSignal.any([controller.signal, copy.signal]) : controller.signal;
        try {
          const response = await transport.execute({ ...copy, url, headers: { ...copy.headers, ...(cookie ? { cookie } : {}) }, signal });
          assertActive(); jar.update(response);
          append([{ sessionId: id, identityId: identity.id, source: 'http', url: evidenceUrl(url), method: response.method, status: response.status, blocked: false }]);
          return response;
        } catch (error) {
          assertActive();
          append([{ sessionId: id, identityId: identity.id, source: 'http', url: evidenceUrl(url), method: copy.method ?? 'GET', status: null, blocked: false }]);
          throw error;
        }
      });
    } });
    const session: AuthSession = Object.freeze({ id, identityId: identity.id,
      get expiresAt() { return new Date(expires).toISOString(); }, http,
      withBrowser: <T>(execute: (browser: BrowserSession) => Promise<T>) => serial(() => browserRun(execute)),
      cookies: async () => { assertActive(); return jar.inspect(id); },
      network: () => { assertActive(); return freeze(records.map(record => ({ ...record }))); },
      close: async () => {
        closed = true; controller.abort(); jar.clear();
        if (expiryTimer) clearTimeout(expiryTimer);
        if (this.sessions.get(identity.id) === session) this.sessions.delete(identity.id);
      },
    });
    try {
      await browserRun(async () => undefined, true);
      expires = Date.now() + this.ttlMs;
      expiryTimer = setTimeout(() => { void session.close(); }, this.ttlMs); expiryTimer.unref();
      return session;
    } catch (error) { await session.close(); throw error; }
  }
  async close(): Promise<void> {
    this.disposed = true;
    const pending = await Promise.allSettled(this.pending.values());
    const sessions = [...this.sessions.values(), ...pending.flatMap(result => result.status === 'fulfilled' ? [result.value] : [])];
    await Promise.all(sessions.map(session => session.close()));
  }
}

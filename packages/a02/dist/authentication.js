import { randomUUID } from 'node:crypto';
import { RuntimeError, SessionCookieJar } from '@agento/runtime';
/** A small HTTP cookie login adapter. Each policy binding and identity gets a fresh jar. */
export class HttpCookieAuthenticationManager {
    options;
    guard;
    sessions = new Set();
    closed = false;
    constructor(options, guard) {
        this.options = options;
        this.guard = guard;
    }
    withGuard(guard) {
        if (this.closed)
            throw new RuntimeError('session-closed');
        return new HttpCookieAuthenticationManager({ ...this.options, executor: this.options.executor.withGuard(guard) }, guard);
    }
    async establishSession(identity) {
        const active = () => {
            if (this.closed)
                throw new RuntimeError('session-closed');
            this.guard?.assertActive();
        };
        active();
        if (!this.guard || identity.authentication !== 'session-cookie')
            throw new RuntimeError('unsupported-capability');
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
            if (response.status < 200 || response.status > 299 || response.body.truncated)
                throw new RuntimeError('authentication-failed');
            jar.update(response);
            if (!jar.privateCookies().length)
                throw new RuntimeError('authentication-failed');
            let closed = false;
            const expiresAt = new Date(Date.now() + 60_000).toISOString();
            const check = () => {
                active();
                if (closed || Date.now() >= Date.parse(expiresAt))
                    throw new RuntimeError('session-closed');
            };
            const session = {
                id, identityId: identity.id, expiresAt,
                http: { execute: async (request) => {
                        check();
                        if (Object.keys(request.headers ?? {}).some(key => /^(cookie|authorization)$/i.test(key)))
                            throw new RuntimeError('invalid-request');
                        const url = this.options.executor.scope.assert(request.url), cookie = jar.header(url);
                        const result = await this.options.executor.execute({ ...request, url,
                            headers: { ...request.headers, ...(cookie ? { cookie } : {}) } });
                        check();
                        jar.update(result);
                        return result;
                    } },
                cookies: async () => { check(); return jar.inspect(id); },
                network: () => { check(); return []; },
                withBrowser: async () => { throw new RuntimeError('unsupported-capability'); },
                close: async () => { closed = true; jar.clear(); this.sessions.delete(session); },
            };
            this.sessions.add(session);
            return Object.freeze(session);
        }
        catch {
            jar.clear();
            throw new RuntimeError('authentication-failed');
        }
    }
    async close() {
        this.closed = true;
        await Promise.all([...this.sessions].map(session => session.close()));
    }
}

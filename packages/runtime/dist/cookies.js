import { isIP } from 'node:net';
import { freeze, limit, RuntimeError } from './safety.js';
const token = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const cookieValue = /^(?:[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*)$/;
export function defaultCookiePath(path) {
    return path.startsWith('/') && path.lastIndexOf('/') > 0 ? path.slice(0, path.lastIndexOf('/')) : '/';
}
export function parseSetCookie(line, responseUrl, now = Date.now()) {
    if (line.length > 16_384 || /[\r\n\u0000]/.test(line))
        return;
    const url = new URL(responseUrl), parts = line.split(';'), pair = parts.shift(), index = pair.indexOf('=');
    if (index < 1)
        return;
    const name = pair.slice(0, index).trim(), value = pair.slice(index + 1).trim().replace(/^"(.*)"$/, '$1');
    if (!token.test(name) || !cookieValue.test(value))
        return;
    const attributes = new Map();
    for (const part of parts) {
        const equals = part.indexOf('='), key = (equals < 0 ? part : part.slice(0, equals)).trim().toLowerCase();
        attributes.set(key, equals < 0 ? '' : part.slice(equals + 1).trim());
    }
    const hostOnly = !attributes.has('domain');
    const domain = hostOnly ? url.hostname : attributes.get('domain').toLowerCase().replace(/^\./, '');
    // Parse only cookies whose domain matches the response host. Jar acceptance is stricter.
    if (!domain || domain.endsWith('.') || domain !== url.hostname && (isIP(url.hostname) || !url.hostname.endsWith(`.${domain}`)))
        return;
    const pathAttribute = attributes.get('path');
    const path = pathAttribute?.startsWith('/') ? pathAttribute : defaultCookiePath(url.pathname);
    const rawSameSite = attributes.get('samesite')?.toLowerCase();
    const sameSite = rawSameSite === 'strict' ? 'Strict' : rawSameSite === 'lax' ? 'Lax' : rawSameSite === 'none' ? 'None' : null;
    const age = attributes.get('max-age');
    const maxAge = age && /^-?\d+$/.test(age) && Number.isSafeInteger(Number(age)) ? Number(age) : null;
    const rawExpires = attributes.get('expires'), parsed = rawExpires ? Date.parse(rawExpires) : NaN;
    let expiry = Number.isFinite(parsed) ? parsed : null;
    if (maxAge !== null)
        expiry = maxAge <= 0 ? 0 : Math.min(8_640_000_000_000_000, now + maxAge * 1000);
    return freeze({ name, value, domain, path, hostOnly, httpOnly: attributes.has('httponly'), secure: attributes.has('secure'),
        sameSite, expiresAt: expiry === null ? null : new Date(expiry).toISOString(), maxAge, partitioned: attributes.has('partitioned') });
}
export function cookieEvidence(cookie, source, reference = {}) {
    const { value: _value, ...metadata } = cookie;
    return freeze({ ...metadata, value: '[REDACTED]', source, ...reference });
}
export class NormalizedCookieAnalyzer {
    async analyze(response) {
        const now = Date.parse(response.timings.startedAt);
        return freeze((response.headers['set-cookie'] ?? []).flatMap(line => {
            const parsed = parseSetCookie(line, response.url, now);
            return parsed ? [cookieEvidence(parsed, 'response', { responseId: response.id })] : [];
        }));
    }
}
/** Private, bounded jar. Every cookie is bound to an exact origin in addition to domain/path. */
export class SessionCookieJar {
    scope;
    entries = new Map();
    maximum;
    constructor(scope, maximum = 200) {
        this.scope = scope;
        this.maximum = limit(maximum, 2000);
    }
    update(response) {
        const url = new URL(this.scope.assert(response.url));
        this.transaction(() => {
            for (const line of response.headers['set-cookie'] ?? []) {
                const cookie = parseSetCookie(line, url.href, Date.parse(response.timings.startedAt));
                if (cookie)
                    this.set(url.origin, cookie);
            }
        });
    }
    replaceFromBrowser(cookies, origin) {
        origin = new URL(this.scope.assert(origin)).origin;
        // Validate the entire batch before replacing any existing private state.
        for (const cookie of cookies)
            this.validate(origin, cookie);
        if (cookies.length > this.maximum)
            throw new RuntimeError('record-limit');
        this.transaction(() => {
            for (const [key, entry] of this.entries)
                if (entry.origin === origin)
                    this.entries.delete(key);
            for (const cookie of cookies)
                this.set(origin, cookie);
        });
    }
    transaction(execute) {
        const before = new Map(this.entries);
        try {
            execute();
        }
        catch (error) {
            this.entries.clear();
            for (const [key, entry] of before)
                this.entries.set(key, entry);
            throw error;
        }
    }
    validate(origin, cookie) {
        const url = new URL(this.scope.assert(origin));
        if (!token.test(cookie.name) || !cookieValue.test(cookie.value) || cookie.domain !== url.hostname
            || !cookie.path.startsWith('/') || /[\x00-\x20;\x7f]/.test(cookie.path)
            || cookie.expiresAt !== null && !Number.isFinite(Date.parse(cookie.expiresAt)))
            throw new RuntimeError('authentication-failed');
        if (cookie.partitioned)
            throw new RuntimeError('unsupported-capability');
    }
    set(origin, cookie) {
        // Parent-domain and partitioned cookies remain observable, but cannot expand this jar.
        if (cookie.domain !== new URL(origin).hostname || cookie.partitioned)
            return;
        this.validate(origin, cookie);
        if (cookie.secure && new URL(origin).protocol !== 'https:')
            return;
        if (cookie.name.startsWith('__Secure-') && (!cookie.secure || new URL(origin).protocol !== 'https:')
            || cookie.name.startsWith('__Host-') && (!cookie.secure || !cookie.hostOnly || cookie.path !== '/')
            || cookie.sameSite === 'None' && !cookie.secure)
            return;
        const key = JSON.stringify([origin, cookie.domain, cookie.path, cookie.name]);
        if (cookie.expiresAt !== null && Date.parse(cookie.expiresAt) <= Date.now()) {
            this.entries.delete(key);
            return;
        }
        this.prune();
        if (!this.entries.has(key) && this.entries.size >= this.maximum)
            throw new RuntimeError('record-limit');
        this.entries.set(key, { origin, cookie: freeze({ ...cookie }) });
    }
    prune() {
        for (const [key, { cookie }] of this.entries)
            if (cookie.expiresAt !== null && Date.parse(cookie.expiresAt) <= Date.now())
                this.entries.delete(key);
    }
    header(requestUrl) {
        const url = new URL(this.scope.assert(requestUrl));
        this.prune();
        return [...this.entries.values()].filter(entry => entry.origin === url.origin
            && (!entry.cookie.secure || url.protocol === 'https:') && pathMatches(url.pathname, entry.cookie.path))
            .sort((a, b) => b.cookie.path.length - a.cookie.path.length)
            .map(({ cookie }) => `${cookie.name}=${cookie.value}`).join('; ');
    }
    privateCookies(origin) {
        this.prune();
        return freeze([...this.entries.values()].filter(entry => !origin || entry.origin === new URL(origin).origin)
            .map(entry => ({ ...entry.cookie })));
    }
    inspect(sessionId) { return freeze(this.privateCookies().map(cookie => cookieEvidence(cookie, 'jar', { sessionId }))); }
    clear() { this.entries.clear(); }
}
function pathMatches(request, path) {
    return request === path || request.startsWith(path) && (path.endsWith('/') || request[path.length] === '/');
}

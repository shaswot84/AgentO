import { createHash } from 'node:crypto';
import type { Identity, Project } from '@agento/core';
import type { BrowserAction, BrowserState } from './types.js';

export class BrowserError extends Error {
  constructor(readonly code: 'invalid-workflow' | 'scope-denied' | 'authentication-failed'
    | 'browser-failed' | 'timeout' | 'session-store-failed') {
    super(code);
  }
}

/** Exact scheme/host/port scope, with no suffix, wildcard, or same-site expansion. */
export class BrowserScope {
  readonly origins: readonly string[];
  readonly baseUrl: string;
  constructor(project: Project) {
    this.origins = [...new Set(project.allowedOrigins.map(value => {
      const url = parseUrl(value);
      if (url.pathname !== '/' || url.search || url.hash) throw new BrowserError('scope-denied');
      return url.origin;
    }))].sort();
    this.baseUrl = this.assert(project.baseUrl);
    Object.freeze(this.origins);
  }
  assert(value: string): string {
    const url = parseUrl(value, this.baseUrl);
    if (!this.origins.includes(url.origin)) throw new BrowserError('scope-denied');
    return url.href;
  }
  binding(project: Project, identity: Identity): string {
    return createHash('sha256').update(JSON.stringify([
      project.id, this.baseUrl, this.origins, identity.id, identity.authentication, [...identity.roles].sort(),
    ])).digest('hex');
  }
  validateActions(actions: readonly BrowserAction[]): void {
    if (!Array.isArray(actions) || actions.length < 1 || actions.length > 100) throw new BrowserError('invalid-workflow');
    for (const action of actions) {
      if (!action || typeof action !== 'object') throw new BrowserError('invalid-workflow');
      switch (action.action) {
        case 'navigate': case 'wait-url': this.assert(action.url); break;
        case 'fill':
          if (typeof action.value !== 'string' || action.value.length > 16_384) throw new BrowserError('invalid-workflow');
          break;
        case 'click': case 'wait-visible': break;
        default: throw new BrowserError('invalid-workflow');
      }
      if ('selector' in action && (typeof action.selector !== 'string' || !action.selector || action.selector.length > 2048)) {
        throw new BrowserError('invalid-workflow');
      }
      if ('response' in action && action.response) {
        this.assert(action.response.url);
        if (action.response.method !== undefined && !/^[A-Z]+$/.test(action.response.method)
          || action.response.status !== undefined && (!Number.isInteger(action.response.status)
            || action.response.status < 100 || action.response.status > 599)) throw new BrowserError('invalid-workflow');
      }
    }
  }
  /** Reject restored storage for other origins and domain cookies spanning unapproved hosts. */
  validateState(state: BrowserState): void {
    if (state.format !== 'playwright-storage-state' || state.version !== 1 || !state.data || typeof state.data !== 'object') {
      throw new BrowserError('authentication-failed');
    }
    const { cookies, origins } = state.data as { cookies?: unknown; origins?: unknown };
    if (!Array.isArray(cookies) || !Array.isArray(origins)) throw new BrowserError('authentication-failed');
    const hosts = this.origins.map(origin => new URL(origin).hostname);
    for (const cookie of cookies) {
      if (!cookie || typeof cookie.domain !== 'string' || !hosts.includes(cookie.domain.replace(/^\./, ''))) {
        throw new BrowserError('authentication-failed');
      }
    }
    for (const origin of origins) {
      if (!origin || typeof origin.origin !== 'string') throw new BrowserError('authentication-failed');
      this.assert(origin.origin);
    }
  }
}

function parseUrl(value: string, base?: string): URL {
  try {
    if (typeof value !== 'string' || !value || value !== value.trim() || /[\u0000-\u0020\\]/.test(value)) throw new Error();
    const url = new URL(value, base);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error();
    return url;
  } catch { throw new BrowserError('scope-denied'); }
}

/** No headers/bodies are retained; every query value and fragment is removed. */
export function redactUrl(value: string, secrets: readonly string[]): string {
  try {
    const url = new URL(value);
    url.username = ''; url.password = ''; url.hash = '';
    for (const key of [...url.searchParams.keys()]) url.searchParams.set(key, '[REDACTED]');
    let result = url.href.replace(/\/((?:token|secret|password|session|jwt|apikey))\/[^/?]+/gi, '/$1/[REDACTED]')
      .replace(/\/[A-Za-z0-9_.~%+=-]{40,}(?=\/|\?|$)/g, '/[REDACTED]');
    for (const secret of secrets.filter(Boolean).sort((a, b) => b.length - a.length)) {
      for (const form of new Set([secret, encodeURIComponent(secret)])) result = result.split(form).join('[REDACTED]');
    }
    return result.slice(0, 4096);
  } catch { return '[REDACTED URL]'; }
}

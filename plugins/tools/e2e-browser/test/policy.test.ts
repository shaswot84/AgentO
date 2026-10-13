import { describe, expect, it } from 'vitest';
import { BrowserScope, redactUrl } from '../src/policy.js';
import { context, state } from './helpers.js';

describe('exact-origin policy', () => {
  it('allows only explicitly listed schemes, hosts and ports and resolves relative URLs', () => {
    const scope = new BrowserScope(context.project);
    expect(scope.assert('/api/orders/102')).toBe('http://127.0.0.1:3000/api/orders/102');
    for (const url of ['http://localhost:3000', 'http://127.0.0.1:3001', 'https://127.0.0.1:3000',
      'http://127.0.0.1.evil.example:3000', '//evil.example', 'javascript:alert(1)', 'data:text/html,hello',
      'file:///etc/passwd', 'http://user:pass@127.0.0.1:3000', 'http://127.0.0.1:3000\\@evil.example', ' http://127.0.0.1:3000']) {
      expect(() => scope.assert(url)).toThrow('scope-denied');
    }
  });
  it('requires the base URL in a nonempty origin-only allowlist', () => {
    for (const allowedOrigins of [[], ['http://127.0.0.1:3000/path'], ['http://127.0.0.1:3000?x=1'],
      ['http://127.0.0.1:3000#fragment'], ['http://*.example.com'], ['https://other.example']]) {
      expect(() => new BrowserScope({ ...context.project, allowedOrigins })).toThrow('scope-denied');
    }
  });
  it('checks restored state format, cookie hosts and storage origins', () => {
    const scope = new BrowserScope(context.project);
    expect(() => scope.validateState(state)).not.toThrow();
    for (const invalid of [
      { ...state, format: 'file', data: '/etc/passwd' },
      { ...state, data: { cookies: [{ domain: 'evil.example', value: 'secret' }], origins: [] } },
      { ...state, data: { cookies: [], origins: [{ origin: 'http://127.0.0.1:3001', localStorage: [] }] } },
      { ...state, data: { cookies: [], origins: [{}] } },
    ]) expect(() => scope.validateState(invalid)).toThrow();
  });
  it('redacts all query values, fragments, userinfo and secret path segments', () => {
    const url = redactUrl('https://user:password@example.com/session/private-session-cookie?ordinary=private&password=secret#token', ['private-session-cookie']);
    expect(url).not.toMatch(/user:|password@|private-session-cookie|ordinary=private|password=secret|#token/);
    expect(url).toContain('example.com/session/[REDACTED]');
    expect(redactUrl('invalid', [])).toBe('[REDACTED URL]');
  });
});

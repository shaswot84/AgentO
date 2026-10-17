import { describe, expect, it } from 'vitest';
import { NormalizedCookieAnalyzer, NormalizedHeaderAnalyzer, RuntimeScope } from '../src/index.js';
import { SessionCookieJar } from '../src/cookies.js';
import { origin, response } from './helpers.js';

describe('header and cookie observations', () => {
  it('extracts repeated CORS/security fields, quoted cache directives and invalid numeric/boolean values without decisions', async () => {
    const result = await new NormalizedHeaderAnalyzer().analyze(response({
      'access-control-allow-origin': ['*', 'https://example.test'], 'access-control-allow-credentials': ['true', 'TRUE', 'false'],
      'access-control-allow-methods': ['GET, POST', 'OPTIONS'], 'access-control-allow-headers': ['Content-Type, X-Token'],
      'access-control-max-age': ['120', '12bad'], 'cache-control': ['private, max-age=60, custom="a,b"'],
      vary: ['Origin, Accept-Encoding'], 'x-frame-options': ['DENY'], 'set-cookie': ['sid=private'], age: ['3', '-1'],
    }));
    expect(result.cors.allowMethods).toEqual(['GET', 'POST', 'OPTIONS']);
    expect(result.cors.allowCredentials).toEqual([true, null, false]); expect(result.cors.maxAge).toEqual([120, null]);
    expect(result.caching.cacheControl).toContainEqual({ name: 'custom', value: 'a,b' });
    expect(result.security).toEqual({ 'x-frame-options': ['DENY'] });
    expect(JSON.stringify(result)).not.toMatch(/sid=|private-token|verdict|severity/);
    expect(Object.isFrozen(result.cors.allowOrigin)).toBe(true);
  });
  it('keeps Expires commas, normalizes flags/default paths, preserves missing SameSite and redacts values', async () => {
    const result = await new NormalizedCookieAnalyzer().analyze(response({ 'set-cookie': [
      'sid=private-session; HttpOnly; Secure; SameSite=None; Domain=.127.0.0.1; Path=/; Expires=Wed, 09 Jun 2038 10:18:14 GMT',
      'preference=secret; Max-Age=60', 'deleted=old; Max-Age=0; Expires=Wed, 09 Jun 2038 10:18:14 GMT',
      'bad name=invalid', 'foreign=secret; Domain=external.test',
    ] }));
    expect(result).toHaveLength(3);
    expect(result[0]).toMatchObject({ name: 'sid', value: '[REDACTED]', domain: '127.0.0.1', path: '/', httpOnly: true,
      secure: true, sameSite: 'None', hostOnly: false, expiresAt: '2038-06-09T10:18:14.000Z' });
    expect(result[1]).toMatchObject({ path: '/account', sameSite: null, hostOnly: true, maxAge: 60 });
    expect(result[2]?.expiresAt).toBe('1970-01-01T00:00:00.000Z');
    expect(JSON.stringify(result)).not.toMatch(/private-session|secret|old/);
  });
  it('maintains a bounded origin/path/expiry jar, replaces cookies and processes deletion', () => {
    const scope = new RuntimeScope(origin, [origin, 'http://127.0.0.1:3001']);
    const jar = new SessionCookieJar(scope, 5);
    jar.update(response({ 'set-cookie': ['sid=root; Path=/', 'sid=nested; Path=/account', 'secure=hidden; Secure', 'none=hidden; SameSite=None'] }));
    expect(jar.header(`${origin}/account/page`)).toBe('sid=nested; sid=root');
    expect(jar.header(`${origin}/accounting`)).toBe('sid=root');
    expect(jar.header('http://127.0.0.1:3001/account')).toBe('');
    jar.update(response({ 'set-cookie': ['sid=changed; Path=/', 'sid=gone; Path=/account; Max-Age=0'] }));
    expect(jar.header(`${origin}/account`)).toBe('sid=changed');
    expect(JSON.stringify(jar.inspect('session'))).not.toContain('changed');
    jar.clear(); expect(jar.header(origin)).toBe('');
  });
  it('does not forward parent-domain or partitioned cookies and rejects capacity overflow', () => {
    const scope = new RuntimeScope('https://app.example.test', ['https://app.example.test']);
    const jar = new SessionCookieJar(scope, 1);
    jar.update(response({ 'set-cookie': ['parent=private; Domain=example.test', 'partition=private; Secure; Partitioned'] }, 'https://app.example.test/'));
    expect(jar.header('https://app.example.test/')).toBe('');
    jar.update(response({ 'set-cookie': ['one=1'] }, 'https://app.example.test/'));
    expect(() => jar.update(response({ 'set-cookie': ['two=2'] }, 'https://app.example.test/'))).toThrow('record-limit');
    expect(() => jar.update(response({ 'set-cookie': ['one=changed', 'two=2'] }, 'https://app.example.test/'))).toThrow('record-limit');
    expect(jar.header('https://app.example.test/')).toBe('one=1');
  });
});

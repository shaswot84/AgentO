import { describe, expect, it } from 'vitest';
import { MemoryEvidenceStore, REDACTED } from '../src/index.js';
import { evidence, scope } from './helpers.js';

describe('redaction before retention', () => {
  it('removes passwords, tokens, credentials and cookie values while preserving security facts', () => {
    const input = evidence('proof', { facts: {
      request: { url: 'https://user:PRIVATE_USER_PASSWORD@shop.test/api?token=PRIVATE_QUERY#PRIVATE_FRAGMENT',
        headers: { Authorization: 'Bearer PRIVATE_AUTH', Cookie: 'sid=PRIVATE_COOKIE', 'X-Auth-Token': 'PRIVATE_HEADER' },
        body: JSON.stringify({ password: 'PRIVATE_PASSWORD', nested: { refresh_token: 'PRIVATE_REFRESH' }, count: 3 }) },
      response: { status: 200, headers: { 'Set-Cookie': ['sid=PRIVATE_SID; Path=/; Secure; HttpOnly'],
        'Content-Type': ['application/json'] }, body: { encoding: 'base64', data: Buffer.from('PRIVATE_BODY').toString('base64'), byteLength: 12 } },
      cookies: [{ name: 'sid', value: 'PRIVATE_COOKIE_VALUE', domain: 'shop.test', path: '/', secure: false, httpOnly: false }],
      api_key: 'PRIVATE_KEY', credentials: { password: 'PRIVATE_CREDENTIAL' },
      config: { name: 'clientSecret', value: 'PRIVATE_CONFIG' },
      source: { snippet: "const password = 'PRIVATE_SOURCE'; return res.send(user);" },
      rawOutput: 'PRIVATE_RAW', stdout: 'PRIVATE_STDOUT', stderr: 'PRIVATE_STDERR',
      browser: { dom: '<input value="PRIVATE_INPUT">', consoleLogs: ['PRIVATE_LOG'], screenshot: { data: 'PRIVATE_PIXELS', masked: true } },
    } });
    const store = new MemoryEvidenceStore();
    const record = store.capture([input], scope)[0]!;
    expect(JSON.stringify(record)).not.toContain('PRIVATE_');
    expect(record.facts.cookies).toEqual([{ name: 'sid', value: REDACTED, domain: 'shop.test', path: '/', secure: false, httpOnly: false }]);
    expect(record.facts.response).toMatchObject({ status: 200, headers: { 'Set-Cookie': [REDACTED] },
      body: { encoding: 'base64', data: REDACTED, byteLength: 12 } });
    expect(record.facts.request).toMatchObject({ body: { password: REDACTED, nested: { refresh_token: REDACTED }, count: 3 } });
    expect(JSON.stringify(input)).toContain('PRIVATE_PASSWORD');
  });
  it('redacts known secrets in free text, keys, paths, source snippets, and encoded forms', () => {
    const secret = 'private-value-7264';
    const store = new MemoryEvidenceStore({ secrets: [secret] });
    const record = store.capture([evidence('proof', {
      summary: `Observed ${secret}`, source: { file: `src/${secret}.ts`, startLine: 1 },
      facts: { [secret]: 'redacted key', note: `${secret} ${encodeURIComponent(secret)} ${Buffer.from(secret).toString('base64')}`,
        source: { snippet: `res.send('${secret}')` } },
    })], scope)[0]!;
    expect(JSON.stringify(record)).not.toContain(secret);
    expect(JSON.stringify(record)).not.toContain(Buffer.from(secret).toString('base64'));
    expect(record.summary).toBe(`Observed ${REDACTED}`);
    expect(Object.keys(record.facts)).toContain(REDACTED);
  });
  it('detects private keys, bearer/basic credentials and JWTs in free text', () => {
    const record = new MemoryEvidenceStore().capture([evidence('proof', { facts: {
      note: 'Bearer private-token Basic cHJpdmF0ZTpwYXNzd29yZA==',
      nested: ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwcml2YXRlIn0.c2lnbmF0dXJl'],
      pem: 'prefix -----BEGIN RSA PRIVATE KEY-----\nPRIVATEKEY\n-----END RSA PRIVATE KEY----- suffix',
      truncatedPem: '-----BEGIN PRIVATE KEY-----\nPRIVATEINCOMPLETE',
    } })], scope)[0]!;
    expect(JSON.stringify(record)).not.toMatch(/private-token|cHJpdm|eyJhbGci|PRIVATEKEY|PRIVATEINCOMPLETE/);
  });
  it('redacts query values and fragments for absolute and relative URLs', () => {
    const record = new MemoryEvidenceStore().capture([evidence('proof', { facts: {
      url: '/api?q=PRIVATE_Q&token=PRIVATE_T#PRIVATE_FRAGMENT',
      note: 'request https://name:PRIVATE_PASS@shop.test/api?session=PRIVATE_S recorded',
    } })], { ...scope, targetUrl: 'https://shop.test/api?key=PRIVATE_TARGET#PRIVATE_FRAGMENT' })[0]!;
    expect(JSON.stringify(record)).not.toContain('PRIVATE_');
    expect(record.facts.url).toBe('/api?q=%5BREDACTED%5D&token=%5BREDACTED%5D');
  });
  it('keeps response hashes, comparative facts, flags and scanner status as observations', () => {
    const facts = { outcome: 'COMPLETED', verified: false, responseEvidenceIds: ['response'],
      body: { sha256: 'a'.repeat(64), byteLength: 400, truncated: false },
      comparison: { statusDelta: 0, bodyEqual: true, ownerMarkersMatch: true },
      security: { 'access-control-allow-origin': ['https://evil.test'], 'content-security-policy': ["default-src 'self'"] } };
    const record = new MemoryEvidenceStore().capture([evidence('proof', { facts })], scope)[0]!;
    expect(record.facts).toEqual(facts);
  });
  it('rejects secret-bearing identifiers and key collisions without exposing their values', () => {
    const store = new MemoryEvidenceStore({ secrets: ['PRIVATE_ID', 'PRIVATE_OTHER'] });
    expect(() => store.capture([evidence('PRIVATE_ID')], scope)).toThrow('invalid-evidence');
    expect(() => store.capture([evidence('proof', { facts: { PRIVATE_ID: 1, PRIVATE_OTHER: 2 } })], scope)).toThrow('invalid-evidence');
    expect(store.list()).toEqual([]);
  });
  it('drops opaque bodies and validates JSON body nesting before processing', () => {
    const store = new MemoryEvidenceStore();
    const deep = '['.repeat(100) + '"PRIVATE"' + ']'.repeat(100);
    const item = store.capture([evidence('proof', { facts: { request: { body: 'PRIVATE_BINARY' }, response: { body: deep } } })], scope)[0]!;
    expect(item.facts).toEqual({ request: { body: REDACTED }, response: { body: REDACTED } });
  });
  it('redacts malformed cookie headers and common credential field aliases', () => {
    const item = new MemoryEvidenceStore().capture([evidence('proof', { facts: {
      headers: { 'set-cookie': ['sid="PRIVATE_A;PRIVATE_B"; Custom=PRIVATE_C'] },
      AWS_SECRET_ACCESS_KEY: 'PRIVATE_AWS', encryption_key: 'PRIVATE_ENCRYPTION', tokenValue: 'PRIVATE_TOKEN',
    } })], scope)[0]!;
    expect(JSON.stringify(item)).not.toContain('PRIVATE_');
  });
  it('retains structured DOM and console metadata while removing input values and raw text', () => {
    const record = new MemoryEvidenceStore().capture([evidence('proof', { kind: 'browser-observation', facts: {
      dom: { tagName: 'form', children: [{ tagName: 'input', attributes: { type: 'password', value: 'PRIVATE_INPUT' } },
        { tagName: 'button', textContent: 'PRIVATE_TEXT' }] },
      console: [{ level: 'error', timestamp: '2026-10-19T00:00:00Z', message: 'PRIVATE_MESSAGE' }],
      controls: [{ type: 'password', value: 'PRIVATE_CONTROL' }],
    } })], scope)[0]!;
    expect(JSON.stringify(record)).not.toContain('PRIVATE_');
    expect(record.facts.dom).toMatchObject({ tagName: 'form', children: [{ tagName: 'input', attributes: { type: 'password', value: REDACTED } },
      { tagName: 'button', textContent: REDACTED }] });
    expect(record.facts.console).toEqual([{ level: 'error', timestamp: '2026-10-19T00:00:00Z', message: REDACTED }]);
  });
});

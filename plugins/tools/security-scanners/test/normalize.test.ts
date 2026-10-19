import { describe, expect, it } from 'vitest';
import { dalfox, nuclei, sqlmap, zap } from '../src/normalize.js';

const url = 'http://127.0.0.1:1234/search?q=a';
describe('untrusted output projection', () => {
  it('handles current Dalfox metadata and findings', () => {
    const result = dalfox(JSON.stringify({ meta: { incomplete: false }, findings: [{ type: 'V', data: url,
      severity: 'High', confidence: 'high', evidence: 'PRIVATE', payload: 'PRIVATE' }] }), url);
    expect(result[0]).toMatchObject({ cweIds: ['CWE-79'], reportedSeverity: 'high', reportedConfidence: 'high' });
    expect(JSON.stringify(result)).not.toContain('PRIVATE');
  });
  it('rejects incomplete Dalfox runs even when they report no findings', () => {
    expect(() => dalfox(JSON.stringify({ meta: { incomplete: true }, findings: [] }), url)).toThrow('incomplete-output');
  });
  it.each([null, {}, { site: [] }])('rejects unsupported Nuclei schemas: %j', value => {
    expect(() => nuclei(JSON.stringify(value), url)).toThrow('invalid-output');
  });
  it('rejects non-HTTP Nuclei engines and foreign result URLs', () => {
    const result = { 'template-id': 'id', type: 'dns', 'matched-at': url, info: { severity: 'high' } };
    expect(() => nuclei(JSON.stringify(result), url)).toThrow('invalid-output');
    expect(() => nuclei(JSON.stringify({ ...result, type: 'http', 'matched-at': 'https://other.test' }), url)).toThrow('invalid-output');
  });
  it('does not accept ZAP alerts without scoped instances', () => {
    expect(() => zap(JSON.stringify({ site: [{ alerts: [{ pluginid: '123', instances: [] }] }] }), url)).toThrow('invalid-output');
    expect(() => zap(JSON.stringify({ site: [{ alerts: [{ pluginid: '123', instances: [{ uri: 'https://other.test' }] }] }] }), url)).toThrow('invalid-output');
  });
  it('does not read sqlmap technique names from arbitrary body text or errors', () => {
    expect(() => sqlmap('PRIVATE Type: boolean-based blind', url)).toThrow('invalid-output');
    expect(() => sqlmap('[CRITICAL] PRIVATE token', url)).toThrow('tool-failed');
    expect(sqlmap('[INFO] testing connection to the target URL\n[WARNING] all tested parameters do not appear to be injectable', url)).toEqual([]);
    expect(sqlmap('[INFO] testing connection to the target URL\n[CRITICAL] all tested parameters do not appear to be injectable.', url)).toEqual([]);
  });
  it('limits findings and accepts only known CWE labels', () => {
    const row = { 'template-id': 'id', type: 'http', 'matched-at': url,
      info: { severity: 'PRIVATE', classification: { 'cwe-id': ['CWE-89', 'CWE-999999-PRIVATE', 'PRIVATE'] } } };
    expect(nuclei(JSON.stringify(row), url)[0]).toMatchObject({ cweIds: ['CWE-89'], reportedSeverity: 'unknown' });
    expect(() => nuclei(Array.from({ length: 257 }, () => JSON.stringify(row)).join('\n'), url)).toThrow('invalid-output');
  });
});

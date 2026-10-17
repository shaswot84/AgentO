import { describe, expect, it, vi } from 'vitest';
import { DeterministicRequestExecutor, NormalizedResponseCollector, RuntimeScope } from '../src/index.js';
import type { TransportRequest } from '../src/index.js';
import { origin, raw } from './helpers.js';

describe('deterministic HTTP execution', () => {
  it('executes one exchange with explicit method, headers and body, preserving raw bytes and duplicate fields', async () => {
    const transport = { send: vi.fn(async (_request: TransportRequest) => raw({ 'set-cookie': ['a=1', 'b=2'], 'x-test': ['one', 'two'] }, '\u0000hello')) };
    const client = new DeterministicRequestExecutor({ baseUrl: origin, allowedOrigins: [origin], transport });
    const result = await client.execute({ url: '/api?token=private', method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: 'request' });
    expect(transport.send).toHaveBeenCalledOnce();
    expect(transport.send.mock.calls[0]![0]).toMatchObject({ url: `${origin}/api?token=private`, method: 'POST', body: 'request', headers: { 'content-type': 'text/plain' } });
    expect(result.headers['set-cookie']).toEqual(['a=1', 'b=2']);
    expect(Buffer.from(result.body.data, 'base64').toString()).toBe('\u0000hello');
    expect(Object.isFrozen(result.headers['set-cookie'])).toBe(true);
    const evidence = new NormalizedResponseCollector().evidence(result);
    expect(evidence.body.sha256).toHaveLength(64); expect(evidence.body.byteLength).toBe(6);
    expect(JSON.stringify(evidence)).not.toMatch(/private|hello|set-cookie/);
  });
  it.each(['http://external.test/', 'http://127.0.0.1:3001/', 'https://127.0.0.1:3000/',
    'http://user:pass@127.0.0.1:3000/', 'file:///etc/passwd', '//external.test/', ' /api', '/bad\\path'])('rejects outside-scope or malformed URL %s before transport', async url => {
    const transport = { send: vi.fn(async (_request: TransportRequest) => raw()) };
    const client = new DeterministicRequestExecutor({ baseUrl: origin, allowedOrigins: [origin], transport });
    await expect(client.execute({ url })).rejects.toMatchObject({ code: 'scope-denied' });
    expect(transport.send).not.toHaveBeenCalled();
  });
  it.each([{ Host: 'external.test' }, { 'Content-Length': '200' }, { Connection: 'upgrade' },
    { Cookie: 'one', cookie: 'two' }, { 'X-Bad': 'value\r\ninjected: yes' }])('rejects ambiguous or unsafe headers', async headers => {
    const client = new DeterministicRequestExecutor({ baseUrl: origin, allowedOrigins: [origin] });
    await expect(client.execute({ url: '/', headers })).rejects.toMatchObject({ code: 'invalid-request' });
  });
  it('bounds request bodies and rejects invalid configuration and scope', async () => {
    const client = new DeterministicRequestExecutor({ baseUrl: origin, allowedOrigins: [origin], maxRequestBytes: 2 });
    await expect(client.execute({ url: '/', body: 'large' })).rejects.toMatchObject({ code: 'invalid-request' });
    expect(() => new RuntimeScope(origin, [`${origin}/path`])).toThrow('scope-denied');
    expect(() => new DeterministicRequestExecutor({ baseUrl: origin, allowedOrigins: [origin], timeoutMs: 0 })).toThrow('invalid-request');
  });
  it('times out an uncooperative transport, respects pre-cancellation, and sanitizes provider errors', async () => {
    const send = vi.fn(async (_request: TransportRequest): Promise<never> => new Promise(() => undefined));
    const client = new DeterministicRequestExecutor({ baseUrl: origin, allowedOrigins: [origin], transport: { send }, timeoutMs: 15 });
    await expect(client.execute({ url: '/' })).rejects.toMatchObject({ code: 'timeout' });
    expect(send.mock.calls[0]![0].signal.aborted).toBe(true);
    await expect(client.execute({ url: '/', signal: AbortSignal.abort() })).rejects.toMatchObject({ code: 'cancelled' });
    expect(send).toHaveBeenCalledOnce();
    const failure = new DeterministicRequestExecutor({ baseUrl: origin, allowedOrigins: [origin], transport: { send: async () => { throw new Error('private-token'); } } });
    await expect(failure.execute({ url: '/' })).rejects.toMatchObject({ message: 'transport-failed' });
  });
  it('does not follow a redirect or retry a failed exchange', async () => {
    const transport = { send: vi.fn(async () => ({ ...raw({ location: ['http://external.test/'] }), status: 302 })) };
    const result = await new DeterministicRequestExecutor({ baseUrl: origin, allowedOrigins: [origin], transport }).execute({ url: '/' });
    expect(result.status).toBe(302); expect(transport.send).toHaveBeenCalledOnce();
  });
});

import { request } from 'node:http';
import { describe, expect, it, vi } from 'vitest';
import { DalfoxAdapter, NucleiAdapter, SqlmapAdapter } from '../src/index.js';
import type { ProcessRunner } from '../src/index.js';
import { input, invocation, raw, response, runner } from './helpers.js';

describe('scanner scope and lifecycle', () => {
  it.each(['https://other.test/search?q=x', 'https://user:secret@target.test/search?q=x', 'file:///tmp/private'])('refuses %s before starting a tool', async url => {
    const start = vi.fn(runner()), data = input({ request: { url } });
    expect((await new NucleiAdapter({ runner: start }).run(data)).outcome).toBe('FAILED');
    expect(start).not.toHaveBeenCalled(); expect(data.executor.execute).not.toHaveBeenCalled();
  });
  it.each(['/other', '//other.test/search', '/search?q=x'])('blocks expanded path, host, and method: %s', async path => {
    const data = input();
    const start: ProcessRunner = async process => {
      const { url } = await invocation(process);
      const local = new URL(url);
      if (path.startsWith('//')) {
        await new Promise<void>(resolve => {
          const outgoing = request({ hostname: local.hostname, port: local.port, path: `https://other.test/search`,
            headers: { host: 'other.test' } }, incoming => { incoming.resume(); incoming.on('end', resolve); });
          outgoing.on('error', () => resolve()); outgoing.end();
        });
      } else await fetch(new URL(path, url), { method: path === '/search?q=x' ? 'POST' : 'GET' });
      return raw(process, url);
    };
    const result = await new NucleiAdapter({ runner: start }).run(data);
    expect(result.error?.code).toBe('scope-denied'); expect(data.executor.execute).not.toHaveBeenCalled();
  });
  it('refuses a CONNECT tunnel', async () => {
    const data = input();
    const result = await new NucleiAdapter({ runner: async process => {
      const { url } = await invocation(process), local = new URL(url);
      await new Promise<void>(resolve => {
        const outgoing = request({ hostname: local.hostname, port: local.port, method: 'CONNECT', path: 'other.test:443' });
        outgoing.on('error', () => resolve()); outgoing.on('connect', (_res, socket) => { socket.destroy(); resolve(); }); outgoing.end();
      }); return raw(process, url);
    } }).run(data);
    expect(result.error?.code).toBe('scope-denied'); expect(data.executor.execute).not.toHaveBeenCalled();
  });
  it('adapts Dalfox HEAD preflight to a counted, approved GET', async () => {
    const data = input({ cweId: 'CWE-79', parameter: { name: 'q', location: 'query' } });
    const result = await new DalfoxAdapter({ runner: async process => {
      const { url } = await invocation(process);
      const received = await fetch(url, { method: 'HEAD' });
      expect(received.status).toBe(200); expect(await received.text()).toBe('');
      return raw(process, url);
    } }).run(data);
    expect(result.outcome).toBe('COMPLETED'); expect(data.executor.execute).toHaveBeenCalledOnce();
    expect(vi.mocked(data.executor.execute).mock.calls[0]?.[0].method).toBe('GET');
  });
  it('forwards a permitted mutation through the private identity executor', async () => {
    const data = input({ parameter: { name: 'q', location: 'query' } });
    const result = await new SqlmapAdapter({ runner: async process => {
      const { url } = await invocation(process), mutation = new URL(url); mutation.searchParams.set('q', "' AND 1=1");
      await fetch(mutation, { headers: { authorization: 'ATTACKER_TOKEN', cookie: 'ATTACKER_COOKIE' } });
      return raw(process, mutation.href);
    } }).run(data);
    expect(result.outcome).toBe('COMPLETED');
    expect(data.executor.execute).toHaveBeenCalledOnce();
    const call = vi.mocked(data.executor.execute).mock.calls[0]![0];
    expect(new URL(call.url).origin).toBe('https://target.test');
    expect(new URL(call.url).searchParams.get('q')).toBe("' AND 1=1");
    expect(call.headers?.authorization).toBe('Bearer PRIVATE_TOKEN'); expect(call.headers?.cookie).toBeUndefined();
  });
  it('does not permit mutation of another parameter', async () => {
    const data = input({ parameter: { name: 'q', location: 'query' } });
    const result = await new SqlmapAdapter({ runner: async process => {
      const { url } = await invocation(process), changed = new URL(url); changed.searchParams.set('keep', 'other');
      await fetch(changed); return raw(process, url);
    } }).run(data);
    expect(result.error?.code).toBe('scope-denied'); expect(data.executor.execute).not.toHaveBeenCalled();
  });
  it.each(['form-body', 'json-body'] as const)('supports bounded %s mutation', async location => {
    const body = location === 'json-body' ? JSON.stringify({ q: 'a', keep: 1 }) : 'q=a&keep=1';
    const data = input({ parameter: { name: 'q', location }, request: { url: 'https://target.test/search', method: 'POST', body } });
    const result = await new SqlmapAdapter({ runner: async process => {
      const { url } = await invocation(process);
      await fetch(url, { method: 'POST', body: location === 'json-body' ? JSON.stringify({ q: "a'", keep: 1 }) : "q=a'&keep=1" });
      return raw(process, url);
    } }).run(data);
    expect(result.outcome).toBe('COMPLETED'); expect(data.executor.execute).toHaveBeenCalledOnce();
  });
  it('counts concurrent requests before transport starts', async () => {
    const data = input({ maxRequests: 1 });
    const result = await new NucleiAdapter({ runner: async process => {
      const { url } = await invocation(process);
      await Promise.allSettled([fetch(url), fetch(url), fetch(url)]); return raw(process, url);
    } }).run(data);
    expect(result.error?.code).toBe('request-limit'); expect(data.executor.execute).toHaveBeenCalledOnce();
  });
  it('does not forward a target redirect to the scanner', async () => {
    const data = input({ executor: { execute: async request => ({ ...response(request), status: 302,
      headers: { location: ['https://other.test/PRIVATE'], refresh: ['0;url=https://other.test'] } }) } });
    const result = await new NucleiAdapter({ runner: async process => {
      const { url } = await invocation(process), received = await fetch(url, { redirect: 'manual' });
      expect(received.status).toBe(302); expect(received.headers.get('location')).toBeNull(); expect(received.headers.get('refresh')).toBeNull();
      return raw(process, url);
    } }).run(data);
    expect(result.outcome).toBe('COMPLETED');
  });
  it('rejects incomplete HTTP bodies rather than producing a clean scan', async () => {
    const data = input({ executor: { execute: async request => ({ ...response(request), body: { ...response(request).body, truncated: true } }) } });
    expect((await new NucleiAdapter({ runner: runner() }).run(data)).error?.code).toBe('incomplete-output');
  });
  it('enforces a deadline even when a custom runner ignores cancellation', async () => {
    const started = Date.now();
    const result = await new NucleiAdapter({ timeoutMs: 50, runner: async () => new Promise(() => undefined) }).run(input());
    expect(result.error?.code).toBe('timeout'); expect(Date.now() - started).toBeLessThan(1000);
  });
  it('cancels in-flight HTTP and revokes the local endpoint after completion', async () => {
    const controller = new AbortController(); let url = '', signal: AbortSignal | undefined;
    const data = input({ signal: controller.signal, executor: { execute: async request => {
      signal = request.signal; controller.abort(); return new Promise(() => undefined);
    } } });
    const result = await new NucleiAdapter({ runner: async process => {
      url = (await invocation(process)).url;
      await fetch(url, { signal: process.signal }); return raw(process, url);
    } }).run(data);
    expect(result.error?.code).toBe('cancelled'); expect(signal?.aborted).toBe(true);
    await expect(fetch(url)).rejects.toThrow();
  });
});

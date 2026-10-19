import { request as httpRequest, validateHeaderName, validateHeaderValue } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { createHash, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import type { ExecutionGuard } from '@agento/core';
import type { HttpRequest, HttpResponse, HttpTransport, RequestExecutor, ResponseCollector,
  ResponseTimings, TransportRequest, TransportResponse } from './contracts.js';
import { bounded, evidenceUrl, freeze, limit, RuntimeError, RuntimeScope } from './safety.js';

export class NormalizedResponseCollector implements ResponseCollector {
  collect(request: { readonly url: string; readonly method: string }, response: TransportResponse, timings: ResponseTimings): HttpResponse {
    return freeze({ id: `http:${randomUUID()}`, ...request, status: response.status,
      headers: structuredClone(response.headers), body: { encoding: 'base64' as const,
        data: Buffer.from(response.body).toString('base64'), byteLength: response.body.byteLength, truncated: response.truncated },
      timings: { ...timings } });
  }
  evidence(response: HttpResponse) {
    return freeze({ responseId: response.id, url: evidenceUrl(response.url), method: response.method, status: response.status,
      body: { sha256: createHash('sha256').update(Buffer.from(response.body.data, 'base64')).digest('hex'),
        byteLength: response.body.byteLength, truncated: response.body.truncated }, timings: { ...response.timings } });
  }
}

/** Node's single-hop client preserves separate Set-Cookie fields and never follows redirects. */
export class NodeHttpTransport implements HttpTransport {
  send(request: TransportRequest): Promise<TransportResponse> {
    return new Promise((resolve, reject) => {
      const started = performance.now();
      const send = new URL(request.url).protocol === 'https:' ? httpsRequest : httpRequest;
      const outgoing = send(request.url, { method: request.method, headers: request.headers, signal: request.signal,
        agent: false, maxHeaderSize: 32_768 }, incoming => {
        const firstByteMs = performance.now() - started;
        const headers: Record<string, string[]> = Object.create(null);
        for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
          const key = incoming.rawHeaders[index]!.toLowerCase();
          (headers[key] ??= []).push(incoming.rawHeaders[index + 1]!);
        }
        const chunks: Buffer[] = [];
        let size = 0, settled = false;
        const finish = (truncated: boolean) => {
          if (settled) return; settled = true;
          resolve({ status: incoming.statusCode!, headers, body: Buffer.concat(chunks), truncated, firstByteMs });
        };
        incoming.on('data', (chunk: Buffer) => {
          const remaining = request.maxBodyBytes - size;
          chunks.push(chunk.subarray(0, Math.max(0, remaining))); size += chunk.length;
          if (size > request.maxBodyBytes) { finish(true); incoming.destroy(); }
        });
        incoming.on('end', () => finish(false));
        incoming.on('error', error => { if (!settled) reject(error); });
        incoming.on('aborted', () => { if (!settled) reject(new RuntimeError('transport-failed')); });
      });
      outgoing.on('error', reject);
      outgoing.on('upgrade', (_response, socket) => { socket.destroy(); reject(new RuntimeError('transport-failed')); });
      outgoing.end(request.body);
    });
  }
}
export interface HttpExecutorOptions {
  readonly baseUrl: string; readonly allowedOrigins: readonly string[];
  readonly timeoutMs?: number; readonly maxBodyBytes?: number; readonly maxRequestBytes?: number;
  readonly transport?: HttpTransport; readonly collector?: ResponseCollector;
  readonly executionGuard?: ExecutionGuard;
}
export class DeterministicRequestExecutor implements RequestExecutor {
  readonly scope: RuntimeScope;
  private readonly timeoutMs: number;
  private readonly maxBodyBytes: number;
  private readonly maxRequestBytes: number;
  private readonly transport: HttpTransport;
  private readonly collector: ResponseCollector;
  constructor(private readonly options: HttpExecutorOptions) {
    this.scope = new RuntimeScope(options.baseUrl, options.allowedOrigins);
    this.timeoutMs = limit(options.timeoutMs ?? 15_000, 600_000);
    this.maxBodyBytes = limit(options.maxBodyBytes ?? 1_048_576, 16_777_216);
    this.maxRequestBytes = limit(options.maxRequestBytes ?? 1_048_576, 16_777_216);
    this.transport = options.transport ?? new NodeHttpTransport();
    this.collector = options.collector ?? new NormalizedResponseCollector();
  }
  withGuard(guard: ExecutionGuard): DeterministicRequestExecutor {
    const previous = this.options.executionGuard;
    return new DeterministicRequestExecutor({ ...this.options, executionGuard: previous ? {
      signal: previous.signal ? AbortSignal.any([previous.signal, ...(guard.signal ? [guard.signal] : [])]) : guard.signal ?? new AbortController().signal,
      assertActive: () => { previous.assertActive(); guard.assertActive(); },
      assertRequest: request => { previous.assertRequest(request); guard.assertRequest(request); },
      assertRedirect: (from, to) => { previous.assertRedirect(from, to); guard.assertRedirect(from, to); },
    } : guard });
  }
  async execute(request: HttpRequest): Promise<HttpResponse> {
    const url = this.scope.assert(request.url), method = request.method ?? 'GET';
    if (!/^[A-Z]+$/.test(method) || ['CONNECT', 'TRACE'].includes(method)
      || request.body !== undefined && (typeof request.body !== 'string' || Buffer.byteLength(request.body) > this.maxRequestBytes)) {
      throw new RuntimeError('invalid-request');
    }
    const headers: Record<string, string> = Object.create(null);
    let bytes = 0;
    try {
      for (const [name, value] of Object.entries(request.headers ?? {})) {
        const key = name.toLowerCase();
        if (typeof value !== 'string' || Object.hasOwn(headers, key)
          || ['host', 'content-length', 'transfer-encoding', 'connection', 'upgrade', 'proxy-authorization', 'proxy-connection', 'expect'].includes(key)) throw new Error();
        validateHeaderName(name); validateHeaderValue(name, value);
        bytes += name.length + Buffer.byteLength(value);
        headers[key] = value;
      }
      if (bytes > 16_384) throw new Error();
    } catch { throw new RuntimeError('invalid-request'); }
    // Policy failures retain their fixed codes and occur before the transport starts.
    this.options.executionGuard?.assertActive();
    if (request.signal?.aborted) throw new RuntimeError('cancelled');
    this.options.executionGuard?.assertRequest({ url, method });
    const controller = new AbortController();
    const cancel = () => controller.abort();
    const sourceSignal = this.options.executionGuard?.signal
      ? AbortSignal.any([this.options.executionGuard.signal, ...(request.signal ? [request.signal] : [])]) : request.signal;
    sourceSignal?.addEventListener('abort', cancel, { once: true });
    if (sourceSignal?.aborted) controller.abort();
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, this.timeoutMs);
    const startedAt = new Date().toISOString(), started = performance.now();
    try {
      if (controller.signal.aborted) throw new RuntimeError('cancelled');
      const response = await bounded(this.transport.send({ url, method, headers: Object.freeze(headers),
        signal: controller.signal, maxBodyBytes: this.maxBodyBytes,
        ...(request.body !== undefined ? { body: request.body } : {}) }), controller.signal);
      if (!Number.isInteger(response.status) || response.status < 100 || response.status > 599
        || response.body.byteLength > this.maxBodyBytes || !Number.isFinite(response.firstByteMs) || response.firstByteMs < 0) throw new Error();
      if (response.status >= 300 && response.status < 400) {
        const locations = Object.entries(response.headers).filter(([key]) => key.toLowerCase() === 'location').flatMap(([, values]) => values);
        for (const location of locations) this.options.executionGuard?.assertRedirect(url, new URL(location, url).href);
      }
      return this.collector.collect({ url, method }, response, { startedAt,
        firstByteMs: response.firstByteMs, durationMs: performance.now() - started });
    } catch {
      throw new RuntimeError(timedOut ? 'timeout' : controller.signal.aborted ? 'cancelled' : 'transport-failed');
    } finally { clearTimeout(timer); sourceSignal?.removeEventListener('abort', cancel); }
  }
}

import { afterEach, describe, expect, it, vi } from 'vitest';
import type { JsonValue, ModelGenerationRequest } from '@agento/core';
import { OpenAIModelProvider, createOpenAIModelProvider } from '../src/index.js';

const KEY = 'test-only-api-key';
const SECRET = 'private-http-error-credential';
const usage = { input_tokens: 123, output_tokens: 45 };
const request = (overrides: Partial<ModelGenerationRequest> = {}): ModelGenerationRequest => ({
  instructions: 'Choose one next action from the normalized page.',
  input: { page: { title: 'Sign in', elements: [] } },
  schema: { name: 'action', jsonSchema: { type: 'object', properties: { done: { type: 'boolean' } }, required: ['done'], additionalProperties: false } },
  maxOutputTokens: 100,
  timeoutMs: 1000,
  signal: new AbortController().signal,
  ...overrides,
});
const message = (content: unknown = { type: 'output_text', text: '{"done":true}' }) => ({
  type: 'message', role: 'assistant', status: 'completed', content: [content],
});
const envelope = (overrides: Record<string, unknown> = {}) => ({
  object: 'response', status: 'completed', output: [message()], usage, ...overrides,
});
const response = (value: unknown, init: ResponseInit = {}): Response => new Response(JSON.stringify(value), {
  headers: { 'Content-Type': 'application/json' }, ...init,
});
const provider = (fetch: typeof globalThis.fetch, options: Partial<ConstructorParameters<typeof OpenAIModelProvider>[0]> = {}) => new OpenAIModelProvider({
  model: 'caller-chosen-model', resolveApiKey: () => KEY, fetch, ...options,
});
const mockFetch = (value: unknown = envelope()) => vi.fn<typeof globalThis.fetch>(async () => response(value));

afterEach(() => { vi.useRealTimers(); });

describe('OpenAIModelProvider', () => {
  it('sends only a bounded structured-output request to the official Responses endpoint', async () => {
    const fetch = mockFetch();
    const instance = provider(fetch);
    const result = await instance.generateStructured(request());
    expect(instance.id).toBe('openai');
    expect(result).toEqual({ status: 'completed', value: { done: true }, usage: { inputTokens: 123, outputTokens: 45 } });
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, options] = fetch.mock.calls[0]!;
    expect(url).toBe('https://api.openai.com/v1/responses');
    expect(options).toMatchObject({ method: 'POST', redirect: 'error', headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' } });
    expect(options?.signal).toBeInstanceOf(AbortSignal);
    const body = JSON.parse(String(options?.body));
    expect(body).toEqual({
      model: 'caller-chosen-model', instructions: request().instructions,
      input: [{ role: 'user', content: [{ type: 'input_text', text: JSON.stringify(request().input) }] }],
      text: { format: { type: 'json_schema', name: 'action', schema: request().schema.jsonSchema, strict: true } },
      max_output_tokens: 100, store: false, stream: false, background: false, truncation: 'disabled', tools: [],
    });
    expect(String(options?.body)).not.toContain(KEY);
    expect(JSON.stringify(result)).not.toContain(KEY);
  });

  it('keeps reasoning metadata and raw response objects inside the provider', async () => {
    const fetch = mockFetch(envelope({ id: SECRET, output: [{ type: 'reasoning', summary: [{ text: SECRET }] }, message()] }));
    const result = await provider(fetch).generateStructured(request());
    expect(result.status).toBe('completed');
    expect(JSON.stringify(result)).not.toContain(SECRET);
  });

  it.each([
    [401, 'OPENAI_AUTHENTICATION_FAILED'], [403, 'OPENAI_AUTHENTICATION_FAILED'],
    [429, 'OPENAI_RATE_LIMITED'], [500, 'OPENAI_UNAVAILABLE'], [400, 'OPENAI_REQUEST_REJECTED'],
    [302, 'OPENAI_REQUEST_REJECTED'],
  ])('sanitizes HTTP %i without forwarding server text', async (status, code) => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () => response({ error: { message: SECRET } }, { status }));
    expect(await provider(fetch).generateStructured(request())).toEqual({ status: 'failed', code });
  });

  it('sanitizes transport exceptions including their credential-bearing text', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () => { throw new Error(SECRET); });
    expect(await provider(fetch).generateStructured(request())).toEqual({ status: 'failed', code: 'OPENAI_TRANSPORT_FAILED' });
  });

  it.each([undefined, '', 'bad key', 'bad\nkey'])('fails closed on an unavailable or invalid backend API key', async (key) => {
    const fetch = mockFetch();
    const result = await provider(fetch, { resolveApiKey: () => key }).generateStructured(request());
    expect(result).toEqual({ status: 'failed', code: 'OPENAI_API_KEY_UNAVAILABLE' });
    expect(fetch).not.toHaveBeenCalled();
  });

  it('sanitizes key resolver errors without making an API request', async () => {
    const fetch = mockFetch();
    expect(await provider(fetch, { resolveApiKey: () => { throw new Error(SECRET); } }).generateStructured(request()))
      .toEqual({ status: 'failed', code: 'OPENAI_API_KEY_UNAVAILABLE' });
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([
    [{ status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' } }, 'OPENAI_INCOMPLETE_RESPONSE'],
    [{ status: 'failed', error: { message: SECRET } }, 'OPENAI_RESPONSE_FAILED'],
    [{ status: 'cancelled' }, 'OPENAI_RESPONSE_FAILED'],
    [{ status: 'queued' }, 'OPENAI_UNSUPPORTED_RESPONSE'],
    [{ object: 'chat.completion' }, 'OPENAI_MALFORMED_RESPONSE'],
    [{ usage: null }, 'OPENAI_MALFORMED_RESPONSE'],
    [{ usage: { input_tokens: -1, output_tokens: 45 } }, 'OPENAI_MALFORMED_RESPONSE'],
    [{ output: [] }, 'OPENAI_MALFORMED_RESPONSE'],
    [{ output: [message(), message()] }, 'OPENAI_MALFORMED_RESPONSE'],
    [{ output: [{ type: 'function_call', arguments: SECRET }] }, 'OPENAI_UNSUPPORTED_OUTPUT'],
    [{ output: [message({ type: 'output_text', text: 'not json' })] }, 'OPENAI_INVALID_JSON'],
    [{ output: [message({ type: 'output_text', text: '{"overflow":1e400}' })] }, 'OPENAI_INVALID_JSON'],
    [{ output: [message({ type: 'image', data: SECRET })] }, 'OPENAI_UNSUPPORTED_OUTPUT'],
    [{ usage: { input_tokens: 123, output_tokens: 101 } }, 'OPENAI_OUTPUT_BUDGET_EXCEEDED'],
    [{ incomplete_details: { reason: SECRET } }, 'OPENAI_MALFORMED_RESPONSE'],
  ])('rejects unsupported or malformed envelopes %#', async (overrides, code) => {
    const result = await provider(mockFetch(envelope(overrides))).generateStructured(request());
    expect(result.status).toBe('failed');
    if (result.status !== 'completed') expect(result.code).toBe(code);
    expect(JSON.stringify(result)).not.toContain(SECRET);
  });

  it('returns a normalized refusal and preserves accounting without copying the refusal message', async () => {
    const result = await provider(mockFetch(envelope({ output: [message({ type: 'refusal', refusal: SECRET })] }))).generateStructured(request());
    expect(result).toEqual({ status: 'refused', code: 'OPENAI_REFUSED', usage: { inputTokens: 123, outputTokens: 45 } });
  });

  it('preserves valid usage on an incomplete response', async () => {
    expect(await provider(mockFetch(envelope({ status: 'incomplete' }))).generateStructured(request()))
      .toEqual({ status: 'failed', code: 'OPENAI_INCOMPLETE_RESPONSE', usage: { inputTokens: 123, outputTokens: 45 } });
  });

  it('rejects invalid UTF-8 and malformed outer JSON', async () => {
    for (const body of ['not json', new Uint8Array([255])]) {
      const fetch = vi.fn<typeof globalThis.fetch>(async () => new Response(body, { headers: { 'Content-Type': 'application/json' } }));
      const result = await provider(fetch).generateStructured(request());
      expect(result.status).toBe('failed');
      expect(JSON.stringify(result)).not.toContain(SECRET);
    }
  });

  it('rejects non-JSON HTTP content without consuming it', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () => new Response(SECRET, { headers: { 'Content-Type': 'text/html' } }));
    expect(await provider(fetch).generateStructured(request())).toEqual({ status: 'failed', code: 'OPENAI_MALFORMED_RESPONSE' });
  });

  it('rejects a redirected response even if an injected transport follows it', async () => {
    const redirected = response(envelope());
    Object.defineProperty(redirected, 'redirected', { value: true });
    const fetch = vi.fn<typeof globalThis.fetch>(async () => redirected);
    expect(await provider(fetch).generateStructured(request())).toEqual({ status: 'failed', code: 'OPENAI_UNSUPPORTED_REDIRECT' });
  });

  it('bounds streamed bodies without trusting content-length', async () => {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new Uint8Array(64)); controller.enqueue(new Uint8Array(64)); },
      cancel() { cancelled = true; },
    });
    const fetch = vi.fn<typeof globalThis.fetch>(async () => new Response(stream, { headers: { 'Content-Type': 'application/json' } }));
    expect(await provider(fetch, { maxResponseBytes: 100 }).generateStructured(request()))
      .toEqual({ status: 'failed', code: 'OPENAI_RESPONSE_TOO_LARGE' });
    expect(cancelled).toBe(true);
  });

  it('rejects excessive content-length before reading the body', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () => response(envelope(), { headers: { 'Content-Type': 'application/json', 'Content-Length': '10000000' } }));
    expect(await provider(fetch).generateStructured(request())).toEqual({ status: 'failed', code: 'OPENAI_RESPONSE_TOO_LARGE' });
  });

  it('bounds serialized request bytes before resolving credentials or invoking the transport', async () => {
    const fetch = mockFetch();
    const resolveApiKey = vi.fn(() => KEY);
    expect(await provider(fetch, { maxRequestBytes: 100, resolveApiKey }).generateStructured(request()))
      .toEqual({ status: 'failed', code: 'OPENAI_REQUEST_TOO_LARGE' });
    expect(resolveApiKey).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([
    { maxOutputTokens: 0 }, { maxOutputTokens: 100_000 }, { timeoutMs: 0 }, { timeoutMs: 500_000 },
    { instructions: '' }, { input: { numeric: Number.NaN } },
    { schema: { name: 'invalid name', jsonSchema: {} } },
  ])('rejects invalid requests before calling the provider %#', async (overrides) => {
    const fetch = mockFetch();
    expect(await provider(fetch).generateStructured(request(overrides))).toEqual({ status: 'failed', code: 'OPENAI_INVALID_REQUEST' });
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects cyclic JSON and accessor properties without executing them', async () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    const getter = vi.fn(() => SECRET);
    const accessor = Object.defineProperty({}, 'secret', { get: getter, enumerable: true });
    const fetch = mockFetch();
    for (const input of [cyclic, accessor]) {
      expect(await provider(fetch).generateStructured(request({ input: input as JsonValue })))
        .toEqual({ status: 'failed', code: 'OPENAI_INVALID_REQUEST' });
    }
    expect(getter).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('does not resolve keys or make requests for pre-aborted generations', async () => {
    const fetch = mockFetch();
    const resolveApiKey = vi.fn(() => KEY);
    expect(await provider(fetch, { resolveApiKey }).generateStructured(request({ signal: AbortSignal.abort(SECRET) })))
      .toEqual({ status: 'failed', code: 'OPENAI_ABORTED' });
    expect(resolveApiKey).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('enforces timeouts even when the key resolver ignores abort', async () => {
    vi.useFakeTimers();
    const fetch = mockFetch();
    const result = provider(fetch, { resolveApiKey: () => new Promise(() => {}) }).generateStructured(request({ timeoutMs: 10 }));
    await vi.advanceTimersByTimeAsync(10);
    expect(await result).toEqual({ status: 'timeout', code: 'OPENAI_TIMEOUT' });
    expect(fetch).not.toHaveBeenCalled();
  });

  it('enforces timeouts and aborts the transport even when it does not settle', async () => {
    vi.useFakeTimers();
    const fetch = vi.fn<typeof globalThis.fetch>(() => new Promise(() => {}));
    const result = provider(fetch).generateStructured(request({ timeoutMs: 10 }));
    await vi.advanceTimersByTimeAsync(10);
    expect(await result).toEqual({ status: 'timeout', code: 'OPENAI_TIMEOUT' });
    expect(fetch.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
  });

  it('honors caller cancellation without exposing its reason', async () => {
    const controller = new AbortController();
    const fetch = vi.fn<typeof globalThis.fetch>(() => new Promise(() => {}));
    const result = provider(fetch).generateStructured(request({ signal: controller.signal }));
    controller.abort(SECRET);
    expect(await result).toEqual({ status: 'failed', code: 'OPENAI_ABORTED' });
  });

  it('does not send a late request after timed-out key resolution completes', async () => {
    vi.useFakeTimers();
    let resolve!: (key: string) => void;
    const key = new Promise<string>((done) => { resolve = done; });
    const fetch = mockFetch();
    const result = provider(fetch, { resolveApiKey: () => key }).generateStructured(request({ timeoutMs: 10 }));
    await vi.advanceTimersByTimeAsync(10);
    expect(await result).toEqual({ status: 'timeout', code: 'OPENAI_TIMEOUT' });
    resolve(KEY);
    await Promise.resolve();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('requires an explicit safe model id and bounded positive integer limits', () => {
    expect(() => provider(mockFetch(), { model: '' })).toThrow('Invalid OpenAI provider options.');
    expect(() => provider(mockFetch(), { model: 'bad\nmodel' })).toThrow('Invalid OpenAI provider options.');
    expect(() => provider(mockFetch(), { maxTimeoutMs: Infinity })).toThrow('Invalid OpenAI provider limits.');
    expect(() => provider(mockFetch(), { maxResponseBytes: 3_000_000 })).toThrow('Invalid OpenAI provider limits.');
    expect(() => provider(mockFetch(), { endpoint: 'ftp://invalid-scheme.test' })).toThrow('Invalid OpenAI provider options.');
    expect(() => provider(mockFetch(), { endpoint: 'not-a-url' })).toThrow('Invalid OpenAI provider options.');
  });

  it('supports custom OpenAI-compatible endpoints like Ollama Cloud', async () => {
    const fetch = mockFetch();
    const customEndpoint = 'https://ollama.com/v1/responses';
    const instance = provider(fetch, { model: 'gemma4:31b', endpoint: customEndpoint });
    const result = await instance.generateStructured(request());
    expect(result.status).toBe('completed');
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url] = fetch.mock.calls[0]!;
    expect(url).toBe(customEndpoint);
  });

  it('parses JSON wrapped in markdown code fences from models like gemma4:31b', async () => {
    const fencedContent = { type: 'output_text', text: '```json\n{\n  "done": true\n}\n```' };
    const fetch = mockFetch(envelope({ output: [message(fencedContent)] }));
    const instance = provider(fetch, { model: 'gemma4:31b' });
    const result = await instance.generateStructured(request());
    expect(result).toEqual({ status: 'completed', value: { done: true }, usage: { inputTokens: 123, outputTokens: 45 } });
  });

  it('creates provider from environment variables with safe defaults', async () => {
    const prevKey = process.env.OPENAI_API_KEY;
    const prevBase = process.env.OPENAI_BASE_URL;
    const prevModel = process.env.OPENAI_MODEL;
    try {
      process.env.OPENAI_API_KEY = 'env-secret-key';
      process.env.OPENAI_BASE_URL = 'https://ollama.com/v1';
      process.env.OPENAI_MODEL = 'gemma4:31b';
      const fetch = mockFetch();
      const instance = createOpenAIModelProvider({ fetch });
      const result = await instance.generateStructured(request());
      expect(result.status).toBe('completed');
      expect(fetch).toHaveBeenCalledTimes(1);
      const [url, opts] = fetch.mock.calls[0]!;
      expect(url).toBe('https://ollama.com/v1/responses');
      expect(opts?.headers).toMatchObject({ Authorization: 'Bearer env-secret-key' });
    } finally {
      if (prevKey === undefined) delete process.env.OPENAI_API_KEY; else process.env.OPENAI_API_KEY = prevKey;
      if (prevBase === undefined) delete process.env.OPENAI_BASE_URL; else process.env.OPENAI_BASE_URL = prevBase;
      if (prevModel === undefined) delete process.env.OPENAI_MODEL; else process.env.OPENAI_MODEL = prevModel;
    }
  });
});


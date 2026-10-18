const DEFAULT_ENDPOINT = 'https://api.openai.com/v1/responses';
const DEFAULT_REQUEST_BYTES = 262_144;
const DEFAULT_RESPONSE_BYTES = 524_288;
const DEFAULT_OUTPUT_TOKENS = 16_384;
const DEFAULT_TIMEOUT_MS = 120_000;
class ProviderFailure extends Error {
    code;
    constructor(code) {
        super(code);
        this.code = code;
    }
}
function record(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
/** Reject non-JSON values, accessors, excessive nesting and cyclic caller input. */
function jsonSafe(value, depth = 0, seen = new Set(), count = { nodes: 0, bytes: 0, maxBytes: 2_097_152 }) {
    if (++count.nodes > 50_000 || depth > 64)
        return false;
    if (typeof value === 'string') {
        if (value.length > count.maxBytes)
            return false;
        count.bytes += Buffer.byteLength(value, 'utf8');
        return count.bytes <= count.maxBytes;
    }
    if (value === null || typeof value === 'boolean')
        return true;
    if (typeof value === 'number')
        return Number.isFinite(value);
    if (typeof value !== 'object' || seen.has(value))
        return false;
    if (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
        return false;
    seen.add(value);
    for (const key of Reflect.ownKeys(value)) {
        if (Array.isArray(value) && key === 'length')
            continue;
        if (typeof key !== 'string')
            return false;
        if (key.length > count.maxBytes)
            return false;
        count.bytes += Buffer.byteLength(key, 'utf8');
        if (count.bytes > count.maxBytes)
            return false;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor || !('value' in descriptor) || !jsonSafe(descriptor.value, depth + 1, seen, count))
            return false;
    }
    seen.delete(value);
    return true;
}
function positiveInteger(value, max) {
    return Number.isSafeInteger(value) && Number(value) > 0 && Number(value) <= max;
}
function usageFrom(value) {
    if (!record(value) || !Number.isSafeInteger(value.input_tokens) || !Number.isSafeInteger(value.output_tokens)
        || Number(value.input_tokens) < 0 || Number(value.output_tokens) < 0)
        return undefined;
    return { inputTokens: Number(value.input_tokens), outputTokens: Number(value.output_tokens) };
}
function failure(code, usage) {
    return { status: 'failed', code, ...(usage ? { usage } : {}) };
}
function extractJsonText(text) {
    const trimmed = text.trim();
    const match = /^```(?:json)?\s*([\s\S]*?)\s*```$/i.exec(trimmed);
    return match?.[1] ? match[1].trim() : trimmed;
}
function parseEnvelope(envelope, maxOutputTokens) {
    if (!record(envelope) || envelope.object !== 'response')
        return failure('OPENAI_MALFORMED_RESPONSE');
    const usage = usageFrom(envelope.usage);
    if (usage && usage.outputTokens > maxOutputTokens)
        return failure('OPENAI_OUTPUT_BUDGET_EXCEEDED', usage);
    if (envelope.status === 'incomplete')
        return failure('OPENAI_INCOMPLETE_RESPONSE', usage);
    if (envelope.status === 'failed' || envelope.status === 'cancelled')
        return failure('OPENAI_RESPONSE_FAILED', usage);
    if (envelope.status !== 'completed')
        return failure('OPENAI_UNSUPPORTED_RESPONSE', usage);
    if (envelope.error != null || envelope.incomplete_details != null || !Array.isArray(envelope.output)) {
        return failure('OPENAI_MALFORMED_RESPONSE', usage);
    }
    let outputText;
    let messages = 0;
    let refused = false;
    for (const item of envelope.output) {
        if (!record(item))
            return failure('OPENAI_MALFORMED_RESPONSE', usage);
        // Reasoning metadata stays inside the adapter. No tools are sent or accepted.
        if (item.type === 'reasoning')
            continue;
        if (item.type !== 'message')
            return failure('OPENAI_UNSUPPORTED_OUTPUT', usage);
        if (++messages > 1 || item.role !== 'assistant' || item.status !== 'completed' || !Array.isArray(item.content) || item.content.length !== 1) {
            return failure('OPENAI_MALFORMED_RESPONSE', usage);
        }
        const content = item.content[0];
        if (!record(content))
            return failure('OPENAI_MALFORMED_RESPONSE', usage);
        if (content.type === 'refusal' && typeof content.refusal === 'string')
            refused = true;
        else if (content.type === 'output_text' && typeof content.text === 'string' && content.text.length > 0)
            outputText = content.text;
        else
            return failure('OPENAI_UNSUPPORTED_OUTPUT', usage);
    }
    if (refused)
        return { status: 'refused', code: 'OPENAI_REFUSED', ...(usage ? { usage } : {}) };
    if (!usage || outputText === undefined)
        return failure('OPENAI_MALFORMED_RESPONSE', usage);
    try {
        const rawJson = extractJsonText(outputText);
        const value = JSON.parse(rawJson);
        if (!jsonSafe(value))
            return failure('OPENAI_INVALID_JSON', usage);
        return { status: 'completed', value, usage };
    }
    catch {
        return failure('OPENAI_INVALID_JSON', usage);
    }
}
async function boundedBody(response, maxBytes, signal) {
    const advertised = response.headers.get('content-length');
    if (advertised !== null && (!/^\d+$/.test(advertised) || Number(advertised) > maxBytes)) {
        void response.body?.cancel().catch(() => { });
        throw new ProviderFailure('OPENAI_RESPONSE_TOO_LARGE');
    }
    if (!response.body)
        throw new ProviderFailure('OPENAI_MALFORMED_RESPONSE');
    const reader = response.body.getReader();
    const chunks = [];
    let bytes = 0;
    try {
        while (true) {
            signal.throwIfAborted();
            const chunk = await reader.read();
            if (chunk.done)
                break;
            bytes += chunk.value.byteLength;
            if (bytes > maxBytes)
                throw new ProviderFailure('OPENAI_RESPONSE_TOO_LARGE');
            chunks.push(chunk.value);
        }
        const body = new Uint8Array(bytes);
        let offset = 0;
        for (const chunk of chunks) {
            body.set(chunk, offset);
            offset += chunk.byteLength;
        }
        return new TextDecoder('utf-8', { fatal: true }).decode(body);
    }
    finally {
        void reader.cancel().catch(() => { });
        reader.releaseLock();
    }
}
/** Optional provider; generation never executes browser actions or confirms findings. */
export class OpenAIModelProvider {
    options;
    id = 'openai';
    endpoint;
    transport;
    maxRequestBytes;
    maxResponseBytes;
    maxOutputTokens;
    maxTimeoutMs;
    constructor(options) {
        this.options = options;
        if (typeof options.model !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}$/.test(options.model)
            || typeof options.resolveApiKey !== 'function' || (options.fetch !== undefined && typeof options.fetch !== 'function')) {
            throw new Error('Invalid OpenAI provider options.');
        }
        if (options.endpoint !== undefined) {
            if (typeof options.endpoint !== 'string' || options.endpoint.trim().length === 0) {
                throw new Error('Invalid OpenAI provider options.');
            }
            try {
                const parsed = new URL(options.endpoint);
                if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
                    throw new Error('Invalid OpenAI provider options.');
                }
            }
            catch {
                throw new Error('Invalid OpenAI provider options.');
            }
        }
        this.endpoint = options.endpoint ?? DEFAULT_ENDPOINT;
        this.transport = options.fetch ?? globalThis.fetch;
        this.maxRequestBytes = options.maxRequestBytes ?? DEFAULT_REQUEST_BYTES;
        this.maxResponseBytes = options.maxResponseBytes ?? DEFAULT_RESPONSE_BYTES;
        this.maxOutputTokens = options.maxOutputTokens ?? DEFAULT_OUTPUT_TOKENS;
        this.maxTimeoutMs = options.maxTimeoutMs ?? DEFAULT_TIMEOUT_MS;
        if (!positiveInteger(this.maxRequestBytes, 1_048_576) || !positiveInteger(this.maxResponseBytes, 2_097_152)
            || !positiveInteger(this.maxOutputTokens, 65_536) || !positiveInteger(this.maxTimeoutMs, 300_000)) {
            throw new Error('Invalid OpenAI provider limits.');
        }
    }
    async generateStructured(request) {
        let body;
        try {
            if (!record(request) || typeof request.instructions !== 'string' || request.instructions.length === 0
                || request.instructions.length > this.maxRequestBytes
                || !record(request.schema) || typeof request.schema.name !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(request.schema.name)
                || !record(request.schema.jsonSchema)
                || !jsonSafe(request.schema.jsonSchema, 0, new Set(), { nodes: 0, bytes: 0, maxBytes: this.maxRequestBytes })
                || !jsonSafe(request.input, 0, new Set(), { nodes: 0, bytes: 0, maxBytes: this.maxRequestBytes })
                || !positiveInteger(request.maxOutputTokens, this.maxOutputTokens) || !positiveInteger(request.timeoutMs, this.maxTimeoutMs)
                || !(request.signal instanceof AbortSignal))
                return failure('OPENAI_INVALID_REQUEST');
            body = JSON.stringify({
                model: this.options.model,
                instructions: request.instructions,
                input: [{ role: 'user', content: [{ type: 'input_text', text: JSON.stringify(request.input) }] }],
                text: { format: { type: 'json_schema', name: request.schema.name, schema: request.schema.jsonSchema, strict: true } },
                max_output_tokens: request.maxOutputTokens,
                store: false,
                stream: false,
                background: false,
                truncation: 'disabled',
                tools: [],
            });
            if (Buffer.byteLength(body, 'utf8') > this.maxRequestBytes)
                return failure('OPENAI_REQUEST_TOO_LARGE');
        }
        catch {
            return failure('OPENAI_INVALID_REQUEST');
        }
        if (request.signal.aborted)
            return failure('OPENAI_ABORTED');
        const controller = new AbortController();
        let timedOut = false;
        const onCallerAbort = () => controller.abort();
        request.signal.addEventListener('abort', onCallerAbort, { once: true });
        const timer = setTimeout(() => { timedOut = true; controller.abort(); }, request.timeoutMs);
        let onAbort = () => { };
        const aborted = new Promise((_, reject) => {
            onAbort = () => reject(new ProviderFailure('OPENAI_ABORTED'));
            controller.signal.addEventListener('abort', onAbort, { once: true });
        });
        try {
            return await Promise.race([this.generate(body, request, controller.signal), aborted]);
        }
        catch (error) {
            if (timedOut)
                return { status: 'timeout', code: 'OPENAI_TIMEOUT' };
            if (controller.signal.aborted)
                return failure('OPENAI_ABORTED');
            return failure(error instanceof ProviderFailure ? error.code : 'OPENAI_TRANSPORT_FAILED');
        }
        finally {
            clearTimeout(timer);
            request.signal.removeEventListener('abort', onCallerAbort);
            controller.signal.removeEventListener('abort', onAbort);
        }
    }
    async generate(body, request, signal) {
        let key;
        try {
            key = await this.options.resolveApiKey(signal);
        }
        catch {
            throw new ProviderFailure('OPENAI_API_KEY_UNAVAILABLE');
        }
        signal.throwIfAborted();
        if (typeof key !== 'string' || key.trim().length === 0 || key.length > 8_192 || /[\s\u0000-\u001f\u007f]/.test(key)) {
            throw new ProviderFailure('OPENAI_API_KEY_UNAVAILABLE');
        }
        const response = await this.transport(this.endpoint, {
            method: 'POST',
            headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
            body,
            signal,
            redirect: 'error',
        });
        signal.throwIfAborted();
        if (response.redirected || (response.url && response.url !== this.endpoint)) {
            void response.body?.cancel().catch(() => { });
            throw new ProviderFailure('OPENAI_UNSUPPORTED_REDIRECT');
        }
        if (!response.ok) {
            void response.body?.cancel().catch(() => { });
            const code = response.status === 401 || response.status === 403 ? 'OPENAI_AUTHENTICATION_FAILED'
                : response.status === 429 ? 'OPENAI_RATE_LIMITED'
                    : response.status >= 500 ? 'OPENAI_UNAVAILABLE' : 'OPENAI_REQUEST_REJECTED';
            throw new ProviderFailure(code);
        }
        if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '')) {
            void response.body?.cancel().catch(() => { });
            throw new ProviderFailure('OPENAI_MALFORMED_RESPONSE');
        }
        const text = await boundedBody(response, this.maxResponseBytes, signal);
        let envelope;
        try {
            envelope = JSON.parse(text);
        }
        catch {
            throw new ProviderFailure('OPENAI_MALFORMED_RESPONSE');
        }
        return parseEnvelope(envelope, request.maxOutputTokens);
    }
}
/** Create an OpenAI or Ollama Cloud compatible model provider using environment variables. */
export function createOpenAIModelProvider(options) {
    const model = options?.model ?? process.env.OPENAI_MODEL ?? process.env.OLLAMA_MODEL ?? 'gemma4:31b';
    const rawBase = options?.endpoint ?? process.env.OPENAI_BASE_URL ?? process.env.OLLAMA_BASE_URL;
    const endpoint = rawBase
        ? (rawBase.endsWith('/responses') ? rawBase : `${rawBase.replace(/\/+$/, '')}/responses`)
        : undefined;
    const resolveApiKey = options?.resolveApiKey ?? (() => process.env.OPENAI_API_KEY ?? process.env.OLLAMA_API_KEY);
    return new OpenAIModelProvider({
        ...options,
        model,
        ...(endpoint ? { endpoint } : {}),
        resolveApiKey,
    });
}

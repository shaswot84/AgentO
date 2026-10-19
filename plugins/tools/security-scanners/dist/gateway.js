import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { RuntimeScope } from '@agento/runtime';
import { ScannerError } from './contracts.js';
const hop = new Set(['host', 'connection', 'proxy-connection', 'proxy-authorization', 'transfer-encoding',
    'content-length', 'upgrade', 'expect', 'trailer', 'te']);
const digest = (value) => createHash('sha256').update(value).digest('hex');
/** A local origin, never an unrestricted forward proxy or CONNECT tunnel. */
export async function openGateway(input, signal, headPreflight = false) {
    const scope = new RuntimeScope(input.project.baseUrl, input.project.allowedOrigins);
    const target = new URL(scope.assert(input.request.url));
    const method = input.request.method ?? 'GET';
    if (!/^[A-Z]+$/.test(method) || ['TRACE', 'CONNECT'].includes(method)
        || !Number.isSafeInteger(input.maxRequests) || input.maxRequests < 1 || input.maxRequests > 1024
        || input.request.body !== undefined && (typeof input.request.body !== 'string' || Buffer.byteLength(input.request.body) > 1_048_576)) {
        throw new ScannerError('invalid-input');
    }
    const trustedHeaders = Object.create(null);
    for (const [key, value] of Object.entries(input.request.headers ?? {})) {
        if (hop.has(key.toLowerCase()) || typeof value !== 'string' || /[\r\n]/.test(key + value))
            throw new ScannerError('invalid-input');
        trustedHeaders[key.toLowerCase()] = value;
    }
    validateParameter(input, target);
    const exchanges = [], tasks = new Set();
    const controller = new AbortController();
    let failure, remaining = input.maxRequests, active = true, origin = '';
    const fail = (code) => { failure ??= new ScannerError(code); controller.abort(); };
    const server = createServer({ maxHeaderSize: 32_768 }, (incoming, outgoing) => {
        const task = handle(incoming, outgoing).catch(() => { fail('transport-failed'); outgoing.destroy(); });
        tasks.add(task);
        void task.finally(() => tasks.delete(task));
    });
    server.requestTimeout = 5000;
    server.headersTimeout = 5000;
    server.keepAliveTimeout = 1;
    server.on('connect', (_request, socket) => { fail('scope-denied'); socket.destroy(); });
    server.on('upgrade', (_request, socket) => { fail('scope-denied'); socket.destroy(); });
    server.on('clientError', (error, socket) => {
        // Scanner connection pools can reset an unused socket during normal shutdown.
        if (error.code !== 'ECONNRESET')
            fail('invalid-input');
        socket.destroy();
    });
    const abort = () => { controller.abort(); server.closeAllConnections(); };
    signal.addEventListener('abort', abort, { once: true });
    try {
        await new Promise((resolve, reject) => {
            server.once('error', reject);
            server.listen(0, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); });
        });
        const address = server.address();
        if (!address || typeof address === 'string')
            throw new ScannerError('transport-failed');
        origin = `http://127.0.0.1:${address.port}`;
        if (signal.aborted)
            throw new ScannerError('cancelled');
    }
    catch {
        signal.removeEventListener('abort', abort);
        server.close();
        throw new ScannerError(signal.aborted ? 'cancelled' : 'transport-failed');
    }
    async function handle(incoming, outgoing) {
        try {
            if (!active || signal.aborted || controller.signal.aborted)
                throw new ScannerError('cancelled');
            // Absolute-form proxy traffic is permitted only to this invocation's local origin.
            if (!incoming.url?.startsWith('/') && !incoming.url?.startsWith(`${origin}/`))
                throw new ScannerError('scope-denied');
            const local = new URL(incoming.url, origin);
            const localHead = headPreflight && method === 'GET' && incoming.method === 'HEAD';
            if (local.origin !== origin || local.pathname !== target.pathname || incoming.method !== method && !localHead
                || incoming.headers.host !== new URL(origin).host || local.username || local.password)
                throw new ScannerError('scope-denied');
            if (remaining-- <= 0)
                throw new ScannerError('request-limit');
            const chunks = [];
            let size = 0;
            for await (const chunk of incoming) {
                size += chunk.length;
                if (size > 1_048_576)
                    throw new ScannerError('invalid-input');
                chunks.push(Buffer.from(chunk));
            }
            const body = Buffer.concat(chunks).toString('utf8');
            restrictMutation(input, target, local, body);
            const remote = new URL(target);
            remote.search = local.search;
            const headers = Object.create(null);
            for (const [key, value] of Object.entries(incoming.headers)) {
                if (!hop.has(key) && !['authorization', 'cookie'].includes(key) && typeof value === 'string')
                    headers[key] = value;
            }
            // Credentials and host-provided session context cannot be changed by the external tool.
            Object.assign(headers, trustedHeaders);
            const request = { url: remote.href, method, headers,
                ...(body || input.request.body !== undefined ? { body } : {}),
                signal: AbortSignal.any([signal, controller.signal]) };
            const response = await bounded(input.executor.execute(request), request.signal);
            if (!active || signal.aborted || controller.signal.aborted)
                throw new ScannerError('cancelled');
            const actual = new URL(response.url);
            if (actual.origin !== target.origin || actual.pathname !== target.pathname || response.method !== method)
                throw new ScannerError('scope-denied');
            scope.assert(response.url);
            checkResponse(response);
            const bytes = Buffer.from(response.body.data, 'base64');
            exchanges.push({ responseId: `response:${digest(response.id)}`, method, status: response.status,
                requestDigest: digest(JSON.stringify([request.url, method, body])), bodyDigest: digest(bytes), byteLength: bytes.length });
            // Redirects are observations only. Never give a scanner a new navigation target.
            const blocked = new Set([...hop, 'location', 'refresh', 'alt-svc',
                ...(response.headers.connection ?? []).flatMap(value => value.split(',').map(name => name.trim().toLowerCase()))]);
            for (const [key, value] of Object.entries(response.headers))
                if (!blocked.has(key.toLowerCase()))
                    outgoing.setHeader(key, [...value]);
            outgoing.writeHead(response.status);
            outgoing.end(localHead ? undefined : bytes);
        }
        catch (error) {
            if (!signal.aborted)
                fail(error instanceof ScannerError ? error.code : 'transport-failed');
            if (!outgoing.destroyed) {
                outgoing.writeHead(502, { connection: 'close' });
                outgoing.end();
            }
        }
    }
    return {
        origin, url: `${origin}${target.pathname}${target.search}`, signal: AbortSignal.any([signal, controller.signal]),
        exchanges,
        assertHealthy() { if (failure)
            throw failure; },
        assertComplete() { if (failure)
            throw failure; if (!exchanges.length)
            throw new ScannerError('incomplete-output'); },
        async close() {
            active = false;
            controller.abort();
            signal.removeEventListener('abort', abort);
            await new Promise(resolve => { server.close(() => resolve()); server.closeAllConnections(); });
            await Promise.allSettled([...tasks]);
        },
    };
}
function checkResponse(response) {
    if (!Number.isInteger(response.status) || response.status < 200 || response.status > 599
        || response.body.encoding !== 'base64' || response.body.truncated || response.body.byteLength > 2_097_152
        || Buffer.from(response.body.data, 'base64').length !== response.body.byteLength)
        throw new ScannerError('incomplete-output');
}
function values(body, location) {
    try {
        if (location === 'json-body') {
            const value = JSON.parse(body);
            if (!value || typeof value !== 'object' || Array.isArray(value))
                throw new Error();
            return value;
        }
        const params = new URLSearchParams(body);
        return Object.fromEntries([...new Set(params.keys())].sort().map(key => [key, params.getAll(key)]));
    }
    catch {
        throw new ScannerError('invalid-input');
    }
}
function validateParameter(input, target) {
    const point = input.parameter;
    if (!point)
        return;
    if (!point.name || point.name.startsWith('-') || point.name.length > 128 || /[\u0000-\u0020]/.test(point.name)
        || !['query', 'form-body', 'json-body'].includes(point.location))
        throw new ScannerError('invalid-input');
    if (point.location === 'query' ? target.searchParams.getAll(point.name).length !== 1
        : !Object.hasOwn(values(input.request.body ?? '', point.location), point.name))
        throw new ScannerError('invalid-input');
}
function restrictMutation(input, target, local, body) {
    const point = input.parameter;
    if (!point)
        return;
    const before = new URLSearchParams(target.search), after = new URLSearchParams(local.search);
    if (point.location === 'query') {
        if (after.getAll(point.name).length !== 1 || body !== (input.request.body ?? ''))
            throw new ScannerError('scope-denied');
        before.delete(point.name);
        after.delete(point.name);
    }
    else {
        const original = values(input.request.body ?? '', point.location), changed = values(body, point.location);
        if (!Object.hasOwn(changed, point.name))
            throw new ScannerError('scope-denied');
        delete original[point.name];
        delete changed[point.name];
        if (JSON.stringify(original) !== JSON.stringify(changed))
            throw new ScannerError('scope-denied');
    }
    before.sort();
    after.sort();
    if (before.toString() !== after.toString())
        throw new ScannerError('scope-denied');
}
export async function bounded(operation, signal) {
    if (signal.aborted) {
        void operation.catch(() => undefined);
        throw new ScannerError('cancelled');
    }
    let abort;
    try {
        return await Promise.race([operation, new Promise((_resolve, reject) => {
                abort = () => reject(new ScannerError('cancelled'));
                signal.addEventListener('abort', abort, { once: true });
            })]);
    }
    finally {
        signal.removeEventListener('abort', abort);
    }
}

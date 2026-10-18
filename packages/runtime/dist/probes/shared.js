import { randomUUID } from 'node:crypto';
import { evidenceUrl, freeze, RuntimeError, RuntimeScope } from '../safety.js';
export function metadata(id, required, optional = []) {
    return freeze({ id, requiredCapabilities: [...required], optionalCapabilities: [...optional] });
}
export function available(context, required) {
    return required.every(id => context.capabilities.has(id));
}
export function assertActive(context) {
    if (context.signal?.aborted)
        throw new RuntimeError('cancelled');
}
export function check(context, supported) {
    assertActive(context);
    if (!supported)
        throw new RuntimeError('unsupported-capability');
}
export async function sanitized(execute) {
    try {
        return await execute();
    }
    catch (error) {
        throw error instanceof RuntimeError ? new RuntimeError(error.code) : new RuntimeError('transport-failed');
    }
}
export function base(context, probeId, diagnostics = []) {
    assertActive(context);
    return { id: `probe:${randomUUID()}`, probeId, projectId: context.project.id,
        capturedAt: new Date().toISOString(), outcome: diagnostics.length ? 'PARTIAL' : 'COMPLETED', diagnostics: [...new Set(diagnostics)] };
}
/** Each investigation snapshots configuration before the first asynchronous boundary. */
export function snapshot(context) {
    return { ...context, project: structuredClone(context.project),
        ...('request' in context ? { request: structuredCloneRequest(context.request) } : {}) };
}
function structuredCloneRequest(request) {
    return { ...request, ...(request.headers ? { headers: { ...request.headers } } : {}) };
}
export function request(context, input, injection = false) {
    assertActive(context);
    const scope = new RuntimeScope(context.project.baseUrl, context.project.allowedOrigins);
    const url = scope.assert(input.url), method = input.method ?? 'GET';
    if (!(injection ? ['GET', 'POST'] : ['GET', 'HEAD']).includes(method)
        || Object.keys(input.headers ?? {}).some(key => /^(cookie|authorization|proxy-authorization|x-api-key)$/i.test(key))
        || input.body !== undefined && (Buffer.byteLength(input.body) > 65_536 || method !== 'POST')) {
        throw new RuntimeError('invalid-request');
    }
    const signal = context.signal && input.signal ? AbortSignal.any([context.signal, input.signal]) : context.signal ?? input.signal;
    return { ...input, url, method, ...(input.headers ? { headers: { ...input.headers } } : {}), ...(signal ? { signal } : {}) };
}
export async function withIdentity(context, identity, execute) {
    assertActive(context);
    const session = await context.capabilities.get('authentication-manager').establishSession(identity);
    try {
        assertActive(context);
        if (session.identityId !== identity.id)
            throw new RuntimeError('authentication-failed');
        return await execute(session);
    }
    finally {
        await session.close();
    }
}
export function publicResponse(context, response) {
    // Project declared fields only: adapters can structurally return extra private fields.
    const result = context.capabilities.get('response-collector').evidence(response);
    return { responseId: result.responseId, url: evidenceUrl(result.url), method: result.method, status: result.status,
        body: { sha256: result.body.sha256, byteLength: result.body.byteLength, truncated: result.body.truncated },
        timings: { startedAt: result.timings.startedAt, firstByteMs: result.timings.firstByteMs, durationMs: result.timings.durationMs } };
}
export function publicComparison(result) {
    return { statusDelta: result.statusDelta, bodyEqual: result.bodyEqual, byteLengthDelta: result.byteLengthDelta,
        durationDeltaMs: result.durationDeltaMs, ownerMarkersMatch: result.ownerMarkersMatch };
}
export function text(response) { return Buffer.from(response.body.data, 'base64').toString('utf8'); }
export class NormalizedResponseComparator {
    compare(reference, candidate, markers = []) {
        const complete = !reference.body.truncated && !candidate.body.truncated;
        return freeze({ statusDelta: candidate.status - reference.status,
            bodyEqual: complete ? Buffer.from(reference.body.data, 'base64').equals(Buffer.from(candidate.body.data, 'base64')) : null,
            byteLengthDelta: candidate.body.byteLength - reference.body.byteLength,
            durationDeltaMs: candidate.timings.durationMs - reference.timings.durationMs,
            ownerMarkersMatch: complete && markers.length ? markers.every(marker => text(reference).includes(marker) && text(candidate).includes(marker)) : null });
    }
}
export function validateInjection(context) {
    const prepared = request(context, context.request, true);
    const point = context.parameter;
    if (!point || !point.name || point.name.length > 128 || /[\r\n]/.test(point.name))
        throw new RuntimeError('invalid-request');
    // Validate the baseline shape even when no mutation has been requested yet.
    mutate(context, prepared, value => value);
    return prepared;
}
/** Mutate exactly one declared query or body parameter, preserving all other inputs. */
export function mutate(context, input, value) {
    const point = context.parameter;
    if (point.location === 'query') {
        const url = new URL(input.url);
        if (url.searchParams.getAll(point.name).length !== 1)
            throw new RuntimeError('invalid-request');
        url.searchParams.set(point.name, value(url.searchParams.get(point.name)));
        return { ...input, url: url.href };
    }
    const type = Object.entries(input.headers ?? {}).find(([key]) => key.toLowerCase() === 'content-type')?.[1]?.split(';')[0]?.trim().toLowerCase();
    if (input.method !== 'POST' || !input.body)
        throw new RuntimeError('invalid-request');
    if (point.location === 'json-body' && type === 'application/json') {
        let body;
        try {
            body = JSON.parse(input.body);
        }
        catch {
            throw new RuntimeError('invalid-request');
        }
        if (!body || Array.isArray(body) || typeof body !== 'object' || !Object.hasOwn(body, point.name)
            || typeof body[point.name] !== 'string')
            throw new RuntimeError('invalid-request');
        Object.defineProperty(body, point.name, { value: value(body[point.name]), enumerable: true });
        return { ...input, body: JSON.stringify(body) };
    }
    if (point.location === 'form-body' && type === 'application/x-www-form-urlencoded') {
        const body = new URLSearchParams(input.body);
        if (body.getAll(point.name).length !== 1)
            throw new RuntimeError('invalid-request');
        body.set(point.name, value(body.get(point.name)));
        return { ...input, body: body.toString() };
    }
    throw new RuntimeError('invalid-request');
}

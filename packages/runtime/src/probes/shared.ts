import { randomUUID } from 'node:crypto';
import type { AuthSession, HttpRequest, HttpResponse, TestIdentity } from '../contracts.js';
import { evidenceUrl, freeze, RuntimeError, RuntimeScope } from '../safety.js';
import type {
  InjectionContext, ProbeContext, ProbeEvidence, ProbeMetadata, ResponseComparator, ResponseComparison,
} from './contracts.js';
import type { CapabilityCatalog } from './registry.js';

export function metadata(id: string, required: readonly (keyof CapabilityCatalog)[],
  optional: readonly (keyof CapabilityCatalog)[] = []): ProbeMetadata {
  return freeze({ id, requiredCapabilities: [...required], optionalCapabilities: [...optional] });
}
export function available(context: ProbeContext, required: readonly string[]): boolean {
  return required.every(id => context.capabilities.has(id as keyof CapabilityCatalog));
}
export function assertActive(context: ProbeContext): void {
  if (context.signal?.aborted) throw new RuntimeError('cancelled');
}
export function check(context: ProbeContext, supported: boolean): void {
  assertActive(context);
  if (!supported) throw new RuntimeError('unsupported-capability');
}
export async function sanitized<T>(execute: () => Promise<T>): Promise<T> {
  try { return await execute(); }
  catch (error) { throw error instanceof RuntimeError ? new RuntimeError(error.code) : new RuntimeError('transport-failed'); }
}
export function base(context: ProbeContext, probeId: string,
  diagnostics: ProbeEvidence['diagnostics'] = []): ProbeEvidence {
  assertActive(context);
  return { id: `probe:${randomUUID()}`, probeId, projectId: context.project.id,
    capturedAt: new Date().toISOString(), outcome: diagnostics.length ? 'PARTIAL' : 'COMPLETED', diagnostics: [...new Set(diagnostics)] };
}
/** Each investigation snapshots configuration before the first asynchronous boundary. */
export function snapshot<C extends ProbeContext>(context: C): C {
  return { ...context, project: structuredClone(context.project),
    ...('request' in context ? { request: structuredCloneRequest(context.request as HttpRequest) } : {}) };
}
function structuredCloneRequest(request: HttpRequest): HttpRequest {
  return { ...request, ...(request.headers ? { headers: { ...request.headers } } : {}) };
}
export function request(context: ProbeContext, input: HttpRequest, injection = false): HttpRequest {
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
export async function withIdentity<T>(context: ProbeContext, identity: TestIdentity,
  execute: (session: AuthSession) => Promise<T>): Promise<T> {
  assertActive(context);
  const session = await context.capabilities.get('authentication-manager').establishSession(identity);
  try {
    assertActive(context);
    if (session.identityId !== identity.id) throw new RuntimeError('authentication-failed');
    return await execute(session);
  } finally { await session.close(); }
}
export function publicResponse(context: ProbeContext, response: HttpResponse) {
  // Project declared fields only: adapters can structurally return extra private fields.
  const result = context.capabilities.get('response-collector').evidence(response);
  return { responseId: result.responseId, url: evidenceUrl(result.url), method: result.method, status: result.status,
    body: { sha256: result.body.sha256, byteLength: result.body.byteLength, truncated: result.body.truncated },
    timings: { startedAt: result.timings.startedAt, firstByteMs: result.timings.firstByteMs, durationMs: result.timings.durationMs } };
}
export function publicComparison(result: ResponseComparison): ResponseComparison {
  return { statusDelta: result.statusDelta, bodyEqual: result.bodyEqual, byteLengthDelta: result.byteLengthDelta,
    durationDeltaMs: result.durationDeltaMs, ownerMarkersMatch: result.ownerMarkersMatch };
}
export function text(response: HttpResponse): string { return Buffer.from(response.body.data, 'base64').toString('utf8'); }
export class NormalizedResponseComparator implements ResponseComparator {
  compare(reference: HttpResponse, candidate: HttpResponse, markers: readonly string[] = []) {
    const complete = !reference.body.truncated && !candidate.body.truncated;
    return freeze({ statusDelta: candidate.status - reference.status,
      bodyEqual: complete ? Buffer.from(reference.body.data, 'base64').equals(Buffer.from(candidate.body.data, 'base64')) : null,
      byteLengthDelta: candidate.body.byteLength - reference.body.byteLength,
      durationDeltaMs: candidate.timings.durationMs - reference.timings.durationMs,
      ownerMarkersMatch: complete && markers.length ? markers.every(marker =>
        text(reference).includes(marker) && text(candidate).includes(marker)) : null });
  }
}
export function validateInjection(context: InjectionContext): HttpRequest {
  const maximum = context.maxScannerRequests ?? 8;
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 512) throw new RuntimeError('invalid-request');
  const prepared = request(context, context.request, true);
  const point = context.parameter;
  if (!point || !point.name || point.name.length > 128 || /[\r\n]/.test(point.name)) throw new RuntimeError('invalid-request');
  // Validate the baseline shape even when no mutation has been requested yet.
  mutate(context, prepared, value => value);
  return prepared;
}
/** Mutate exactly one declared query or body parameter, preserving all other inputs. */
export function mutate(context: InjectionContext, input: HttpRequest, value: (original: string) => string): HttpRequest {
  const point = context.parameter;
  if (point.location === 'query') {
    const url = new URL(input.url);
    if (url.searchParams.getAll(point.name).length !== 1) throw new RuntimeError('invalid-request');
    url.searchParams.set(point.name, value(url.searchParams.get(point.name)!));
    return { ...input, url: url.href };
  }
  const type = Object.entries(input.headers ?? {}).find(([key]) => key.toLowerCase() === 'content-type')?.[1]?.split(';')[0]?.trim().toLowerCase();
  if (input.method !== 'POST' || !input.body) throw new RuntimeError('invalid-request');
  if (point.location === 'json-body' && type === 'application/json') {
    let body: Record<string, unknown>;
    try { body = JSON.parse(input.body); } catch { throw new RuntimeError('invalid-request'); }
    if (!body || Array.isArray(body) || typeof body !== 'object' || !Object.hasOwn(body, point.name)
      || typeof body[point.name] !== 'string') throw new RuntimeError('invalid-request');
    Object.defineProperty(body, point.name, { value: value(body[point.name] as string), enumerable: true });
    return { ...input, body: JSON.stringify(body) };
  }
  if (point.location === 'form-body' && type === 'application/x-www-form-urlencoded') {
    const body = new URLSearchParams(input.body);
    if (body.getAll(point.name).length !== 1) throw new RuntimeError('invalid-request');
    body.set(point.name, value(body.get(point.name)!)); return { ...input, body: body.toString() };
  }
  throw new RuntimeError('invalid-request');
}

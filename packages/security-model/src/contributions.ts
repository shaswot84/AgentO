import { createHash } from 'node:crypto';
import type {
  AnalysisContext, BrowserObservation, Component, Endpoint, Evidence, FrameworkAnalysis,
  JsonValue, Project, StaticAnalysis,
} from '@agento/core';
import type { CookieEvidence, HeaderEvidence, HttpResponseEvidence, NetworkEvidence } from '@agento/runtime';
import type { ModelContribution } from './contracts.js';

/** Only the runtime's public projections belong here; private responses and sessions do not. */
export interface RuntimeSnapshot {
  readonly producerId: string;
  readonly capturedAt: string;
  readonly responses?: readonly HttpResponseEvidence[];
  readonly headers?: readonly HeaderEvidence[];
  readonly cookies?: readonly CookieEvidence[];
  readonly network?: readonly NetworkEvidence[];
}

export function fromFrameworkAnalysis(analysis: FrameworkAnalysis): ModelContribution {
  return { source: 'source', components: analysis.components, endpoints: analysis.endpoints,
    resources: analysis.resources, signals: analysis.signals, evidence: analysis.evidence };
}

export function fromStaticAnalysis(analysis: StaticAnalysis): ModelContribution {
  return { source: 'source', signals: analysis.signals, evidence: analysis.evidence };
}

export function fromBrowserObservation(observation: BrowserObservation): ModelContribution {
  return { source: 'browser', endpoints: observation.endpoints, resources: observation.resources,
    signals: observation.signals, evidence: observation.evidence };
}

/** A mixed exchange context has no reliable per-entry knowledge source. */
export function fromAnalysisContext(context: AnalysisContext): ModelContribution {
  return { source: 'declared', components: context.components, endpoints: context.endpoints,
    resources: context.resources, signals: context.signals, evidence: context.evidence };
}

const methods = new Set<string>(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']);
function identifier(kind: string, ...parts: unknown[]): string {
  return `runtime-model:${kind}:${createHash('sha256').update(JSON.stringify(parts)).digest('hex').slice(0, 24)}`;
}
function invalid(): never { throw new Error('Invalid public runtime snapshot'); }
function object(value: unknown): void {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
}
function array<T>(value: readonly T[]): readonly T[] { return Array.isArray(value) ? value : invalid(); }
function optionalArray<T>(value: readonly T[] | undefined): readonly T[] { return value === undefined ? [] : array(value); }
function text(value: unknown): string { return typeof value === 'string' && value.length > 0 ? value : invalid(); }
function boolean(value: unknown): boolean { return typeof value === 'boolean' ? value : invalid(); }
function number(value: unknown): number { return typeof value === 'number' && Number.isFinite(value) ? value : invalid(); }
function nonnegative(value: unknown): number { const result = number(value); return result >= 0 ? result : invalid(); }
function strings(value: readonly string[]): string[] {
  return Array.isArray(value) ? value.map(item => typeof item === 'string' ? item : invalid()) : invalid();
}
function nullableNumber(value: unknown): number | null { return value === null ? null : number(value); }
function status(value: unknown): number {
  const result = number(value);
  return Number.isInteger(result) && result >= 100 && result <= 599 ? result : invalid();
}
function method(value: unknown): string {
  const result = text(value); return /^[A-Z]+$/.test(result) ? result : invalid();
}
function compare(a: string, b: string): number { return a < b ? -1 : a > b ? 1 : 0; }
function publicUrl(value: string): URL {
  let parsed: URL;
  try { parsed = new URL(text(value)); } catch { return invalid(); }
  if (!['http:', 'https:'].includes(parsed.protocol)) return invalid();
  parsed.username = ''; parsed.password = ''; parsed.hash = '';
  const query = new URLSearchParams();
  for (const name of parsed.searchParams.keys()) query.append(name, '[REDACTED]');
  parsed.search = query.toString();
  return parsed;
}

/** Wrap public observations without execution, ownership guesses, or authentication conclusions. */
export function fromRuntimeSnapshot(project: Project, snapshot: RuntimeSnapshot): ModelContribution {
  object(snapshot);
  const producerId = text(snapshot.producerId), capturedAt = text(snapshot.capturedAt);
  const components = new Map<string, Component>();
  const endpoints = new Map<string, Endpoint>();
  const endpointOrigins: Record<string, string> = Object.create(null);
  const evidence = new Map<string, Evidence>();
  const responseEndpoints = new Map<string, Set<string>>();
  const responseUrls = new Map<string, Set<string>>();
  const responseFingerprints = new Map<string, string>();

  function endpoint(url: URL, method: string): string | undefined {
    if (!methods.has(method)) return;
    const id = identifier('endpoint', project.id, method, url.origin, url.pathname);
    const existing = endpoints.get(id);
    const parameters = new Map((existing?.parameters ?? []).map(parameter => [`${parameter.location}:${parameter.name}`, parameter]));
    for (const name of new Set(url.searchParams.keys())) parameters.set(`query:${name}`, { name, location: 'query', required: false });
    if (!existing) {
      const componentId = identifier('component', project.id, url.origin);
      components.set(componentId, { id: componentId, projectId: project.id, name: url.origin, kind: 'service' });
      endpoints.set(id, { id, componentId, method: method as Endpoint['method'], path: url.pathname,
        parameters: [...parameters.values()], authentication: 'unknown', roles: [], evidenceIds: [] });
      endpointOrigins[id] = url.origin;
    } else endpoints.set(id, { ...existing, parameters: [...parameters.values()] });
    return id;
  }

  function add(kind: Evidence['kind'], summary: string, facts: Record<string, JsonValue>, endpointId?: string,
    identityId?: string): void {
    const id = identifier('evidence', project.id, producerId, capturedAt, kind, facts, endpointId ?? null, identityId ?? null);
    evidence.set(id, { id, projectId: project.id, producerId, capturedAt, kind, summary, facts,
      ...(endpointId ? { endpointId } : {}), ...(identityId ? { identityId } : {}) });
    if (endpointId) {
      const item = endpoints.get(endpointId)!;
      endpoints.set(endpointId, { ...item, evidenceIds: [...new Set([...item.evidenceIds, id])] });
    }
  }

  for (const response of optionalArray(snapshot.responses)) {
    object(response); object(response.body); object(response.timings);
    const url = publicUrl(response.url), responseMethod = method(response.method), responseId = text(response.responseId);
    const sha256 = text(response.body.sha256);
    if (!/^[a-f0-9]{64}$/i.test(sha256)) invalid();
    const facts: Record<string, JsonValue> = {
      observation: 'http-response', responseId, url: url.href, origin: url.origin, method: responseMethod, status: status(response.status),
      body: { sha256, byteLength: nonnegative(response.body.byteLength), truncated: boolean(response.body.truncated) },
      timings: { startedAt: text(response.timings.startedAt), firstByteMs: nonnegative(response.timings.firstByteMs),
        durationMs: nonnegative(response.timings.durationMs) },
    };
    // Distinct exchanges must not acquire one response's headers after URL redaction collapses their query values.
    // This private comparison is never copied into evidence or error messages.
    const fingerprint = JSON.stringify([response.url, facts]), previous = responseFingerprints.get(responseId);
    if (previous !== undefined && previous !== fingerprint) invalid();
    responseFingerprints.set(responseId, fingerprint);
    const endpointId = endpoint(url, responseMethod);
    if (endpointId) {
      const references = responseEndpoints.get(responseId) ?? new Set<string>(); references.add(endpointId);
      responseEndpoints.set(responseId, references);
    }
    const urls = responseUrls.get(responseId) ?? new Set<string>(); urls.add(url.href); responseUrls.set(responseId, urls);
    add('http-response', 'Normalized runtime HTTP response.', facts, endpointId);
  }

  function responseEndpoint(responseId: string | undefined): string | undefined {
    const references = responseId && responseEndpoints.get(responseId);
    return references && references.size === 1 ? [...references][0] : undefined;
  }
  function responseLocation(responseId: string): Record<string, JsonValue> {
    const urls = responseUrls.get(responseId);
    if (!urls || urls.size !== 1) return {};
    const url = new URL([...urls][0]!);
    return { url: url.href, origin: url.origin };
  }

  for (const headers of optionalArray(snapshot.headers)) {
    object(headers); object(headers.cors);
    const responseId = text(headers.responseId), cors = headers.cors;
    const credentials = array(cors.allowCredentials).map(value => value === null ? null : boolean(value));
    add('configuration', 'Normalized runtime CORS response headers.', {
      observation: 'cors', responseId, ...responseLocation(responseId), options: {
        allowOrigin: strings(cors.allowOrigin), allowCredentials: credentials,
        allowMethods: strings(cors.allowMethods), allowHeaders: strings(cors.allowHeaders),
        exposeHeaders: strings(cors.exposeHeaders), maxAge: array(cors.maxAge).map(nullableNumber),
      },
    }, responseEndpoint(responseId));
  }

  for (const cookie of optionalArray(snapshot.cookies)) {
    object(cookie);
    if (!['response', 'browser', 'jar'].includes(cookie.source)
      || !['Strict', 'Lax', 'None', null].includes(cookie.sameSite)) invalid();
    const responseId = cookie.responseId === undefined ? undefined : text(cookie.responseId);
    add('configuration', 'Normalized runtime cookie metadata.', {
      observation: 'cookie', name: text(cookie.name), domain: text(cookie.domain), path: text(cookie.path),
      hostOnly: boolean(cookie.hostOnly), httpOnly: boolean(cookie.httpOnly), secure: boolean(cookie.secure),
      sameSite: cookie.sameSite, expiresAt: cookie.expiresAt === null ? null : text(cookie.expiresAt),
      maxAge: nullableNumber(cookie.maxAge), partitioned: boolean(cookie.partitioned), value: '[REDACTED]',
      source: cookie.source, ...(responseId ? { responseId, ...responseLocation(responseId) } : {}),
      ...(cookie.sessionId === undefined ? {} : { sessionId: text(cookie.sessionId) }),
    }, responseEndpoint(responseId));
  }

  for (const record of optionalArray(snapshot.network)) {
    object(record);
    if (!['browser', 'http'].includes(record.source)) invalid();
    const url = publicUrl(record.url), networkMethod = method(record.method), blocked = boolean(record.blocked);
    const observedStatus = record.status === null ? null : status(record.status);
    const endpointId = !blocked && observedStatus !== null ? endpoint(url, networkMethod) : undefined;
    const identityId = text(record.identityId);
    add('http-request', 'Normalized runtime network observation.', {
      observation: 'network', sessionId: text(record.sessionId), identityId, source: record.source,
      url: url.href, origin: url.origin, method: networkMethod, status: observedStatus, blocked,
    }, endpointId, identityId);
  }

  return { source: 'runtime', components: [...components.values()].sort((a, b) => compare(a.id, b.id)),
    endpoints: [...endpoints.values()].map(item => ({ ...item,
      parameters: [...item.parameters].sort((a, b) => compare(a.location, b.location) || compare(a.name, b.name)),
      evidenceIds: [...item.evidenceIds].sort(compare),
    })).sort((a, b) => compare(a.id, b.id)),
    endpointOrigins: Object.fromEntries(Object.entries(endpointOrigins).sort(([a], [b]) => compare(a, b))),
    evidence: [...evidence.values()].sort((a, b) => compare(a.id, b.id)) };
}

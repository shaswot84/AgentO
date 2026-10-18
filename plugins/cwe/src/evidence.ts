import type { Evidence, JsonValue } from '@agento/core';
import type { HttpResponseEvidence } from '@agento/runtime';
import type { NormalizedProbeEvidence } from './contracts.js';
import { freeze } from './shared.js';

type RecordValue = Record<string, unknown>;
const object = (value: unknown): value is RecordValue => value !== null && typeof value === 'object' && !Array.isArray(value);
const string = (value: unknown): value is string => typeof value === 'string' && value.length > 0;
const strings = (value: unknown): boolean => Array.isArray(value) && value.every(item => typeof item === 'string');
const bool = (value: unknown): boolean => typeof value === 'boolean';
const tri = (value: unknown): boolean => value === null || bool(value);
const numeric = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value);
const nonnegative = (value: unknown): boolean => numeric(value) && value >= 0;
const timestamp = (value: unknown): boolean => string(value) && Number.isFinite(Date.parse(value));
function httpUrl(value: unknown): boolean {
  if (!string(value)) return false;
  try { const parsed = new URL(value); return ['http:', 'https:'].includes(parsed.protocol) && !parsed.username && !parsed.password; }
  catch { return false; }
}
function origin(value: unknown): boolean {
  return value === 'null' || httpUrl(value) && new URL(value as string).origin === value;
}
function response(value: unknown): value is HttpResponseEvidence {
  if (!object(value) || !string(value.responseId) || !string(value.url) || !string(value.method)
    || !numeric(value.status) || !Number.isInteger(value.status) || value.status < 100 || value.status > 599
    || !object(value.body) || !string(value.body.sha256) || !/^[a-f0-9]{64}$/i.test(value.body.sha256)
    || !nonnegative(value.body.byteLength) || !bool(value.body.truncated) || !object(value.timings)) return false;
  if (!httpUrl(value.url)) return false;
  return timestamp(value.timings.startedAt) && nonnegative(value.timings.firstByteMs) && nonnegative(value.timings.durationMs);
}
function comparison(value: unknown): boolean {
  return object(value) && numeric(value.statusDelta) && tri(value.bodyEqual) && numeric(value.byteLengthDelta)
    && numeric(value.durationDeltaMs) && tri(value.ownerMarkersMatch);
}
function cors(value: unknown): boolean {
  return object(value) && strings(value.allowOrigin) && Array.isArray(value.allowCredentials)
    && value.allowCredentials.every(tri) && strings(value.allowMethods) && strings(value.allowHeaders)
    && strings(value.exposeHeaders) && Array.isArray(value.maxAge) && value.maxAge.every(item => item === null || numeric(item));
}
function cookie(value: unknown): boolean {
  return object(value) && string(value.name) && value.value === '[REDACTED]' && string(value.domain) && string(value.path)
    && bool(value.hostOnly) && bool(value.httpOnly) && bool(value.secure) && bool(value.partitioned)
    && ['Strict', 'Lax', 'None', null].includes(value.sameSite as string | null)
    && (value.expiresAt === null || timestamp(value.expiresAt)) && (value.maxAge === null || numeric(value.maxAge))
    && ['response', 'browser', 'jar'].includes(value.source as string)
    && (value.responseId === undefined || string(value.responseId)) && (value.sessionId === undefined || string(value.sessionId));
}
function parameter(value: unknown): boolean {
  return object(value) && string(value.name) && ['query', 'json-body', 'form-body'].includes(value.location as string);
}
/** Validate at the core JSON boundary as well as at the public typed evaluator boundary. */
export function isProbeEvidence(value: unknown): value is NormalizedProbeEvidence {
  if (!object(value) || !string(value.id) || !string(value.projectId) || !timestamp(value.capturedAt)
    || !['COMPLETED', 'PARTIAL'].includes(value.outcome as string) || !Array.isArray(value.diagnostics)
    || !value.diagnostics.every(item => ['scanner-unavailable', 'browser-unavailable', 'response-truncated'].includes(item))
    || value.outcome === 'COMPLETED' && value.diagnostics.length > 0) return false;
  switch (value.probeId) {
    case 'cookie-security': return Array.isArray(value.observations) && value.observations.every(item => object(item)
      && ['anonymous', 'authenticated'].includes(item.context as string)
      && (item.context === 'anonymous' ? item.identityId === null : string(item.identityId))
      && response(item.response) && Array.isArray(item.cookies) && item.cookies.every(cookie));
    case 'cross-origin': return Array.isArray(value.observations) && value.observations.every(item => object(item)
      && origin(item.requestedOrigin) && (item.identityId === null || string(item.identityId))
      && ['omit', 'session'].includes(item.credentialMode as string) && object(item.preflight) && object(item.actual)
      && response(item.preflight.response) && response(item.actual.response) && cors(item.preflight.cors) && cors(item.actual.cors));
    case 'authorization': return string(value.resourceId) && string(value.ownerIdentityId) && string(value.attackerIdentityId)
      && value.ownerIdentityId !== value.attackerIdentityId && response(value.owner) && response(value.attacker)
      && response(value.anonymous) && comparison(value.attackerComparison) && comparison(value.anonymousComparison);
    case 'xss': return parameter(value.parameter) && response(value.baseline) && response(value.injected) && string(value.canary)
      && tri(value.literalReflection) && Array.isArray(value.reflectionContexts)
      && value.reflectionContexts.every(item => ['html', 'attribute', 'script', 'text'].includes(item))
      && (value.browser === null || object(value.browser) && httpUrl(value.browser.url) && bool(value.browser.canaryVisible))
      && tri(value.executionConfirmed) && tri(value.domSinkReached);
    case 'sql-injection': return parameter(value.parameter) && response(value.baseline) && comparison(value.booleanComparison)
      && Array.isArray(value.observations) && value.observations.every(item => object(item)
        && ['syntax', 'boolean-true', 'boolean-false'].includes(item.variant as string)
        && ['error', 'boolean'].includes(item.technique as string) && response(item.response)
        && comparison(item.comparison) && strings(item.errorIndicators) && fingerprint(item.dbmsFingerprint))
      && (value.scanner === null || object(value.scanner) && ['error', 'boolean', 'time'].includes(value.scanner.technique as string)
        && fingerprint(value.scanner.dbmsFingerprint) && tri(value.scanner.observedDifference));
    default: return false;
  }
}
function fingerprint(value: unknown): boolean { return [null, 'SQLite', 'PostgreSQL', 'MySQL', 'SQLServer', 'Oracle'].includes(value as string | null); }

/** Each nested object has its own public schema; extra adapter fields are never copied. */
function pick(value: unknown, keys: readonly string[]): Record<string, JsonValue> {
  const source = value as RecordValue;
  return Object.fromEntries(keys.filter(key => source[key] !== undefined).map(key => [key, source[key] as JsonValue]));
}
function publicResponse(value: unknown): Record<string, JsonValue> {
  const item = value as RecordValue, parsed = new URL(item.url as string);
  parsed.hash = ''; parsed.username = ''; parsed.password = '';
  for (const name of new Set(parsed.searchParams.keys())) parsed.searchParams.set(name, '[REDACTED]');
  return { ...pick(item, ['responseId', 'method', 'status']), url: parsed.href,
    body: pick(item.body, ['sha256', 'byteLength', 'truncated']),
    timings: pick(item.timings, ['startedAt', 'firstByteMs', 'durationMs']) };
}
const publicComparison = (value: unknown) => pick(value, ['statusDelta', 'bodyEqual', 'byteLengthDelta', 'durationDeltaMs', 'ownerMarkersMatch']);
const publicCors = (value: unknown) => pick(value, ['allowOrigin', 'allowCredentials', 'allowMethods', 'allowHeaders', 'exposeHeaders', 'maxAge']);
function project(value: NormalizedProbeEvidence): JsonValue {
  const item = value as unknown as RecordValue;
  const common = pick(item, ['id', 'probeId', 'projectId', 'capturedAt', 'outcome', 'diagnostics']);
  if (item.probeId === 'cookie-security') return { ...common, observations: (item.observations as RecordValue[]).map(observation => ({
    ...pick(observation, ['identityId', 'context']), response: publicResponse(observation.response),
    cookies: (observation.cookies as RecordValue[]).map(cookie => pick(cookie, [
      'name', 'value', 'domain', 'path', 'hostOnly', 'httpOnly', 'secure', 'sameSite', 'expiresAt', 'maxAge',
      'partitioned', 'source', 'responseId', 'sessionId',
    ])),
  })) };
  if (item.probeId === 'cross-origin') return { ...common, observations: (item.observations as RecordValue[]).map(observation => ({
    ...pick(observation, ['requestedOrigin', 'identityId', 'credentialMode']),
    ...Object.fromEntries(['preflight', 'actual'].map(key => {
      const exchange = observation[key] as RecordValue;
      return [key, { response: publicResponse(exchange.response), cors: publicCors(exchange.cors) }];
    })),
  })) };
  if (item.probeId === 'authorization') return { ...common, ...pick(item, ['resourceId', 'ownerIdentityId', 'attackerIdentityId']),
    owner: publicResponse(item.owner), attacker: publicResponse(item.attacker), anonymous: publicResponse(item.anonymous),
    attackerComparison: publicComparison(item.attackerComparison), anonymousComparison: publicComparison(item.anonymousComparison) };
  const injection = { ...common, parameter: pick(item.parameter, ['name', 'location']), baseline: publicResponse(item.baseline) };
  if (item.probeId === 'xss') {
    const browser = item.browser as RecordValue | null;
    return { ...injection, ...pick(item, ['canary', 'literalReflection', 'reflectionContexts', 'executionConfirmed', 'domSinkReached']),
      injected: publicResponse(item.injected), browser: browser === null ? null : {
        canaryVisible: browser.canaryVisible as boolean, url: new URL(browser.url as string).origin + new URL(browser.url as string).pathname,
      } };
  }
  return { ...injection, booleanComparison: publicComparison(item.booleanComparison),
    scanner: item.scanner === null ? null : pick(item.scanner, ['technique', 'dbmsFingerprint', 'observedDifference']),
    observations: (item.observations as RecordValue[]).map(observation => ({
      ...pick(observation, ['variant', 'technique', 'errorIndicators', 'dbmsFingerprint']),
      response: publicResponse(observation.response), comparison: publicComparison(observation.comparison),
    })) };
}
export function toCoreEvidence(probe: NormalizedProbeEvidence, endpointId?: string): Evidence {
  if (!isProbeEvidence(probe)) throw new Error('Invalid normalized probe evidence');
  return freeze({ id: probe.id, projectId: probe.projectId, kind: 'configuration', producerId: `probe:${probe.probeId}`,
    capturedAt: probe.capturedAt, summary: 'Normalized security probe observations.',
    ...(endpointId ? { endpointId } : {}), facts: { observation: 'security-probe', schemaVersion: 1, probe: structuredClone(project(probe)) } });
}
export function fromCoreEvidence(item: Evidence): NormalizedProbeEvidence | undefined {
  const probe = item.facts.probe;
  if (item.facts.observation !== 'security-probe' || item.facts.schemaVersion !== 1 || !isProbeEvidence(probe)
    || probe.id !== item.id || probe.projectId !== item.projectId || probe.capturedAt !== item.capturedAt
    || item.producerId !== `probe:${probe.probeId}`) return;
  return probe;
}

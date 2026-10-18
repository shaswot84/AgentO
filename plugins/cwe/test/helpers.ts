import { createHash } from 'node:crypto';
import type { AnalysisContext, Endpoint, Evidence, Project } from '@agento/core';
import type { AuthorizationEvidence, CookieSecurityEvidence, CrossOriginEvidence, HttpResponseEvidence, ResponseComparison, SQLInjectionEvidence, XSSEvidence } from '@agento/runtime';
import type { EvaluationScope } from '../src/index.js';

export const project: Project = { id: 'rules', name: 'Rules', mode: 'code-aware', baseUrl: 'https://shop.test',
  allowedOrigins: ['https://shop.test', 'https://api.shop.test'], languages: ['typescript'] };
export const policy = { resourceId: 'order-1', ownerIdentityId: 'alice', attackerIdentityId: 'bob',
  attackerIsUnauthorized: true, anonymousIsUnauthorized: true };
export const scope: EvaluationScope = { projectId: project.id, targetUrl: `${project.baseUrl}/orders/1`, method: 'GET',
  parameter: { name: 'q', location: 'query' }, sensitiveCookieNames: ['sid'],
  untrustedOrigins: ['https://unapproved.invalid', 'null'], authorization: policy };
export function response(extra: Partial<HttpResponseEvidence> = {}): HttpResponseEvidence {
  return { responseId: 'response', url: scope.targetUrl, method: 'GET', status: 200,
    body: { sha256: createHash('sha256').update('owner contents').digest('hex'), byteLength: 14, truncated: false },
    timings: { startedAt: '2026-10-18T00:00:00Z', firstByteMs: 1, durationMs: 2 }, ...extra };
}
export const comparison = (extra: Partial<ResponseComparison> = {}): ResponseComparison => ({
  statusDelta: 0, bodyEqual: true, byteLengthDelta: 0, durationDeltaMs: 0, ownerMarkersMatch: true, ...extra,
});
export const base = (probeId: string) => ({ id: `probe:${probeId}`, probeId, projectId: project.id,
  capturedAt: '2026-10-18T00:00:00Z', outcome: 'COMPLETED' as const, diagnostics: [] });
export const cookies = (extra: Partial<CookieSecurityEvidence> = {}): CookieSecurityEvidence => ({ ...base('cookie-security'),
  observations: [{ identityId: 'alice', context: 'authenticated', response: response(), cookies: [{
    name: 'sid', value: '[REDACTED]', domain: 'shop.test', path: '/', hostOnly: true,
    httpOnly: false, secure: false, sameSite: 'Lax', expiresAt: null, maxAge: null, partitioned: false, source: 'response',
  }] }], ...extra });
export function cors(extra: Partial<CrossOriginEvidence> = {}): CrossOriginEvidence {
  const headers = { allowOrigin: ['https://unapproved.invalid'], allowCredentials: [true], allowMethods: ['GET'],
    allowHeaders: [], exposeHeaders: [], maxAge: [] };
  return { ...base('cross-origin'), observations: [{ requestedOrigin: 'https://unapproved.invalid', identityId: 'alice', credentialMode: 'session',
    preflight: { response: response({ method: 'OPTIONS' }), cors: headers }, actual: { response: response(), cors: headers } }], ...extra };
}
export const authorization = (extra: Partial<AuthorizationEvidence> = {}): AuthorizationEvidence => ({ ...base('authorization'),
  resourceId: policy.resourceId, ownerIdentityId: policy.ownerIdentityId, attackerIdentityId: policy.attackerIdentityId,
  owner: response(), attacker: response(), anonymous: response({ status: 401 }),
  attackerComparison: comparison(), anonymousComparison: comparison({ bodyEqual: false, ownerMarkersMatch: false }), ...extra });
export const xss = (extra: Partial<XSSEvidence> = {}): XSSEvidence => ({ ...base('xss'), parameter: { name: 'q', location: 'query' },
  baseline: response(), injected: response(), canary: 'agento-canary', literalReflection: true, reflectionContexts: ['html'], browser: null,
  executionConfirmed: true, domSinkReached: true, ...extra });
export function sql(extra: Partial<SQLInjectionEvidence> = {}): SQLInjectionEvidence {
  return { ...base('sql-injection'), parameter: { name: 'q', location: 'query' }, baseline: response(),
    observations: [{ variant: 'syntax', technique: 'error', response: response({ status: 500 }), comparison: comparison({ bodyEqual: false }),
      errorIndicators: ['sqlite-error'], dbmsFingerprint: 'SQLite' },
    { variant: 'boolean-true', technique: 'boolean', response: response(), comparison: comparison(), errorIndicators: [], dbmsFingerprint: null },
    { variant: 'boolean-false', technique: 'boolean', response: response({ body: { ...response().body, sha256: 'f'.repeat(64) } }),
      comparison: comparison({ bodyEqual: false }), errorIndicators: [], dbmsFingerprint: null }],
    booleanComparison: comparison({ bodyEqual: false }), scanner: null, ...extra };
}
export const endpoint = (extra: Partial<Endpoint> = {}): Endpoint => ({ id: 'order', componentId: 'service', method: 'GET', path: '/orders/1',
  authentication: 'required', roles: ['admin'], parameters: [{ name: 'q', location: 'query', required: false }], evidenceIds: ['route'], ...extra });
export const route: Evidence = { id: 'route', projectId: project.id, producerId: 'framework', kind: 'source-location',
  capturedAt: '2026-10-18T00:00:00Z', summary: 'Route declaration', endpointId: 'order', facts: { observation: 'route' } };
export function context(extra: Partial<AnalysisContext> = {}): AnalysisContext {
  return { project, components: [{ id: 'service', projectId: project.id, name: 'Service', kind: 'service' }], endpoints: [endpoint()],
    identities: [{ id: 'alice', label: 'Alice', roles: ['admin'], authentication: 'session-cookie' },
      { id: 'bob', label: 'Bob', roles: ['customer'], authentication: 'session-cookie' }],
    resources: [{ id: 'order-1', projectId: project.id, type: 'Order', externalKey: '1', ownerIdentityId: 'alice', endpointId: 'order', evidenceIds: ['route'] }],
    signals: [{ id: 'sql-candidate', projectId: project.id, producerId: 'static', endpointId: 'order', cweIds: ['CWE-89'], summary: 'SQL candidate', evidenceIds: ['route'] }],
    evidence: [route], ...extra };
}

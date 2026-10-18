import type { Endpoint, Evidence, JsonValue, ModelGenerationRequest, ModelProvider, Project } from '@agento/core';
import { buildApplicationSecurityModel } from '@agento/security-model';
import {
  CWE79Plugin, CWE89Plugin, CWE639Plugin, CWE862Plugin, CWE942Plugin, CWE1004Plugin, CWE614Plugin,
} from '@agento/cwe';
import { SecurityHypothesisEngine, type HypothesisEngineOptions } from '../src/index.js';

export const project: Project = { id: 'shop', name: 'Shop', mode: 'code-aware', baseUrl: 'https://shop.test',
  allowedOrigins: ['https://shop.test'], languages: ['typescript'] };
export const endpoint: Endpoint = { id: 'orders', componentId: 'service', method: 'GET', path: '/orders/:id',
  authentication: 'required', roles: [], parameters: [{ name: 'id', location: 'path', required: true },
    { name: 'q', location: 'query', required: false }], evidenceIds: ['route'], handler: { file: 'routes.ts', startLine: 3 } };
export function evidence(id: string, facts: Record<string, JsonValue>, extra: Partial<Evidence> = {}): Evidence {
  return { id, projectId: project.id, producerId: 'fixture', kind: 'source-location', capturedAt: '2026-10-18T00:00:00Z',
    endpointId: endpoint.id, summary: 'Normalized test observation', facts, ...extra };
}
export function model(fixed = false, extraEvidence: Evidence[] = []) {
  const records = [evidence('route', { observation: 'route' }),
    evidence('owner', { resourceId: 'order-1', ownerIdentityId: 'alice' }, { kind: 'resource-ownership', identityId: 'alice' }),
    evidence('guard', { observation: 'authorization-guard', enforcement: fixed ? 'observed' : 'conditional' }),
    evidence('cookie', { observation: 'session', options: { name: 'sid', secret: 'private-session-secret', cookie: { httpOnly: fixed, secure: fixed } } }),
    evidence('cors', { observation: 'cors', options: { origin: fixed ? ['https://trusted.test'] : '*', credentials: true } }),
    evidence('sql', { observation: 'database-operation', interpolated: !fixed, placeholders: fixed ? 1 : 0 }),
    ...(fixed ? [] : [evidence('xss', { observation: 'static-candidate', cweId: 'CWE-79', sources: [], sink: { kind: 'html' } })]),
    ...extraEvidence];
  return buildApplicationSecurityModel({ project,
    identities: [{ id: 'alice', label: 'Alice', roles: ['customer'], authentication: 'session-cookie', sessionRef: 'private-session-handle' }],
    contributions: [{ source: 'source', components: [{ id: 'service', projectId: project.id, name: 'Service', kind: 'service' }],
      endpoints: [endpoint], resources: [{ id: 'order-1', projectId: project.id, type: 'Order', externalKey: 'private-order-id',
        ownerIdentityId: 'alice', endpointId: endpoint.id, evidenceIds: ['owner'] }], evidence: records,
      signals: fixed ? [] : [{ id: 'xss-signal', projectId: project.id, producerId: 'static', cweIds: ['CWE-79'],
        endpointId: endpoint.id, summary: 'private-source-body', evidenceIds: ['xss'] }] }] });
}
export const plugins = () => [new CWE639Plugin(), new CWE862Plugin(), new CWE942Plugin(), new CWE1004Plugin(),
  new CWE614Plugin(), new CWE79Plugin(), new CWE89Plugin()];
export function engine(options: Partial<HypothesisEngineOptions> = {}) {
  return new SecurityHypothesisEngine({ plugins: plugins(), ...options });
}
export function provider(reply: (request: ModelGenerationRequest) => unknown): ModelProvider {
  return { id: 'fake-model', generateStructured: async request => ({ status: 'completed',
    value: reply(request) as JsonValue, usage: { inputTokens: 100, outputTokens: 50 } }) };
}
export function selectAll(request: ModelGenerationRequest) {
  const input = request.input as { candidates: { candidateRef: string; supports: { supportRef: string }[] }[] };
  return { hypotheses: input.candidates.map(item => ({ candidateRef: item.candidateRef, supportRefs: item.supports.map(s => s.supportRef) })) };
}

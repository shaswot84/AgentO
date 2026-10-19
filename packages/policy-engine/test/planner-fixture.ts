import type { Evidence, JsonValue, Project } from '@agento/core';
import { CWE639Plugin, CWE862Plugin, CWE942Plugin, CWE1004Plugin, CWE614Plugin, CWE79Plugin, CWE89Plugin } from '@agento/cwe';
import { buildApplicationSecurityModel } from '@agento/security-model';
import { SecurityTestPlanner } from '@agento/test-planner';
import { origin } from './helpers.js';

export const bindings = { inputs: [{ name: 'id', location: 'path' as const, valueRef: 'order-key' }, { name: 'q', location: 'query' as const, valueRef: 'query-input' }] };
export async function candidate(cweId: string, fixed = false) {
  const project: Project = { id: 'shop', name: 'Shop', mode: 'code-aware', baseUrl: origin, allowedOrigins: [origin], languages: ['typescript'] };
  const options = { sensitiveCookieNames: ['sid'], untrustedOrigins: ['https://untrusted.test'], authorizationPolicies: [{
    resourceId: 'order', ownerIdentityId: 'alice', attackerIdentityId: 'bob', attackerIsUnauthorized: true, anonymousIsUnauthorized: true }] };
  const rules = [new CWE639Plugin(options), new CWE862Plugin(options), new CWE942Plugin(options), new CWE1004Plugin(options), new CWE614Plugin(options), new CWE79Plugin(options), new CWE89Plugin(options)];
  const evidence = (id: string, facts: Record<string, JsonValue>, extra: Partial<Evidence> = {}): Evidence => ({ id, facts,
    projectId: project.id, endpointId: 'orders', producerId: 'fixture', capturedAt: '2026-10-19T00:00:00Z', kind: 'source-location', summary: 'Synthetic observation', ...extra });
  const context = buildApplicationSecurityModel({ project, identities: ['alice', 'bob'].map(id => ({ id, label: id, roles: ['customer'], authentication: 'session-cookie' as const })),
    contributions: [{ source: 'source', components: [{ id: 'service', projectId: project.id, name: 'Service', kind: 'service' }],
      endpoints: [{ id: 'orders', componentId: 'service', method: 'GET', path: '/orders/:id', authentication: 'required', roles: ['customer'],
        parameters: [{ name: 'id', location: 'path', required: true }, { name: 'q', location: 'query', required: false }], evidenceIds: ['route'] }],
      resources: [{ id: 'order', projectId: project.id, type: 'Order', externalKey: 'PRIVATE_KEY', ownerIdentityId: 'alice', endpointId: 'orders', evidenceIds: ['owner'] }],
      evidence: [evidence('route', { observation: 'route' }), evidence('owner', { resourceId: 'order', ownerIdentityId: 'alice' }, { kind: 'resource-ownership', identityId: 'alice' }),
        evidence('guard', { observation: 'authorization-guard', enforcement: fixed ? 'observed' : 'conditional' }),
        evidence('cookie', { observation: 'session', options: { name: 'sid', cookie: { httpOnly: fixed, secure: fixed } } }),
        evidence('cors', { observation: 'cors', options: { origin: fixed ? ['https://trusted.test'] : '*', credentials: true } }),
        evidence('sql', { observation: 'database-operation', interpolated: !fixed, placeholders: fixed ? 1 : 0 }),
        evidence('xss', { observation: 'static-candidate', cweId: 'CWE-79', sources: [], sink: { kind: 'html' } })],
      signals: [{ id: 'xss-signal', projectId: project.id, producerId: 'fixture', cweIds: ['CWE-79'], endpointId: 'orders', summary: 'Synthetic candidate', evidenceIds: ['xss'] }] }] });
  const rule = rules.find(rule => rule.cweId === cweId)!, hypothesis = (await rule.detectCandidates(context))[0]!;
  return { context, rule, hypothesis, planner: new SecurityTestPlanner({ plugins: rules }) };
}

import type { AnalysisContext, Endpoint, Evidence, JsonValue, Project } from '@agento/core';
import type { ApplicationSecurityModel } from '@agento/security-model';
import { buildApplicationSecurityModel } from '@agento/security-model';
import { CWE639Plugin, CWE862Plugin, CWE942Plugin, CWE1004Plugin, CWE614Plugin, CWE79Plugin, CWE89Plugin } from '@agento/cwe';
import type { RuleOptions } from '@agento/cwe';
import { SecurityTestPlanner, type PlanningBindings } from '../src/index.js';

export const project: Project = { id: 'shop', name: 'Shop', mode: 'code-aware', baseUrl: 'https://shop.test',
  allowedOrigins: ['https://shop.test'], languages: ['typescript'] };
export const policy = { resourceId: 'order-1', ownerIdentityId: 'alice', attackerIdentityId: 'bob',
  attackerIsUnauthorized: true, anonymousIsUnauthorized: true };
export const ruleOptions: RuleOptions = { sensitiveCookieNames: ['sid'], untrustedOrigins: ['https://untrusted.test'], authorizationPolicies: [policy] };
export const plugins = (options: RuleOptions = ruleOptions) => [new CWE639Plugin(options), new CWE862Plugin(options), new CWE942Plugin(options),
  new CWE1004Plugin(options), new CWE614Plugin(options), new CWE79Plugin(options), new CWE89Plugin(options)];
export const bindings: PlanningBindings = { inputs: [{ name: 'id', location: 'path', valueRef: 'order-key-input' },
  { name: 'q', location: 'query', valueRef: 'baseline-query-input' }] };
export function evidence(id: string, facts: Record<string, JsonValue>, extra: Partial<Evidence> = {}): Evidence {
  return { id, projectId: project.id, producerId: 'fixture', kind: 'source-location', capturedAt: '2026-10-18T00:00:00Z',
    endpointId: 'orders', summary: 'Target observation', facts, ...extra };
}
export function model(fixed = false, endpointOverrides: Partial<Endpoint> = {}, target = project) {
  const endpoint: Endpoint = { id: 'orders', componentId: 'service', method: 'GET', path: '/orders/:id',
    authentication: 'required', roles: ['customer'], parameters: [{ name: 'id', location: 'path', required: true },
      { name: 'q', location: 'query', required: false }], evidenceIds: ['route'], ...endpointOverrides };
  const records = [evidence('route', { observation: 'route' }),
    evidence('owner', { resourceId: 'order-1', ownerIdentityId: 'alice' }, { kind: 'resource-ownership', identityId: 'alice' }),
    evidence('guard', { observation: 'authorization-guard', enforcement: fixed ? 'observed' : 'conditional' }),
    evidence('cookie', { observation: 'session', options: { name: 'sid', secret: 'PRIVATE_SESSION_SECRET', cookie: { httpOnly: fixed, secure: fixed } } }),
    evidence('cors', { observation: 'cors', options: { origin: fixed ? ['https://trusted.test'] : '*', credentials: true } }),
    evidence('sql', { observation: 'database-operation', interpolated: !fixed, placeholders: fixed ? 1 : 0 }),
    evidence('xss', { observation: 'static-candidate', cweId: 'CWE-79', sources: [], sink: { kind: 'html' } })];
  return buildApplicationSecurityModel({ project: target,
    identities: [{ id: 'alice', label: 'PRIVATE_IDENTITY_LABEL', roles: ['customer'], authentication: 'session-cookie', sessionRef: 'PRIVATE_SESSION_HANDLE' },
      { id: 'bob', label: 'Bob', roles: ['customer'], authentication: 'session-cookie' }],
    contributions: [{ source: 'source', components: [{ id: 'service', projectId: target.id, name: 'Service', kind: 'service' }], endpoints: [endpoint],
      resources: [{ id: 'order-1', projectId: target.id, type: 'Order', externalKey: 'PRIVATE_RESOURCE_VALUE', ownerIdentityId: 'alice',
        endpointId: endpoint.id, evidenceIds: ['owner'] }], evidence: records,
      signals: [{ id: 'xss-signal', projectId: target.id, producerId: 'fixture', cweIds: ['CWE-79'], endpointId: endpoint.id,
        summary: 'PRIVATE_SOURCE_CODE', evidenceIds: ['xss'] }] }] });
}
export async function candidate(cweId = 'CWE-639', context = model(), rules = plugins()) {
  const rule = rules.find(plugin => plugin.cweId === cweId)!;
  const hypothesis = (await rule.detectCandidates(context))[0]!;
  if (!hypothesis) throw new Error('Missing fixture hypothesis');
  return { rule, hypothesis, context, planner: new SecurityTestPlanner({ plugins: rules }) };
}
export function flatModel(full: ApplicationSecurityModel): AnalysisContext {
  const aliases = new Map(full.endpoints.map(endpoint => [endpoint.id, endpoint.observations[0]!.endpoint.id]));
  return { project: full.project, components: full.components, identities: full.identities, evidence: full.evidence,
    endpoints: full.endpoints.map(endpoint => endpoint.observations[0]!.endpoint),
    resources: full.resources.map(resource => ({ ...resource, endpointId: aliases.get(resource.endpointId!) ?? resource.endpointId! })),
    signals: full.signals.map(signal => ({ ...signal, endpointId: aliases.get(signal.endpointId!) ?? signal.endpointId! })) };
}

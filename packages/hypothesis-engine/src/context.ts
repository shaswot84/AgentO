import type { AnalysisContext, SecurityHypothesis } from '@agento/core';
import { buildApplicationSecurityModel, fromAnalysisContext, resolveEndpoint } from '@agento/security-model';
import type { ApplicationSecurityModel } from '@agento/security-model';
import type { HypothesisContext, HypothesisSupport } from './contracts.js';
import { strings } from './shared.js';

export function applicationModel(context: AnalysisContext): ApplicationSecurityModel {
  return 'schemaVersion' in context && context.schemaVersion === 1 ? context as ApplicationSecurityModel
    : buildApplicationSecurityModel({ project: context.project, identities: context.identities,
      contributions: [fromAnalysisContext(context)] });
}

export function gatherContext(model: ApplicationSecurityModel, candidate: SecurityHypothesis): HypothesisContext | undefined {
  if (!candidate || typeof candidate.id !== 'string' || !candidate.id || candidate.status !== 'HYPOTHESIS'
    || candidate.projectId !== model.project.id || !strings(candidate.evidenceIds) || !candidate.endpointId) return;
  const endpoint = resolveEndpoint(model, candidate.endpointId);
  if (!endpoint || !model.project.allowedOrigins.includes(endpoint.origin)
    || !['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(endpoint.method)
    || !['required', 'optional', 'unknown'].includes(endpoint.authentication)
    || endpoint.parameters.some(parameter => !['path', 'query', 'body', 'header', 'cookie'].includes(parameter.location))) return;
  const evidenceById = new Map(model.evidence.map(item => [item.id, item]));
  if (candidate.evidenceIds.some(id => !evidenceById.has(id) || evidenceById.get(id)!.projectId !== model.project.id)) return;
  const matches = (id: string | undefined) => !!id && resolveEndpoint(model, id)?.id === endpoint.id;
  const facts = [...model.cookies, ...model.corsConfigurations, ...model.dataFlows, ...model.databaseOperations,
    ...model.observedOwnership, ...model.resourceTypes].filter(fact => fact.endpointIds.some(matches)
      || fact.endpointIds.length === 0 && (fact.kind === 'cookie' || fact.kind === 'cors'));
  const resources = model.resources.filter(resource => resource.projectId === model.project.id && matches(resource.endpointId));
  const signals = model.signals.filter(signal => signal.projectId === model.project.id && matches(signal.endpointId)
    && signal.cweIds.includes(candidate.cweId));
  const linked = new Set([...endpoint.evidenceIds, ...facts.flatMap(fact => fact.evidenceIds),
    ...resources.flatMap(resource => resource.evidenceIds), ...signals.flatMap(signal => signal.evidenceIds)]);
  const evidence = model.evidence.filter(item => item.projectId === model.project.id
    && (matches(item.endpointId) || !item.endpointId && linked.has(item.id)));
  return { model, candidate, endpoint, facts, resources, signals, evidence };
}

/** Membership in the endpoint's context is required; an arbitrary known project ID is insufficient. */
export function validateSupports(context: HypothesisContext, supports: readonly HypothesisSupport[]): readonly HypothesisSupport[] {
  const known = new Map(context.evidence.map(item => [item.id, item]));
  const ids = new Set<string>();
  return supports.filter(support => {
    if (!support || typeof support.id !== 'string' || !support.id || ids.has(support.id)
      || typeof support.kind !== 'string' || !support.kind || typeof support.statement !== 'string'
      || !support.statement.trim() || support.statement.length > 1_000 || !strings(support.evidenceIds)
      || !support.evidenceIds.length || !['candidate', 'context'].includes(support.strength)
      || support.evidenceIds.some(id => !known.has(id))) return false;
    ids.add(support.id); return true;
  });
}


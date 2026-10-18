import type { Evidence, Identity, Resource, SourceLocation } from '@agento/core';
import type {
  ApplicationSecurityModel, AuthenticationRequirement, ModelDiagnostic, ModelEndpoint,
  ModelParameter, SecurityModelInput, SourceHandler, UserRole,
} from './contracts.js';
import { mergeEndpoints } from './endpoints.js';
import { projectFacts } from './projections.js';
import { byId, distinct, freeze, stableJson, unique } from './utils.js';

/** Pure, deterministic assembly. No target execution, provider imports or verdict evaluation. */
export function buildApplicationSecurityModel(input: SecurityModelInput): ApplicationSecurityModel {
  const { project, identities: inputIdentities = [], contributions = [] } = structuredClone(input);
  const diagnostics: ModelDiagnostic[] = [];
  if (!project.id) throw new Error('Invalid project');
  if (contributions.some(item => !['source', 'browser', 'runtime', 'declared'].includes(item.source))) throw new Error('Invalid knowledge source');
  const identities = byId(inputIdentities, 'identity');
  const components = byId(contributions.flatMap(item => item.components ?? []), 'component');
  const evidence = byId(contributions.flatMap(item => item.evidence ?? []), 'evidence');
  const rawResources = distinct(contributions.flatMap(item => item.resources ?? []));
  const rawSignals = byId(contributions.flatMap(item => item.signals ?? []), 'signal');
  for (const item of [...components, ...evidence, ...rawResources, ...rawSignals]) {
    if (item.projectId !== project.id) throw new Error('Model entity project mismatch');
  }
  const knownEvidence = new Set(evidence.map(item => item.id));
  const checkEvidence = (ids: readonly string[]) => {
    if (ids.some(id => !knownEvidence.has(id))) throw new Error('Unknown evidence reference');
  };
  const checkIdentity = (id: string | undefined) => {
    if (id !== undefined && !identities.some(item => item.id === id)) throw new Error('Unknown identity reference');
  };
  for (const item of evidence) checkIdentity(item.identityId);
  for (const contribution of contributions) for (const endpoint of contribution.endpoints ?? []) {
    checkEvidence(endpoint.evidenceIds);
    if (!['required', 'optional', 'unknown'].includes(endpoint.authentication)
      || endpoint.parameters.some(value => !value.name || typeof value.required !== 'boolean'
        || !['path', 'query', 'body', 'header', 'cookie'].includes(value.location))) throw new Error('Invalid endpoint declaration');
  }
  const { endpoints, aliases } = mergeEndpoints(project, contributions, evidence, components, diagnostics);
  const canonicalEndpoint = (id: string) => {
    if (!Object.hasOwn(aliases, id)) throw new Error('Unknown endpoint reference');
    return aliases[id]!;
  };
  for (const item of evidence) if (item.endpointId) canonicalEndpoint(item.endpointId);
  for (const item of rawResources) { checkEvidence(item.evidenceIds); checkIdentity(item.ownerIdentityId); }
  const resources = mergeResources(rawResources.map(item => ({ ...item,
    ...(item.endpointId ? { endpointId: canonicalEndpoint(item.endpointId) } : {}) })), diagnostics);
  const signals = rawSignals.map(item => {
    checkEvidence(item.evidenceIds);
    return { ...item, ...(item.endpointId ? { endpointId: canonicalEndpoint(item.endpointId) } : {}) };
  });
  const parameters = projectParameters(endpoints, diagnostics);
  const summarizedEndpoints = endpoints.map(endpoint => ({ ...endpoint,
    parameters: endpoint.parameters.map(parameter => ({ ...parameter,
      required: parameters.find(value => value.endpointId === endpoint.id && value.name === parameter.name
        && value.location === parameter.location)?.required ?? false })) }));
  const authenticationRequirements: AuthenticationRequirement[] = distinct(endpoints.flatMap(endpoint =>
    endpoint.observations.map(observation => ({ endpointId: endpoint.id,
      requirement: observation.endpoint.authentication, roles: observation.endpoint.roles,
      source: observation.source, evidenceIds: observation.endpoint.evidenceIds }))));
  const sourceHandlers = projectHandlers(endpoints, evidence, aliases);
  const facts = projectFacts(contributions, summarizedEndpoints, rawResources, evidence, aliases, diagnostics);
  for (const item of facts.observedOwnership) {
    if (typeof item.details.ownerIdentityId !== 'string') throw new Error('Invalid ownership identity');
    checkIdentity(item.details.ownerIdentityId);
    if (!resources.some(resource => resource.id === item.details.resourceId)) throw new Error('Unknown ownership resource');
  }
  const runtimeEvidenceIds = new Set(contributions.filter(item => item.source === 'runtime' || item.source === 'browser')
    .flatMap(item => (item.evidence ?? []).map(record => record.id)));
  const runtimeKinds = new Set(['http-request', 'http-response', 'browser-observation', 'identity-session', 'resource-ownership', 'screenshot']);
  return freeze({ schemaVersion: 1, project, identities, components: components.sort((a, b) => a.id.localeCompare(b.id)),
    endpoints: summarizedEndpoints, resources, signals, evidence, endpointAliases: aliases,
    parameters, authenticationRequirements, userRoles: projectRoles(identities, endpoints), sourceHandlers, ...facts,
    runtimeObservations: evidence.filter(item => runtimeEvidenceIds.has(item.id) || runtimeKinds.has(item.kind)),
    diagnostics: distinct(diagnostics) });
}

export function resolveEndpoint(model: ApplicationSecurityModel, endpointId: string): ModelEndpoint | undefined {
  if (!Object.hasOwn(model.endpointAliases, endpointId)) return undefined;
  const canonical = model.endpointAliases[endpointId];
  return model.endpoints.find(endpoint => endpoint.id === canonical);
}

function mergeResources(resources: readonly Resource[], diagnostics: ModelDiagnostic[]): Resource[] {
  const grouped = new Map<string, Resource[]>();
  for (const resource of resources) {
    if (!resource.id || !resource.type) throw new Error('Invalid resource');
    grouped.set(resource.id, [...(grouped.get(resource.id) ?? []), resource]);
  }
  return [...grouped.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([id, group]) => {
    const first = group[0]!;
    if (group.some(item => item.type !== first.type || item.externalKey !== first.externalKey)) throw new Error('Conflicting resource ID');
    const owners = unique(group.flatMap(item => item.ownerIdentityId ? [item.ownerIdentityId] : []));
    const endpointIds = unique(group.flatMap(item => item.endpointId ? [item.endpointId] : []));
    if (endpointIds.length > 1) throw new Error('Conflicting resource endpoint references');
    if (owners.length > 1) diagnostics.push({ code: 'conflicting-ownership', entityIds: [id, ...owners] });
    return { id, projectId: first.projectId, type: first.type, externalKey: first.externalKey,
      ...(owners.length === 1 ? { ownerIdentityId: owners[0]! } : {}),
      ...(endpointIds.length === 1 ? { endpointId: endpointIds[0]! } : {}),
      evidenceIds: unique(group.flatMap(item => item.evidenceIds)) };
  });
}

function projectParameters(endpoints: readonly ModelEndpoint[], diagnostics: ModelDiagnostic[]): ModelParameter[] {
  return endpoints.flatMap(endpoint => endpoint.parameters.map(parameter => {
    const observations = endpoint.observations.filter(item => item.endpoint.parameters.some(value =>
      value.location === parameter.location && (value.location === 'header' ? value.name.toLowerCase() : value.name) === parameter.name));
    const declarations = observations.filter(item => item.source === 'source' || item.source === 'declared');
    const requirements = new Set(declarations.flatMap(item => item.endpoint.parameters.filter(value =>
      value.location === parameter.location && (value.location === 'header' ? value.name.toLowerCase() : value.name) === parameter.name)
      .map(value => value.required)));
    if (requirements.size > 1) diagnostics.push({ code: 'conflicting-parameter', entityIds: [endpoint.id, parameter.location, parameter.name] });
    return { endpointId: endpoint.id, name: parameter.name, location: parameter.location,
      required: requirements.size === 1 ? [...requirements][0]! : null,
      evidenceIds: unique(observations.flatMap(item => item.endpoint.evidenceIds)) };
  }));
}

function projectRoles(identities: readonly Identity[], endpoints: readonly ModelEndpoint[]): UserRole[] {
  const names = unique([...identities.flatMap(item => item.roles), ...endpoints.flatMap(item => item.roles)]);
  return names.map(name => ({ name, identityIds: identities.filter(item => item.roles.includes(name)).map(item => item.id),
    endpointIds: endpoints.filter(item => item.roles.includes(name)).map(item => item.id),
    evidenceIds: unique(endpoints.flatMap(item => item.observations.filter(observation => observation.endpoint.roles.includes(name))
      .flatMap(observation => observation.endpoint.evidenceIds))) }));
}

function projectHandlers(endpoints: readonly ModelEndpoint[], evidence: readonly Evidence[], aliases: Readonly<Record<string, string>>): SourceHandler[] {
  const handlers: SourceHandler[] = endpoints.flatMap(endpoint => endpoint.observations.flatMap(item =>
    item.endpoint.handler ? [{ endpointId: endpoint.id, source: item.endpoint.handler, evidenceIds: item.endpoint.evidenceIds }] : []));
  for (const item of evidence) {
    if (!item.endpointId || !Array.isArray(item.facts.handlers)) continue;
    for (const handler of item.facts.handlers) {
      if (!handler || typeof handler !== 'object' || Array.isArray(handler)) continue;
      const location = handler.source;
      if (!location || typeof location !== 'object' || Array.isArray(location)
        || typeof location.file !== 'string' || typeof location.startLine !== 'number') continue;
      const source: SourceLocation = { file: location.file, startLine: location.startLine,
        ...(typeof location.endLine === 'number' ? { endLine: location.endLine } : {}),
        ...(typeof handler.name === 'string' ? { symbol: handler.name } : {}) };
      handlers.push({ endpointId: aliases[item.endpointId]!, source, evidenceIds: [item.id] });
    }
  }
  const grouped = new Map<string, SourceHandler>();
  for (const handler of handlers) {
    const key = stableJson([handler.endpointId, handler.source]);
    const previous = grouped.get(key);
    grouped.set(key, { ...handler, evidenceIds: unique([...(previous?.evidenceIds ?? []), ...handler.evidenceIds]) });
  }
  return [...grouped.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, value]) => value);
}

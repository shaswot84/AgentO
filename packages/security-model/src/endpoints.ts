import type { Component, Endpoint, Evidence, Project } from '@agento/core';
import type { EndpointObservation, ModelContribution, ModelDiagnostic, ModelEndpoint } from './contracts.js';
import { distinct, identifier, stableJson, unique } from './utils.js';

const methods = new Set(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']);
const parameter = /^:([A-Za-z_]\w*)$|^\{([A-Za-z_]\w*)\}$/;
function template(path: string): string {
  return path.split('/').map(part => {
    const match = parameter.exec(part);
    return match ? `:${match[1] ?? match[2]}` : part;
  }).join('/');
}
function isTemplate(path: string): boolean { return path.split('/').some(part => parameter.test(part)); }
function matches(pattern: string, path: string): boolean {
  const declared = pattern.split('/'), concrete = path.split('/');
  return declared.length === concrete.length && declared.every((part, index) =>
    parameter.test(part) ? !!concrete[index] : part === concrete[index]);
}
function origin(value: string): string {
  const parsed = new URL(value);
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error('Invalid endpoint origin');
  return parsed.origin;
}

interface Entry { readonly key: string; readonly path: string; readonly observation: EndpointObservation }

export function mergeEndpoints(project: Project, contributions: readonly ModelContribution[], evidence: readonly Evidence[],
  components: Component[], diagnostics: ModelDiagnostic[]): { endpoints: ModelEndpoint[]; aliases: Record<string, string> } {
  const baseOrigin = origin(project.baseUrl);
  const entries: Entry[] = [];
  const claimedIds = new Map<string, string>();
  for (const contribution of contributions) for (const endpoint of contribution.endpoints ?? []) {
    if (!endpoint.id || !endpoint.componentId || !methods.has(endpoint.method)) throw new Error('Invalid endpoint');
    let path = endpoint.path;
    let boundOrigin = contribution.endpointOrigins?.[endpoint.id];
    if (/^https?:\/\//i.test(path)) {
      const parsed = new URL(path);
      if (boundOrigin && origin(boundOrigin) !== parsed.origin) throw new Error('Conflicting endpoint origin');
      boundOrigin = origin(path);
      path = parsed.pathname;
    } else if (contribution.source !== 'source') path = path.split(/[?#]/)[0]!;
    if (!path.startsWith('/') || path.startsWith('//')) throw new Error('Invalid endpoint path');
    const associated = evidence.filter(item => item.endpointId === endpoint.id || endpoint.evidenceIds.includes(item.id));
    const observedOrigins = unique(associated.flatMap(item => {
      if (!['http-request', 'http-response'].includes(item.kind)) return [];
      const urlOrigin = typeof item.facts.url === 'string' ? origin(item.facts.url) : undefined;
      if (typeof item.facts.origin === 'string' && urlOrigin && origin(item.facts.origin) !== urlOrigin) {
        throw new Error('HTTP evidence origin does not match its URL');
      }
      const value = item.facts.origin ?? urlOrigin;
      return typeof value === 'string' ? [origin(value)] : [];
    }));
    if (observedOrigins.length > 1) throw new Error('Conflicting endpoint origins; use distinct provider endpoint IDs');
    const endpointOrigin = boundOrigin ? origin(boundOrigin)
      : contribution.source === 'source' ? baseOrigin : observedOrigins[0] ?? baseOrigin;
    if (observedOrigins.some(value => value !== endpointOrigin)) throw new Error('Endpoint evidence origin mismatch');
    const normalizedPath = template(path);
    const key = stableJson([endpointOrigin, endpoint.method, normalizedPath]);
    const previous = claimedIds.get(endpoint.id);
    if (previous && previous !== key) throw new Error('Provider endpoint ID identifies different routes');
    claimedIds.set(endpoint.id, key);
    entries.push({ key, path: normalizedPath, observation: { source: contribution.source, origin: endpointOrigin, endpoint } });
    if (!components.some(component => component.id === endpoint.componentId)) {
      components.push({ id: endpoint.componentId, projectId: project.id, name: endpoint.componentId, kind: 'service' });
    }
  }
  const groups = new Map<string, Entry[]>();
  for (const entry of entries) groups.set(entry.key, [...(groups.get(entry.key) ?? []), entry]);
  // Source declarations win only when exactly one template explains a concrete observation.
  // Literal routes retain precedence, and unsupported pattern syntax is treated as opaque.
  for (const [key, group] of [...groups]) {
    const first = group[0]!;
    if (isTemplate(first.path) || group.some(item => item.observation.source === 'source' || item.observation.source === 'declared')) continue;
    const candidates = [...groups.entries()].filter(([, other]) => {
      const candidate = other[0]!;
      return other.some(item => item.observation.source === 'source' || item.observation.source === 'declared')
        && isTemplate(candidate.path) && candidate.observation.origin === first.observation.origin
        && candidate.observation.endpoint.method === first.observation.endpoint.method && matches(candidate.path, first.path);
    });
    if (candidates.length === 1) {
      const [target, other] = candidates[0]!;
      groups.set(target, [...other, ...group]);
      groups.delete(key);
    } else if (candidates.length > 1) diagnostics.push({ code: 'ambiguous-endpoint',
      entityIds: unique([...group, ...candidates.flatMap(([, other]) => other)].map(item => item.observation.endpoint.id)) });
  }
  const aliases: Record<string, string> = Object.create(null) as Record<string, string>;
  function bindAlias(alias: string, id: string): void {
    if (Object.hasOwn(aliases, alias) && aliases[alias] !== id) throw new Error('Provider alias conflicts with a canonical endpoint ID');
    aliases[alias] = id;
  }
  const endpoints: ModelEndpoint[] = [];
  for (const [key, group] of [...groups].sort(([a], [b]) => a.localeCompare(b))) {
    const observations = distinct(group.map(item => item.observation));
    const first = group[0]!;
    const id = identifier('endpoint', [project.id, key]);
    const aliasIds = unique(observations.map(item => item.endpoint.id));
    for (const alias of aliasIds) bindAlias(alias, id);
    bindAlias(id, id);
    const authentication = unique(observations.map(item => item.endpoint.authentication).filter(value => value !== 'unknown'));
    if (authentication.length > 1) diagnostics.push({ code: 'conflicting-authentication', entityIds: aliasIds });
    const parameters = new Map<string, Endpoint['parameters'][number]>();
    for (const observation of observations) for (const value of observation.endpoint.parameters) {
      const parameterKey = stableJson([value.location, value.location === 'header' ? value.name.toLowerCase() : value.name]);
      const name = value.location === 'header' ? value.name.toLowerCase() : value.name;
      const previous = parameters.get(parameterKey);
      parameters.set(parameterKey, { ...value, name, required: previous ? previous.required && value.required : value.required });
    }
    const related = evidence.filter(item => item.endpointId && aliasIds.includes(item.endpointId));
    for (const item of related) if (typeof item.facts.url === 'string' && ['http-request', 'http-response'].includes(item.kind)) {
      for (const name of new URL(item.facts.url).searchParams.keys()) {
        const parameterKey = stableJson(['query', name]);
        if (!parameters.has(parameterKey)) parameters.set(parameterKey, { name, location: 'query', required: false });
      }
    }
    const handlers = distinct(observations.flatMap(item => item.endpoint.handler ? [item.endpoint.handler] : []));
    const componentIds = unique(observations.map(item => item.endpoint.componentId));
    endpoints.push({ id, componentId: componentIds[0]!, componentIds, origin: first.observation.origin,
      method: first.observation.endpoint.method, path: first.path, aliases: aliasIds, observations,
      parameters: [...parameters.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, value]) => value),
      authentication: authentication.length === 1 ? authentication[0] as Endpoint['authentication'] : 'unknown',
      roles: unique(observations.flatMap(item => item.endpoint.roles)), ...(handlers.length === 1 ? { handler: handlers[0]! } : {}),
      evidenceIds: unique([...observations.flatMap(item => item.endpoint.evidenceIds), ...related.map(item => item.id)]) });
  }
  return { endpoints, aliases };
}

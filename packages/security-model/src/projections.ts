import { createHash } from 'node:crypto';
import type { Evidence, JsonValue, Resource } from '@agento/core';
import type {
  KnowledgeSource, ModelContribution, ModelDiagnostic, ModelEndpoint, ModelFact,
  ModelFactInput, ModelFactKind,
} from './contracts.js';

interface FactProjections {
  readonly resourceTypes: readonly ModelFact[];
  readonly observedOwnership: readonly ModelFact[];
  readonly dataFlows: readonly ModelFact[];
  readonly databaseOperations: readonly ModelFact[];
  readonly cookies: readonly ModelFact[];
  readonly corsConfigurations: readonly ModelFact[];
}

/** Sort object keys, retaining array order and every normalized detail. */
function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map(key => `${JSON.stringify(key)}:${stableJson(object[key])}`).join(',')}}`;
  }
  return JSON.stringify(value)!;
}

function isRecord(value: JsonValue | undefined): value is Readonly<Record<string, JsonValue>> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function evidenceKind(item: Evidence): ModelFactKind | undefined {
  const observation = item.facts.observation;
  if (observation === 'database-operation') return 'database-operation';
  if (observation === 'cookie' || observation === 'session' || observation === 'session-cookie-update') return 'cookie';
  if (observation === 'cors' || observation === 'cors-header' || observation === 'cors-origin-allowlist') return 'cors';
  if (observation === 'resource-type') return 'resource-type';
  if (observation === 'ownership' || item.kind === 'resource-ownership') return 'ownership';
  if (observation === 'static-candidate' && Array.isArray(item.facts.sources) && isRecord(item.facts.sink)) return 'data-flow';
  return undefined;
}

function hasOwnership(details: Readonly<Record<string, JsonValue>>): boolean {
  return typeof details.resourceId === 'string' && details.resourceId.length > 0
    && typeof details.ownerIdentityId === 'string' && details.ownerIdentityId.length > 0;
}

/** Build factual views without interpreting framework syntax or supplying configuration defaults. */
export function projectFacts(
  contributions: readonly ModelContribution[],
  endpoints: readonly ModelEndpoint[],
  resources: readonly Resource[],
  evidence: readonly Evidence[],
  aliases: Readonly<Record<string, string>>,
  diagnostics: ModelDiagnostic[],
): FactProjections {
  const evidenceById = new Map(evidence.map(item => [item.id, item]));
  const endpointIds = new Set(endpoints.map(endpoint => endpoint.id));
  const evidenceSources = new Map<string, Set<KnowledgeSource>>();
  const resourceSources = new Map<string, Set<KnowledgeSource>>();
  const facts = new Map<string, ModelFact>();

  for (const contribution of contributions) {
    for (const item of contribution.evidence ?? []) {
      const sources = evidenceSources.get(item.id) ?? new Set<KnowledgeSource>();
      sources.add(contribution.source);
      evidenceSources.set(item.id, sources);
    }
    for (const resource of contribution.resources ?? []) {
      const key = stableJson(resource);
      const sources = resourceSources.get(key) ?? new Set<KnowledgeSource>();
      sources.add(contribution.source);
      resourceSources.set(key, sources);
    }
  }

  function resolveEndpoint(id: string): string {
    const canonical = Object.hasOwn(aliases, id) ? aliases[id]! : id;
    if (!endpointIds.has(canonical)) throw new Error(`Unknown endpoint reference in model fact: ${id}`);
    return canonical;
  }

  function add(input: ModelFactInput, source: KnowledgeSource): void {
    if (input.kind !== 'resource-type' && input.evidenceIds.length === 0) {
      throw new Error(`Model ${input.kind} facts require at least one evidence reference.`);
    }
    for (const id of input.evidenceIds) {
      if (!evidenceById.has(id)) throw new Error(`Unknown evidence reference in model fact: ${id}`);
    }
    const normalized = {
      kind: input.kind, source,
      endpointIds: [...new Set((input.endpointIds ?? []).map(resolveEndpoint))].sort(),
      evidenceIds: [...new Set(input.evidenceIds)].sort(),
      details: input.details,
    };
    if (input.kind === 'ownership' && !hasOwnership(input.details)) {
      throw new Error('Ownership facts require explicit resourceId and ownerIdentityId details.');
    }
    const key = stableJson(normalized);
    if (!facts.has(key)) {
      facts.set(key, { id: `model-fact:${createHash('sha256').update(key).digest('hex')}`, ...normalized });
    }
  }

  for (const contribution of contributions) {
    for (const input of contribution.facts ?? []) add(input, contribution.source);
  }

  for (const item of evidence) {
    const kind = evidenceKind(item);
    if (!kind || (kind === 'ownership' && !hasOwnership(item.facts))) continue;
    const referencedEndpoints: string[] = item.endpointId ? [item.endpointId] : [];
    if (typeof item.facts.endpointId === 'string') referencedEndpoints.push(item.facts.endpointId);
    if (Array.isArray(item.facts.endpointIds)) {
      for (const id of item.facts.endpointIds) {
        if (typeof id !== 'string') throw new Error(`Invalid endpoint reference in evidence: ${item.id}`);
        referencedEndpoints.push(id);
      }
    }
    const details: Readonly<Record<string, JsonValue>> = item.source && !Object.hasOwn(item.facts, 'sourceLocation')
      ? { ...item.facts, sourceLocation: { ...item.source } }
      : item.facts;
    for (const source of evidenceSources.get(item.id) ?? ['declared'] as const) {
      add({ kind, endpointIds: referencedEndpoints, evidenceIds: [item.id], details }, source);
    }
  }

  for (const resource of resources) {
    const referencedEndpoints = resource.endpointId ? [resource.endpointId] : [];
    const sources = resourceSources.get(stableJson(resource)) ?? new Set<KnowledgeSource>(['declared']);
    for (const source of sources) {
      add({ kind: 'resource-type', endpointIds: referencedEndpoints, evidenceIds: resource.evidenceIds,
        details: { resourceId: resource.id, type: resource.type, externalKey: resource.externalKey } }, source);
    }
    if (!resource.ownerIdentityId) continue;
    const ownershipEvidence = resource.evidenceIds.filter(id => {
      const item = evidenceById.get(id);
      return item?.kind === 'resource-ownership'
        && (item.facts.resourceId === undefined || item.facts.resourceId === resource.id)
        && (item.facts.ownerIdentityId === undefined || item.facts.ownerIdentityId === resource.ownerIdentityId);
    });
    if (ownershipEvidence.length === 0) {
      diagnostics.push({ code: 'missing-ownership-evidence', entityIds: [resource.id] });
      continue;
    }
    for (const source of sources) {
      add({ kind: 'ownership', endpointIds: referencedEndpoints, evidenceIds: ownershipEvidence,
        details: { resourceId: resource.id, ownerIdentityId: resource.ownerIdentityId } }, source);
    }
  }

  const sorted = [...facts.values()].sort((left, right) => left.id.localeCompare(right.id));
  const ownersByResource = new Map<string, Set<string>>();
  for (const fact of sorted) {
    if (fact.kind !== 'ownership') continue;
    const resourceId = fact.details.resourceId as string;
    const owners = ownersByResource.get(resourceId) ?? new Set<string>();
    owners.add(fact.details.ownerIdentityId as string);
    ownersByResource.set(resourceId, owners);
  }
  for (const [resourceId, owners] of [...ownersByResource].sort(([left], [right]) => left.localeCompare(right))) {
    if (owners.size > 1) diagnostics.push({ code: 'conflicting-ownership', entityIds: [resourceId, ...[...owners].sort()] });
  }

  return {
    resourceTypes: sorted.filter(fact => fact.kind === 'resource-type'),
    observedOwnership: sorted.filter(fact => fact.kind === 'ownership'),
    dataFlows: sorted.filter(fact => fact.kind === 'data-flow'),
    databaseOperations: sorted.filter(fact => fact.kind === 'database-operation'),
    cookies: sorted.filter(fact => fact.kind === 'cookie'),
    corsConfigurations: sorted.filter(fact => fact.kind === 'cors'),
  };
}

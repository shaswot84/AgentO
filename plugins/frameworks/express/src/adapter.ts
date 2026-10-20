import type { Endpoint, Evidence, FrameworkAdapter, Project } from '@agento/core';
import { DEFAULT_SOURCE_EXCLUSIONS, NoirEndpointDiscoveryProvider } from './noir.js';
import { readRepository } from './repository.js';
import { ExpressSourceAnalyzer } from './source-analyzer.js';
import type { ExpressAdapterOptions, ExpressAnalysis, ExpressDiagnostic } from './types.js';

/** Noir supplies inventory. AgentO independently corroborates routes and enriches their source evidence. */
export class ExpressFrameworkAdapter implements FrameworkAdapter {
  readonly id = 'express-framework-adapter';
  readonly capabilities = ['static-endpoint-discovery', 'route-extraction', 'middleware-extraction',
    'configuration-extraction', 'database-observations'] as const;
  private readonly provider;
  private readonly source;
  private readonly excludePaths;
  constructor(options: ExpressAdapterOptions = {}) {
    this.excludePaths = [...new Set([...DEFAULT_SOURCE_EXCLUSIONS, ...(options.excludePaths ?? []), ...(options.noir?.excludePaths ?? [])])];
    this.provider = options.endpointDiscoveryProvider ?? new NoirEndpointDiscoveryProvider({ ...options.noir,
      excludePaths: this.excludePaths, ...(options.now ? { now: options.now } : {}) });
    this.source = new ExpressSourceAnalyzer({ ...options, excludePaths: this.excludePaths });
  }
  async supports(project: Project): Promise<boolean> {
    if (!project.repositoryPath || !project.languages.some(language => ['javascript', 'typescript'].includes(language))) return false;
    const repository = await readRepository(project.repositoryPath, this.excludePaths);
    return [...repository.files.values()].some(file => /(?:from\s*|require\s*\(\s*)['"]express['"]/.test(file.text));
  }
  async extract(project: Project): Promise<ExpressAnalysis> {
    const inventory = await this.provider.discover(project);
    const source = await this.source.extract(project);
    const evidence: Evidence[] = inventory.evidence.filter(item => !item.endpointId);
    const endpoints = new Map<string, Endpoint>();
    let validated = 0;
    let sourceSupplementCount = 0;
    const sourceEvidence = new Map(source.evidence.map(item => [item.id, item]));
    const inventoryEvidence = new Map(inventory.evidence.map(item => [item.id, item]));
    const routes = new Map(source.evidence.filter(item => item.endpointId && item.facts.observation === 'route').map(item => [item.endpointId!, item]));
    const route = (endpoint: Endpoint) => routes.get(endpoint.id);
    const safe = (endpoint: Endpoint) => route(endpoint)?.facts.conditional === false
      && /^\/(?:[A-Za-z0-9._~-]+|:[A-Za-z_]\w*)?(?:\/(?:[A-Za-z0-9._~-]+|:[A-Za-z_]\w*))*\/?$/.test(endpoint.path);
    const declarations = new Map<string, Endpoint[]>();
    const key = (method: string, path: string, file: string, line: number) => JSON.stringify([method, path, file, line]);
    for (const endpoint of source.endpoints) {
      const declaration = route(endpoint);
      if (!safe(endpoint) || !declaration?.source) continue;
      for (const path of new Set([endpoint.path, declaration.facts.declaredPath])) {
        if (typeof path !== 'string') continue;
        const identity = key(endpoint.method, path, declaration.source.file, declaration.source.startLine);
        declarations.set(identity, [...(declarations.get(identity) ?? []), endpoint]);
      }
    }
    const retainSource = (endpoint: Endpoint, providerId: string) => {
      if (!endpoints.has(endpoint.id)) {
        evidence.push(...endpoint.evidenceIds.flatMap(id => sourceEvidence.has(id) ? [sourceEvidence.get(id)!] : []));
        endpoints.set(endpoint.id, { ...endpoint, discovery: { providerId, validation: 'source-corroborated' } });
        validated++;
      }
    };
    for (const candidate of inventory.endpoints) {
      const candidateEvidence = candidate.evidenceIds.flatMap(id => inventoryEvidence.has(id) ? [inventoryEvidence.get(id)!] : []);
      const matches = [...new Map(candidateEvidence.flatMap(item => item.source
        ? declarations.get(key(candidate.method, candidate.path, item.source.file, item.source.startLine)) ?? [] : [])
        .map(endpoint => [endpoint.id, endpoint])).values()];
      // Compare the declaration, source and method. AgentO's independently resolved mounts win.
      if (!matches.length) {
        endpoints.set(candidate.id, { ...candidate, authentication: 'unknown', roles: [],
          discovery: { providerId: this.provider.id, validation: 'candidate' } });
        evidence.push(...candidateEvidence);
        continue;
      }
      for (const match of matches) {
        retainSource(match, this.provider.id);
        const retained = candidateEvidence.map(item => ({
          ...item, id: `${item.id}:${match.id}`, endpointId: match.id,
        }));
        evidence.push(...retained);
        const previous = endpoints.get(match.id)!;
        endpoints.set(match.id, { ...previous, evidenceIds: [...previous.evidenceIds, ...retained.map(item => item.id)] });
      }
    }
    // Preserve independently known routes that a successful inventory run collapsed or omitted.
    // Failure never silently falls back to the legacy extractor.
    if (inventory.discovery.status === 'completed' || inventory.discovery.status === 'partial') {
      for (const endpoint of source.endpoints) if (safe(endpoint) && !endpoints.has(endpoint.id)) {
        retainSource(endpoint, 'express-source-validation'); sourceSupplementCount++;
      }
    }
    const diagnostics: ExpressDiagnostic[] = [...source.diagnostics,
      ...inventory.discovery.diagnostics.map(item => ({ ...item, source: { file: '.', startLine: 1 } }))];
    if (endpoints.size > validated) diagnostics.push({ code: 'unvalidated-endpoint', source: { file: '.', startLine: 1 },
      message: 'Some inventory routes lack independent source validation and cannot drive tests.' });
    const uniqueDiagnostics = [...new Map(diagnostics.map(item => [JSON.stringify(item), item])).values()];
    const run = inventory.evidence.find(item => item.facts.observation === 'endpoint-discovery-run');
    if (run) evidence.push({ ...run, id: `${run.id}:validation`, producerId: this.id,
      summary: 'AgentO source validation of static endpoint inventory.',
      facts: { observation: 'endpoint-validation-run', candidateCount: endpoints.size - validated, sourceSupplementCount,
        sourceCorroboratedCount: validated, completeCoverage: false, runtimeVerified: false } });
    const componentIds = new Set([...endpoints.values()].map(endpoint => endpoint.componentId));
    return { ...inventory, components: [...inventory.components, ...source.components].filter(item => componentIds.has(item.id)),
      endpoints: [...endpoints.values()], evidence: [...new Map(evidence.map(item => [item.id, item])).values()], diagnostics: uniqueDiagnostics };
  }
}

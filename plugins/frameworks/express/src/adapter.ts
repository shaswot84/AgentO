import { createHash } from 'node:crypto';
import ts from 'typescript-parser';
import type { Component, Endpoint, Evidence, FrameworkAdapter, JsonValue, Project } from '@agento/core';
import { observeHandler } from './observations.js';
import { readRepository } from './repository.js';
import { extractRoutes } from './routes.js';
import { isFunction, Syntax } from './syntax.js';
import type { ExpressAdapterOptions, ExpressAnalysis } from './types.js';

function identifier(...parts: string[]): string {
  return `express:${createHash('sha256').update(JSON.stringify(parts)).digest('hex').slice(0, 24)}`;
}

/** Syntax extraction only. No HTTP, browser, security verdict, or target code execution. */
export class ExpressFrameworkAdapter implements FrameworkAdapter {
  readonly id = 'express-framework-adapter';
  readonly capabilities = ['route-extraction', 'middleware-extraction', 'configuration-extraction', 'database-observations'] as const;
  private readonly now: () => string;
  constructor(options: ExpressAdapterOptions = {}) { this.now = options.now ?? (() => new Date().toISOString()); }

  async supports(project: Project): Promise<boolean> {
    if (!project.repositoryPath || !project.languages.some(language => ['javascript', 'typescript'].includes(language))) return false;
    const repository = await readRepository(project.repositoryPath);
    if (repository.diagnostics.length) return false;
    const syntax = new Syntax(repository);
    return extractRoutes(syntax, []).length > 0;
  }

  async extract(project: Project): Promise<ExpressAnalysis> {
    if (!project.repositoryPath) return { components: [], endpoints: [], resources: [], signals: [], evidence: [],
      diagnostics: [{ code: 'repository-unavailable', source: { file: '.', startLine: 1 }, message: 'A repository path is required.' }] };
    const repository = await readRepository(project.repositoryPath);
    const syntax = new Syntax(repository);
    const diagnostics = [...repository.diagnostics];
    const routes = extractRoutes(syntax, diagnostics);
    const components: Component[] = [];
    const endpoints: Endpoint[] = [];
    const evidence: Evidence[] = [];
    const capturedAt = this.now();
    const componentId = identifier(project.id, 'service');
    if (routes.length) components.push({ id: componentId, projectId: project.id, name: project.name, kind: 'service' });
    for (const route of routes) {
      const source = syntax.source(route.node);
      const mountLocations = route.mounts.map(node => syntax.source(node));
      const endpointId = identifier(project.id, route.method, route.path, JSON.stringify(source), String(route.node.getStart()),
        JSON.stringify(route.mounts.map(node => [syntax.source(node), node.getStart()])));
      const references = new Set<string>();
      function add(kind: Evidence['kind'], node: import('typescript-parser').Node, facts: Record<string, JsonValue>): void {
        const location = syntax.source(node);
        const id = identifier(endpointId, kind, JSON.stringify(location), String(node.getStart()), JSON.stringify(facts));
        if (references.has(id)) return;
        references.add(id);
        evidence.push({ id, projectId: project.id, producerId: 'express-framework-adapter', capturedAt, kind,
          source: location, endpointId, summary: `Express source observation: ${String(facts.observation)}.`, facts });
      }
      const inputs = new Map<string, Endpoint['parameters'][number]>();
      // Path templates are observations even when the handler does not read the parameter.
      for (const match of route.path.matchAll(/[:*]([A-Za-z_]\w*|"[^"]+")/g)) {
        const name = match[1]!.replace(/^"|"$/g, '');
        const before = route.path.slice(0, match.index);
        const insideGroup = (before.match(/\{/g) ?? []).length > (before.match(/\}/g) ?? []).length;
        const optional = insideGroup || route.path[match.index + match[0].length] === '?';
        inputs.set(`path:${name}`, { name, location: 'path', required: !optional });
      }
      let authRequired = false;
      let bodyUsed = false;
      const roles = new Set<string>();
      const handlers: JsonValue[] = [];
      for (const handler of route.handlers) {
        const resolved = syntax.resolve(handler);
        const binding = syntax.binding(handler) ?? (ts.isCallExpression(resolved) ? syntax.binding(resolved.expression) : undefined);
        const symbol = isFunction(resolved) && resolved.name ? resolved.name.text
          : /^[A-Za-z_$][\w$]*$/.test(handler.getText()) ? handler.getText() : 'anonymous';
        handlers.push({ name: symbol, source: { ...syntax.source(resolved) },
          ...(binding ? { package: binding.package } : {}) });
        const observed = observeHandler(syntax, handler);
        for (const input of observed.parameters) {
          const key = `${input.location}:${input.name}`;
          if (!inputs.has(key)) inputs.set(key, input);
        }
        authRequired ||= observed.authRequired;
        bodyUsed ||= observed.bodyUsed;
        observed.roles.forEach(role => roles.add(role));
        for (const observation of observed.observations) add(observation.kind, observation.node, observation.facts);
        const knownMiddleware = binding && (['express-session', 'cookie-parser', 'cors'].includes(binding.package)
          || (binding.package === 'express' && ['json', 'urlencoded', 'raw', 'text', 'static'].includes(binding.name)));
        if (!isFunction(resolved) && !knownMiddleware) {
          diagnostics.push({ code: 'unresolved-handler', source: syntax.source(handler), message: 'Handler or middleware could not be resolved.' });
        }
      }
      const lastHandler = route.handlers.at(-1);
      const resolvedHandler = lastHandler && syntax.resolve(lastHandler);
      const handlerSource = resolvedHandler && isFunction(resolvedHandler) ? syntax.source(resolvedHandler,
        resolvedHandler.name?.text ?? (lastHandler && /^[\w$]+$/.test(lastHandler.getText()) ? lastHandler.getText() : 'anonymous')) : undefined;
      add('source-location', route.node, { observation: 'route', method: route.method, path: route.path,
        handlers, mounts: mountLocations.map(item => ({ ...item })), bodyUsed,
        conditional: route.conditional, runtimeVerified: false });
      endpoints.push({ id: endpointId, componentId, method: route.method, path: route.path,
        parameters: [...inputs.values()].sort((a, b) => a.location.localeCompare(b.location) || a.name.localeCompare(b.name)),
        authentication: authRequired && !route.conditional ? 'required' : 'unknown',
        roles: route.conditional ? [] : [...roles].sort(), ...(handlerSource ? { handler: handlerSource } : {}),
        evidenceIds: [...references] });
    }
    return { components, endpoints, resources: [], signals: [], evidence, diagnostics };
  }
}

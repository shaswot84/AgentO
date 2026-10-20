import ts from 'typescript-parser';
import type { Endpoint } from '@agento/core';
import { isFunction, member, Syntax, unwrap, walk } from './syntax.js';
import type { ExpressDiagnostic } from './types.js';

export const methods: readonly Endpoint['method'][] = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'];
interface Container { readonly node: ts.CallExpression; readonly kind: 'app' | 'router'; readonly events: Event[] }
interface Event {
  readonly node: ts.CallExpression;
  readonly method: string;
  readonly paths: readonly string[];
  readonly handlers: readonly ts.Expression[];
  readonly conditional: boolean;
}
export interface Route {
  readonly method: Endpoint['method'];
  readonly path: string;
  readonly declaredPath: string;
  readonly node: ts.CallExpression;
  readonly handlers: readonly ts.Expression[];
  readonly conditional: boolean;
  readonly mounts: readonly ts.CallExpression[];
}

function fullPath(prefix: string, path: string): string {
  return `${prefix === '/' ? '' : prefix.replace(/\/$/, '')}${path === '/' ? '' : path}` || '/';
}
function under(path: string, prefix: string): boolean {
  if (prefix === '/') return true;
  const p = prefix.replace(/\/$/, '').split('/'), actual = path.split('/');
  return p.every((segment, i) => segment.startsWith(':') ? actual[i] !== undefined : segment === actual[i]);
}

export function conditional(node: ts.Node): boolean {
  let parent = node.parent;
  while (parent && !isFunction(parent) && !ts.isSourceFile(parent)) {
    if (ts.isIfStatement(parent) || ts.isConditionalExpression(parent) || ts.isIterationStatement(parent, false)
      || ts.isSwitchStatement(parent) || ts.isCatchClause(parent)) return true;
    parent = parent.parent;
  }
  return false;
}

/** Reconstruct declared route and mount topology without importing Express or the application. */
export function extractRoutes(syntax: Syntax, diagnostics: ExpressDiagnostic[]): Route[] {
  const containers = new Map<ts.Node, Container>();
  const calls: ts.CallExpression[] = [];
  for (const file of syntax.repository.files.values()) walk(file, node => {
    if (ts.isCallExpression(node)) calls.push(node);
    if (!ts.isVariableDeclaration(node) || !node.initializer) return;
    const init = syntax.resolve(node.initializer);
    if (!ts.isCallExpression(init)) return;
    const binding = syntax.binding(init.expression);
    if (binding?.package === 'express' && ['default', 'Router'].includes(binding.name)) {
      containers.set(init, { node: init, kind: binding.name === 'Router' ? 'router' : 'app', events: [] });
    }
  });
  function container(node: ts.Node, seen = new Set<ts.Node>()): Container | undefined {
    const resolved = syntax.resolve(node);
    if (seen.has(resolved)) return;
    seen.add(resolved);
    const found = containers.get(resolved);
    if (found) return found;
    if (ts.isCallExpression(resolved)) {
      const method = member(resolved.expression);
      if (method && ['route', 'use', 'all', ...methods.map(item => item.toLowerCase())].includes(method.name)) {
        return container(method.base, seen);
      }
    }
    return;
  }
  function flatten(node: ts.Expression, depth = 0): ts.Expression[] {
    if (depth > 12) {
      diagnostics.push({ code: 'limit-reached', source: syntax.source(node), message: 'Middleware array resolution limit reached.' });
      return [node];
    }
    const resolved = syntax.resolve(node);
    return ts.isArrayLiteralExpression(resolved) ? resolved.elements.flatMap(element =>
      ts.isSpreadElement(element) ? flatten(element.expression, depth + 1) : flatten(element, depth + 1)) : [node];
  }
  for (const call of calls) {
    const property = member(call.expression);
    if (!property || !['use', 'all', ...methods.map(item => item.toLowerCase())].includes(property.name)) continue;
    const owner = container(property.base);
    if (!owner || !call.arguments.length) continue;
    let pathExpression = call.arguments[0]!;
    let handlers = call.arguments.slice(1);
    let base = unwrap(property.base);
    while (ts.isCallExpression(base)) {
      const previous = member(base.expression);
      if (!previous) break;
      if (previous.name === 'route') {
        if (base.arguments[0]) { pathExpression = base.arguments[0]; handlers = [...call.arguments]; }
        break;
      }
      if (![...methods.map(item => item.toLowerCase()), 'all'].includes(previous.name)) break;
      base = unwrap(previous.base);
    }
    let paths = syntax.paths(pathExpression);
    // app.get(setting) retrieves configuration; it does not register a route.
    if (property.name === 'get' && handlers.length === 0 && !paths && typeof syntax.value(pathExpression) === 'string') continue;
    if (property.name === 'use' && !paths) {
      const first = syntax.resolve(pathExpression);
      if (container(first) || isFunction(first) || ts.isCallExpression(first) || ts.isArrayLiteralExpression(first)) {
        paths = ['/']; handlers = [...call.arguments];
      }
    }
    if (!paths) {
      diagnostics.push({ code: 'unresolved-route', source: syntax.source(call), message: 'Computed or regular-expression route path was not resolved.' });
      continue;
    }
    const isConditional = conditional(call);
    if (isConditional) diagnostics.push({ code: 'conditional-registration', source: syntax.source(call),
      message: 'Route or middleware registration is conditional; runtime availability is unknown.' });
    owner.events.push({ node: call, method: property.name, paths, handlers: handlers.flatMap(handler => flatten(handler)), conditional: isConditional });
  }
  for (const owner of containers.values()) owner.events.sort((a, b) =>
    a.node.getSourceFile().fileName.localeCompare(b.node.getSourceFile().fileName) || a.node.getStart() - b.node.getStart());
  const mounted = new Set<Container>();
  for (const owner of containers.values()) for (const event of owner.events) {
    if (event.method === 'use') for (const handler of event.handlers) {
      const child = container(handler); if (child) mounted.add(child);
    }
  }
  const routes: Route[] = [];
  interface Middleware { prefix: string; expression: ts.Expression; conditional: boolean }
  function visit(owner: Container, prefix: string, inherited: readonly Middleware[], stack: readonly Container[],
    mounts: readonly ts.CallExpression[], isConditional: boolean): void {
    if (stack.includes(owner)) {
      diagnostics.push({ code: 'router-cycle', source: syntax.source(owner.node), message: 'Cyclic router mount was skipped.' }); return;
    }
    if (stack.length > 40 || routes.length >= 10_000) {
      diagnostics.push({ code: 'limit-reached', source: syntax.source(owner.node), message: 'Route expansion limit reached.' }); return;
    }
    const middleware = [...inherited];
    for (const event of owner.events) for (const path of event.paths) {
      const joined = fullPath(prefix, path);
      if (event.method === 'use') {
        for (const handler of event.handlers) {
          const child = container(handler);
          if (child) visit(child, joined, middleware, [...stack, owner],
            [...mounts, event.node], isConditional || event.conditional);
          else middleware.push({ prefix: joined, expression: handler, conditional: event.conditional });
        }
      } else {
        const applicable = middleware.filter(item => under(joined, item.prefix));
        for (const method of event.method === 'all' ? methods : [event.method.toUpperCase() as Endpoint['method']]) {
          if (routes.length >= 10_000) {
            diagnostics.push({ code: 'limit-reached', source: syntax.source(event.node), message: 'Route expansion limit reached.' });
            return;
          }
          routes.push({ method, path: joined, declaredPath: path, node: event.node,
            handlers: [...applicable.map(item => item.expression), ...event.handlers], mounts,
            conditional: isConditional || event.conditional || applicable.some(item => item.conditional) });
        }
      }
    }
  }
  const apps = [...containers.values()].filter(item => item.kind === 'app' && !mounted.has(item));
  const roots = apps.length ? apps : [...containers.values()].filter(item => !mounted.has(item));
  for (const root of roots) visit(root, '/', [], [], [], false);
  return routes;
}

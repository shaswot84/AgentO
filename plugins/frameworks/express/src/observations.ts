import ts from 'typescript-parser';
import type { Endpoint, JsonValue } from '@agento/core';
import { isFunction, member, Syntax, unwrap, walk } from './syntax.js';
import type { FunctionNode } from './syntax.js';

type Facts = Record<string, JsonValue>;
export interface Observation { readonly node: ts.Node; readonly facts: Facts; readonly kind: 'source-location' | 'configuration' }
export interface HandlerObservation {
  readonly parameters: Endpoint['parameters'];
  readonly bodyUsed: boolean;
  readonly authRequired: boolean;
  readonly roles: readonly string[];
  readonly observations: readonly Observation[];
}
const configKeys: Readonly<Record<string, readonly string[]>> = {
  session: ['name', 'secret', 'resave', 'saveUninitialized', 'rolling', 'proxy', 'cookie'],
  cookie: ['httpOnly', 'secure', 'sameSite', 'maxAge', 'expires', 'domain', 'path', 'signed', 'partitioned', 'priority'],
  cors: ['origin', 'credentials', 'methods', 'allowedHeaders', 'exposedHeaders', 'maxAge', 'preflightContinue', 'optionsSuccessStatus'],
};

function options(syntax: Syntax, node: ts.Node | undefined, kind: string): JsonValue {
  const evaluated = syntax.value(node);
  if (typeof evaluated !== 'object' || evaluated === null || Array.isArray(evaluated)) return { kind: 'dynamic' };
  if ('kind' in evaluated) return { kind: 'dynamic' };
  const properties = evaluated as Readonly<Record<string, JsonValue>>;
  const result: Facts = {};
  for (const key of configKeys[kind] ?? []) {
    if (properties[key] !== undefined) result[key] = key === 'cookie' ? optionsFromValue(properties[key]!, 'cookie') : properties[key]!;
  }
  if ('[spread]' in evaluated || '[computed]' in evaluated) result.unresolvedProperties = true;
  return result;
}
function optionsFromValue(value: JsonValue, kind: string): JsonValue {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { kind: 'dynamic' };
  if ('kind' in value) return { kind: 'dynamic' };
  return Object.fromEntries(Object.entries(value).filter(([key]) => configKeys[kind]?.includes(key)));
}

function conditions(node: ts.Node): JsonValue[] {
  const result: JsonValue[] = [];
  let child = node, parent = child.parent;
  while (parent && !isFunction(parent) && !ts.isSourceFile(parent)) {
    if (ts.isIfStatement(parent)) result.push({ kind: 'conditional', branch: child === parent.elseStatement ? 'else' : 'then' });
    if (ts.isConditionalExpression(parent)) result.push({ kind: 'conditional' });
    child = parent; parent = parent.parent;
  }
  return result;
}

export function observeHandler(syntax: Syntax, expression: ts.Expression): HandlerObservation {
  const observations: Observation[] = [];
  const params = new Map<string, Endpoint['parameters'][number]>();
  const roles = new Set<string>();
  let bodyUsed = false;
  let authRequired = false;
  const visited = new Set<ts.Node>();
  const parameter = (name: string, location: Endpoint['parameters'][number]['location']) => {
    params.set(`${location}:${name}`, { name, location, required: false });
    if (location === 'body') bodyUsed = true;
  };
  function access(node: ts.Node, roots: ReadonlySet<ts.Node>, seen = new Set<ts.Node>()): string[] | undefined {
    node = unwrap(node);
    if (seen.has(node)) return;
    seen.add(node);
    const part = member(node);
    if (part) { const base = access(part.base, roots, seen); return base && [...base, part.name]; }
    if (ts.isIdentifier(node)) {
      const declaration = syntax.declaration(node);
      if (declaration && roots.has(declaration)) return [];
      const resolved = syntax.resolve(node);
      if (resolved !== node) return access(resolved, roots, seen);
    }
    return;
  }
  function emit(node: ts.Node, observation: string, facts: Facts, configuration = false): void {
    observations.push({ node, kind: configuration ? 'configuration' : 'source-location',
      facts: { observation, ...facts, conditions: conditions(node), runtimeVerified: false } });
  }
  function scan(fn: FunctionNode, requestRoots: ReadonlySet<ts.Node>, responseRoots: ReadonlySet<ts.Node>, depth: number): void {
    if (visited.has(fn) || depth > 12 || !fn.body) return;
    visited.add(fn);
    const locationKinds: Record<string, Endpoint['parameters'][number]['location']> = {
      params: 'path', query: 'query', body: 'body', headers: 'header', cookies: 'cookie', signedCookies: 'cookie',
    };
    // Do not treat nested callbacks as route handlers; helper calls are followed explicitly below.
    function inspect(node: ts.Node): void {
      if (node !== fn && isFunction(node)) return;
      const parts = access(node, requestRoots);
      if (parts?.[0] === 'body') bodyUsed = true;
      if (parts && parts.length >= 2 && locationKinds[parts[0]!]) parameter(parts[1]!, locationKinds[parts[0]!]!);
      if (ts.isVariableDeclaration(node) && node.initializer && ts.isObjectBindingPattern(node.name)) {
        const input = access(node.initializer, requestRoots);
        if (input?.length === 1 && locationKinds[input[0]!]) for (const element of node.name.elements) {
          if (element.dotDotDotToken) { parameter('*', locationKinds[input[0]!]!); continue; }
          const field = element.propertyName ?? element.name;
          if (ts.isIdentifier(field) || ts.isStringLiteralLike(field)) parameter(field.text, locationKinds[input[0]!]!);
        }
      }
      if (ts.isCallExpression(node)) {
        const method = member(node.expression);
        const response = method && access(method.base, responseRoots);
        const binding = syntax.binding(node.expression);
        if (method && ['get', 'header'].includes(method.name) && access(method.base, requestRoots)?.length === 0) {
          const header = syntax.value(node.arguments[0]);
          if (typeof header === 'string') parameter(header.toLowerCase(), 'header');
        }
        if (response?.length === 0 && method?.name === 'cookie') {
          const name = syntax.value(node.arguments[0]);
          emit(node, 'cookie', { name: typeof name === 'string' ? name : { kind: 'dynamic' },
            options: options(syntax, node.arguments[2], 'cookie') }, true);
        }
        if (response?.length === 0 && method && ['setHeader', 'header', 'set'].includes(method.name)) {
          const header = syntax.value(node.arguments[0]);
          if (typeof header === 'string' && header.toLowerCase().startsWith('access-control-')) {
            emit(node, 'cors-header', { header: header.toLowerCase(), value: syntax.value(node.arguments[1]),
              requestInput: access(node.arguments[1] ?? node, requestRoots)?.join('.') ?? null }, true);
          }
        }
        if (method?.name === 'includes' && node.arguments[0] && access(node.arguments[0], requestRoots)?.join('.') === 'headers.origin') {
          const origins = syntax.value(method.base);
          if (Array.isArray(origins) && origins.every(origin => typeof origin === 'string')) {
            emit(node, 'cors-origin-allowlist', { origins, requestInput: 'headers.origin' }, true);
          }
        }
        if (binding?.package === 'express-session' || binding?.package === 'cors' || binding?.package === 'cookie-parser') {
          const kind = binding.package === 'express-session' ? 'session' : binding.package === 'cors' ? 'cors' : 'cookie-parser';
          emit(node, kind, { options: kind === 'cookie-parser' ? { secret: node.arguments.length ? '[REDACTED]' : null }
            : options(syntax, node.arguments[0], kind) }, true);
        }
        // Recognize SQL execution/preparation on imported DB handles and statement aliases.
        if (method && ['prepare', 'query', 'execute', 'exec', 'get', 'all', 'run'].includes(method.name)) {
          const base = syntax.resolve(method.base);
          const prepared = ts.isCallExpression(base) && member(base.expression)?.name === 'prepare' ? base : undefined;
          const databaseMethod = ['prepare', 'query', 'execute', 'exec'].includes(method.name);
          const sqlNode = databaseMethod ? node.arguments[0] : prepared?.arguments[0];
          if (sqlNode) {
            const sql = syntax.sqlShape(sqlNode);
            const literal = sql.text;
            if (literal && /\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b/i.test(literal)) {
              const operation = literal.match(/\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b/i)?.[1]?.toUpperCase() ?? 'UNKNOWN';
              const tables = [...literal.matchAll(/\b(?:FROM|JOIN|INTO|UPDATE|TABLE(?:\s+IF\s+(?:NOT\s+)?EXISTS)?)\s+([A-Za-z_]\w*)/gi)]
                .map(match => match[1]!);
              emit(node, 'database-operation', { api: method.name, operation, tables: [...new Set(tables)].sort(),
                interpolated: sql.interpolated, placeholders: (literal.match(/\?/g) ?? []).length,
                argumentCount: databaseMethod ? Math.max(0, node.arguments.length - 1) : node.arguments.length });
            } else if (databaseMethod && method.name !== 'get') {
              emit(node, 'database-operation', { api: method.name, operation: 'UNKNOWN', sql: { kind: 'dynamic' } });
            }
          }
        }
        const target = syntax.resolve(node.expression);
        if (isFunction(target)) {
          const helperRequest = new Set<ts.Node>(), helperResponse = new Set<ts.Node>();
          node.arguments.forEach((arg, i) => {
            const targetParam = target.parameters[i];
            if (!targetParam) return;
            if (access(arg, requestRoots)?.length === 0) helperRequest.add(targetParam);
            if (access(arg, responseRoots)?.length === 0) helperResponse.add(targetParam);
          });
          scan(target, helperRequest, helperResponse, depth + 1);
        }
      }
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        const assignment = access(node.left, requestRoots);
        if (assignment?.[0] === 'session' && assignment[1] === 'cookie' && assignment[2]) {
          emit(node, 'session-cookie-update', { attribute: assignment[2], value: syntax.value(node.right) }, true);
        }
      }
      ts.forEachChild(node, inspect);
    }
    inspect(fn.body);
    function missingIdentity(node: ts.Node, depth = 0): boolean {
      if (depth > 12) return false;
      node = unwrap(node);
      if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.ExclamationToken) {
        const input = access(node.operand, requestRoots);
        return input?.[0] === 'user' || (input?.[0] === 'session' && input[1] === 'user');
      }
      if (ts.isBinaryExpression(node)) {
        if (node.operatorToken.kind === ts.SyntaxKind.BarBarToken) return missingIdentity(node.left, depth + 1) || missingIdentity(node.right, depth + 1);
        if (node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) return missingIdentity(node.left, depth + 1) && missingIdentity(node.right, depth + 1);
        if ([ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.EqualsEqualsEqualsToken].includes(node.operatorToken.kind)) {
          const input = access(node.left, requestRoots);
          return (input?.[0] === 'user' || (input?.[0] === 'session' && input[1] === 'user'))
            && (node.right.kind === ts.SyntaxKind.NullKeyword || (ts.isIdentifier(node.right) && node.right.text === 'undefined'));
        }
      }
      const resolved = syntax.resolve(node);
      return resolved !== node && missingIdentity(resolved, depth + 1);
    }
    function within(node: ts.Node, visit: (child: ts.Node) => void): void {
      if (isFunction(node)) return;
      visit(node); ts.forEachChild(node, child => within(child, visit));
    }
    // Authentication is observed only for direct identity-dependent rejection guards.
    // A guard nested behind another condition remains conditional.
    within(fn.body, node => {
      if (!ts.isIfStatement(node)) return;
      let identity = false, role = false;
      const observedRoles = new Set<string>();
      walk(node.expression, child => {
        const reference = access(child, requestRoots);
        if (reference?.[0] === 'session' || reference?.[0] === 'user') identity = true;
        if (reference?.includes('role') || reference?.includes('roles')) role = true;
        if (ts.isBinaryExpression(child) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken,
          ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken].includes(child.operatorToken.kind)) {
          const left = access(child.left, requestRoots), right = access(child.right, requestRoots);
          const roleValue = left?.includes('role') ? syntax.value(child.right) : right?.includes('role') ? syntax.value(child.left) : undefined;
          if (typeof roleValue === 'string' && /^[\w-]{1,64}$/.test(roleValue)) observedRoles.add(roleValue);
        }
      });
      let unauthorized = false, forbidden = false, nestedRejection = false;
      within(node.thenStatement, child => {
        if (!ts.isCallExpression(child)) return;
        const method = member(child.expression);
        if (!method || !['status', 'sendStatus'].includes(method.name) || access(method.base, responseRoots)?.length !== 0) return;
        const status = syntax.value(child.arguments[0]);
        if (status === 401) unauthorized = true;
        if (status === 403) forbidden = true;
        if ((status === 401 || status === 403) && conditions(child).length > conditions(node).length + 1) nestedRejection = true;
      });
      const isConditional = conditions(node).length > 0 || nestedRejection;
      if (identity && unauthorized) {
        const conditionalGuard = isConditional || !missingIdentity(node.expression);
        if (!conditionalGuard) authRequired = true;
        emit(node, 'authentication-guard', { enforcement: conditionalGuard ? 'conditional' : 'observed', status: 401 });
      }
      if (role && forbidden) {
        if (!isConditional) observedRoles.forEach(value => roles.add(value));
        emit(node, 'authorization-guard', { enforcement: isConditional ? 'conditional' : 'observed', roles: [...observedRoles], status: 403 });
      }
    });
  }
  const resolved = syntax.resolve(expression);
  if (isFunction(resolved)) scan(resolved, new Set(resolved.parameters[0] ? [resolved.parameters[0]] : []),
    new Set(resolved.parameters[1] ? [resolved.parameters[1]] : []), 0);
  else if (ts.isCallExpression(resolved)) {
    const binding = syntax.binding(resolved.expression);
    if (binding && ['express-session', 'cors', 'cookie-parser'].includes(binding.package)) {
      const kind = binding.package === 'express-session' ? 'session' : binding.package === 'cors' ? 'cors' : 'cookie-parser';
      emit(resolved, kind, { options: kind === 'cookie-parser' ? { secret: resolved.arguments.length ? '[REDACTED]' : null }
        : options(syntax, resolved.arguments[0], kind) }, true);
    }
  }
  return { parameters: [...params.values()], bodyUsed, authRequired, roles: [...roles].sort(), observations };
}

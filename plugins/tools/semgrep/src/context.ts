import ts from 'typescript-parser';
import type { JsonValue, SourceLocation } from '@agento/core';
import type { Inventory } from './repository.js';

export const member = (node: ts.Node): { base: ts.Expression; name: string } | undefined => {
  if (ts.isPropertyAccessExpression(node)) return { base: node.expression, name: node.name.text };
  if (ts.isElementAccessExpression(node) && node.argumentExpression && ts.isStringLiteralLike(node.argumentExpression)) {
    return { base: node.expression, name: node.argumentExpression.text };
  }
  return undefined;
};
const isFunction = (node: ts.Node): node is ts.FunctionLikeDeclaration => ts.isFunctionDeclaration(node)
  || ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node);
const location = (node: ts.Node): SourceLocation => ({ file: node.getSourceFile().fileName,
  startLine: node.getSourceFile().getLineAndCharacterOfPosition(node.getStart()).line + 1,
  endLine: node.getSourceFile().getLineAndCharacterOfPosition(node.getEnd()).line + 1 });
const asFact = (value: SourceLocation): JsonValue => ({ ...value });
const sanitizers = new Set(['escapeHtml', 'sanitizeHtml']);

/** Bounded syntax context, not a second taint engine or a runtime verdict. */
export class SourceContext {
  private readonly checker: ts.TypeChecker;
  constructor(inventory: Inventory) {
    const host: ts.CompilerHost = {
      getSourceFile: file => inventory.files.get(file), getDefaultLibFileName: () => '',
      writeFile: () => {}, getCurrentDirectory: () => '/', getDirectories: () => [],
      fileExists: file => inventory.files.has(file), readFile: file => inventory.files.get(file)?.text,
      getCanonicalFileName: file => file, useCaseSensitiveFileNames: () => true, getNewLine: () => '\n',
    };
    this.checker = ts.createProgram([...inventory.files.keys()], { allowJs: true, noLib: true, noResolve: true }, host).getTypeChecker();
  }

  describe(file: ts.SourceFile, start: number, end: number): Record<string, JsonValue> {
    let sink: ts.CallExpression | undefined;
    let nodes = 0;
    function find(node: ts.Node): void {
      if (++nodes > 50_000 || node.getStart() > start || node.getEnd() < end) return;
      if (ts.isCallExpression(node) && node.arguments[0]
        && node.arguments[0].getStart() <= start && node.arguments[0].getEnd() >= end) sink = node;
      ts.forEachChild(node, find);
    }
    find(file);
    if (!sink) return { sources: [], sourceResolution: 'unavailable', sink: { file: file.fileName,
      startLine: file.getLineAndCharacterOfPosition(start).line + 1 }, contextResolution: 'unavailable' };
    let scope: ts.Node = sink;
    while (scope.parent && !isFunction(scope)) scope = scope.parent;
    const assignments = new Map<ts.Symbol, ts.Expression[]>();
    const declarations = new Set<ts.Node>();
    let visitedCount = 0;
    const visitScope = (node: ts.Node): void => {
      if (++visitedCount > 50_000 || (node !== scope && isFunction(node)) || node.getStart() > sink!.getStart()) return;
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left)) {
        const symbol = this.checker.getSymbolAtLocation(node.left);
        if (symbol) assignments.set(symbol, [...(assignments.get(symbol) ?? []), node.right]);
      }
      ts.forEachChild(node, visitScope);
    };
    visitScope(scope);
    const inputs = new Map<string, JsonValue>();
    let limited = visitedCount > 50_000 || nodes > 50_000;
    const trace = (node: ts.Node, depth: number): void => {
      if (depth > 12 || declarations.size > 2_000) { limited = true; return; }
      if (declarations.has(node)) return;
      declarations.add(node);
      // Sanitizer names are rule assumptions; their implementation is never certified here.
      if (ts.isCallExpression(node)) {
        if (ts.isIdentifier(node.expression) && sanitizers.has(node.expression.text)) return;
        const method = member(node.expression);
        if (method?.name === 'sanitize' && ts.isIdentifier(method.base) && method.base.text === 'DOMPurify') return;
      }
      const property = member(node);
      if (property && ['query', 'body', 'params', 'headers', 'cookies'].includes(property.name)) {
        const source = { ...location(node), symbol: property.name };
        const selected = node.parent && member(node.parent);
        inputs.set(JSON.stringify(source), { location: asFact(source), kind: `request-${property.name}`,
          ...(selected && selected.base === node ? { parameterName: selected.name } : {}) });
        return;
      }
      if (ts.isCallExpression(node) && member(node.expression)?.name === 'get') {
        const base = member(node.expression)!.base;
        if (ts.isIdentifier(base) && ['req', 'request'].includes(base.text)) {
          const source = { ...location(node), symbol: 'header' };
          inputs.set(JSON.stringify(source), { location: asFact(source), kind: 'request-header' });
          return;
        }
      }
      if (ts.isIdentifier(node)) {
        const symbol = this.checker.getSymbolAtLocation(node);
        for (const declaration of symbol?.declarations ?? []) {
          if (ts.isVariableDeclaration(declaration) && declaration.initializer) trace(declaration.initializer, depth + 1);
          if (ts.isBindingElement(declaration)) {
            const variable = declaration.parent.parent;
            if (ts.isVariableDeclaration(variable) && variable.initializer) trace(variable.initializer, depth + 1);
          }
        }
        if (symbol) for (const value of assignments.get(symbol) ?? []) trace(value, depth + 1);
        return;
      }
      ts.forEachChild(node, child => trace(child, depth + 1));
    };
    trace(sink.arguments[0]!, 0);
    const conditions: JsonValue[] = [];
    let child: ts.Node = sink, parent = child.parent;
    while (parent && !isFunction(parent) && !ts.isSourceFile(parent)) {
      if (ts.isIfStatement(parent)) conditions.push({ location: asFact(location(parent.expression)),
        kind: 'conditional', branch: child === parent.elseStatement ? 'else' : 'then' });
      child = parent; parent = parent.parent;
    }
    let responseFormat = 'unknown';
    const receiver = (expression: ts.Expression): ts.Symbol | undefined => {
      if (ts.isIdentifier(expression)) return this.checker.getSymbolAtLocation(expression);
      if (ts.isCallExpression(expression)) {
        const method = member(expression.expression);
        if (method) return receiver(method.base);
      }
      return undefined;
    };
    const sinkReceiver = member(sink.expression);
    const receiverSymbol = sinkReceiver && receiver(sinkReceiver.base);
    const inspect = (node: ts.Node): void => {
      if (node !== scope && isFunction(node)) return;
      if (node.getStart() > sink!.getStart()) return;
      if (ts.isCallExpression(node) && receiverSymbol) {
        const method = member(node.expression);
        const literal = (value: ts.Expression | undefined) => value && ts.isStringLiteralLike(value) ? value.text.toLowerCase() : '';
        const type = !method || receiver(method.base) !== receiverSymbol ? '' : method.name === 'type' ? literal(node.arguments[0])
          : method && ['setHeader', 'header', 'set'].includes(method.name) && literal(node.arguments[0]) === 'content-type'
            ? literal(node.arguments[1]) : '';
        if (type.includes('html')) responseFormat = 'html';
        else if (type.includes('json')) responseFormat = 'json';
        else if (type.includes('text/plain') || type === 'text') responseFormat = 'text';
      }
      ts.forEachChild(node, inspect);
    };
    inspect(scope);
    return {
      sink: { location: asFact(location(sink)), kind: member(sink.expression)?.name ?? 'unknown' },
      sources: [...inputs.values()], sourceResolution: limited ? 'bounded-ast-def-use-partial' : 'bounded-ast-def-use',
      contextResolution: 'syntax-only', conditions, responseFormat,
      sanitizerAssumptions: ['DOMPurify.sanitize', 'sanitizeHtml', 'escapeHtml'],
    };
  }
}

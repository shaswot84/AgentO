import { dirname, extname, relative, resolve } from 'node:path';
import ts from 'typescript-parser';
import type { JsonValue, SourceLocation } from '@agento/core';
import type { Repository } from './repository.js';

export function unwrap(node: ts.Node): ts.Node {
  while (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isTypeAssertionExpression(node)
    || ts.isNonNullExpression(node) || ts.isSatisfiesExpression(node)) node = node.expression;
  return node;
}

export function walk(node: ts.Node, visit: (node: ts.Node) => void): void {
  visit(node); ts.forEachChild(node, child => walk(child, visit));
}

export function member(node: ts.Node): { base: ts.Expression; name: string } | undefined {
  node = unwrap(node);
  if (ts.isPropertyAccessExpression(node)) return { base: node.expression, name: node.name.text };
  if (ts.isElementAccessExpression(node) && node.argumentExpression && ts.isStringLiteralLike(node.argumentExpression)) {
    return { base: node.expression, name: node.argumentExpression.text };
  }
  return;
}

export function chain(node: ts.Node): string[] {
  node = unwrap(node);
  const property = member(node);
  if (property) return [...chain(property.base), property.name];
  return ts.isIdentifier(node) ? [node.text] : [];
}

export type FunctionNode = ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction;
export function isFunction(node: ts.Node): node is FunctionNode {
  return ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node);
}

/** Compiler symbols resolve lexical scope and local ESM imports; the host reads only the inventory. */
export class Syntax {
  readonly checker: ts.TypeChecker;
  constructor(readonly repository: Repository) {
    const host: ts.CompilerHost = {
      getSourceFile: file => repository.files.get(file),
      getDefaultLibFileName: () => '', writeFile: () => {}, getCurrentDirectory: () => repository.root,
      getDirectories: () => [], fileExists: file => repository.files.has(file),
      readFile: file => repository.files.get(file)?.text,
      getCanonicalFileName: file => file, useCaseSensitiveFileNames: () => true, getNewLine: () => '\n',
      resolveModuleNames: (names, containingFile) => names.map(name => {
        const file = this.localModule(name, containingFile);
        if (!file) return undefined;
        const extension = extname(file);
        return { resolvedFileName: file, extension: extension === '.ts' ? ts.Extension.Ts
          : extension === '.tsx' ? ts.Extension.Tsx : extension === '.mts' ? ts.Extension.Mts
          : extension === '.cts' ? ts.Extension.Cts : extension === '.jsx' ? ts.Extension.Jsx : ts.Extension.Js };
      }),
    };
    const program = ts.createProgram([...repository.files.keys()], {
      allowJs: true, noLib: true, noResolve: false, module: ts.ModuleKind.NodeNext,
      moduleResolution: ts.ModuleResolutionKind.NodeNext,
    }, host);
    this.checker = program.getTypeChecker();
  }

  localModule(name: string, containingFile: string): string | undefined {
    if (!name.startsWith('.')) return;
    const base = resolve(dirname(containingFile), name);
    const stem = base.replace(/\.(?:[cm]?js|jsx)$/, '');
    return [base, `${stem}.ts`, `${stem}.tsx`, `${stem}.mts`, `${stem}.cts`, `${base}.js`, `${base}.ts`,
      `${base}/index.ts`, `${base}/index.js`].find(file => this.repository.files.has(file));
  }

  source(node: ts.Node, symbol?: string): SourceLocation {
    const file = node.getSourceFile();
    return { file: relative(this.repository.root, file.fileName).replaceAll('\\', '/'),
      startLine: file.getLineAndCharacterOfPosition(node.getStart()).line + 1,
      endLine: file.getLineAndCharacterOfPosition(node.getEnd()).line + 1,
      ...(symbol ? { symbol } : {}) };
  }

  declaration(node: ts.Node): ts.Declaration | undefined {
    const symbol = this.checker.getSymbolAtLocation(node);
    if (!symbol) return;
    const target = symbol.flags & ts.SymbolFlags.Alias ? this.checker.getAliasedSymbol(symbol) : symbol;
    return target.valueDeclaration ?? target.declarations?.[0] ?? symbol.declarations?.[0];
  }

  /** Resolve values, aliases, handlers, and common literal CommonJS local exports. */
  resolve(node: ts.Node, seen = new Set<ts.Node>()): ts.Node {
    node = unwrap(node);
    if (seen.has(node) || seen.size >= 12) return node;
    seen.add(node);
    const decl = this.declaration(node);
    if (decl && decl !== node) {
      if (ts.isVariableDeclaration(decl) && decl.initializer) return this.resolve(decl.initializer, seen);
      if (isFunction(decl)) return decl;
      if (ts.isExportAssignment(decl)) return this.resolve(decl.expression, seen);
      if (ts.isBindingElement(decl) && ts.isVariableDeclaration(decl.parent.parent) && decl.parent.parent.initializer) {
        const required = this.resolve(decl.parent.parent.initializer, new Set(seen));
        const exported = this.commonJSExport(required, (decl.propertyName ?? decl.name).getText());
        if (exported) return this.resolve(exported, seen);
      }
    }
    const property = member(node);
    const required = property ? this.resolve(property.base, new Set(seen)) : node;
    const exported = this.commonJSExport(required, property?.name);
    if (exported) return this.resolve(exported, seen);
    return node;
  }

  private commonJSExport(required: ts.Node, name?: string): ts.Node | undefined {
    if (!ts.isCallExpression(required) || !ts.isIdentifier(required.expression) || required.expression.text !== 'require'
      || !required.arguments[0] || !ts.isStringLiteralLike(required.arguments[0])) return;
    const file = this.localModule(required.arguments[0].text, required.getSourceFile().fileName);
    const source = file && this.repository.files.get(file);
    let exported: ts.Node | undefined;
    if (source) walk(source, child => {
      if (!ts.isBinaryExpression(child) || child.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return;
      const parts = chain(child.left).join('.');
      if (name ? parts === `exports.${name}` || parts === `module.exports.${name}` : parts === 'module.exports') exported = child.right;
      if (name && parts === 'module.exports' && ts.isObjectLiteralExpression(child.right)) {
        for (const prop of child.right.properties) {
          if ((ts.isPropertyAssignment(prop) || ts.isShorthandPropertyAssignment(prop)) && prop.name.getText() === name) {
            exported = ts.isPropertyAssignment(prop) ? prop.initializer : prop.name;
          }
        }
      }
    });
    return exported;
  }

  binding(node: ts.Node, seen = new Set<ts.Node>()): { package: string; name: string } | undefined {
    node = unwrap(node);
    if (seen.has(node) || seen.size >= 12) return;
    seen.add(node);
    const property = member(node);
    if (property) {
      const base = this.binding(property.base, seen);
      if (base) return { package: base.package, name: property.name };
    }
    const decl = this.checker.getSymbolAtLocation(node)?.declarations?.[0];
    if (decl) {
      let current: ts.Node | undefined = decl;
      while (current && !ts.isImportDeclaration(current)) current = current.parent;
      if (current && ts.isStringLiteralLike(current.moduleSpecifier) && !current.importClause?.isTypeOnly) {
        if (ts.isImportSpecifier(decl) && decl.isTypeOnly) return;
        return { package: current.moduleSpecifier.text,
          name: ts.isImportSpecifier(decl) ? (decl.propertyName ?? decl.name).text : 'default' };
      }
      if (ts.isVariableDeclaration(decl) && decl.initializer) return this.binding(decl.initializer, seen);
      if (ts.isBindingElement(decl) && ts.isVariableDeclaration(decl.parent.parent) && decl.parent.parent.initializer) {
        const base = this.binding(decl.parent.parent.initializer, seen);
        if (base) return { package: base.package, name: decl.propertyName?.getText() ?? decl.name.getText() };
      }
    }
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'require'
      && node.arguments[0] && ts.isStringLiteralLike(node.arguments[0])) {
      return { package: node.arguments[0].text, name: 'default' };
    }
    return;
  }

  /** A deliberately small evaluator. Unresolved code stays dynamic and is never run. */
  value(node: ts.Node | undefined, depth = 0): JsonValue {
    if (!node || depth > 12) return { kind: 'dynamic' };
    node = unwrap(node);
    if (ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      try {
        const url = new URL(node.text);
        if (url.username || url.password) return '[REDACTED]';
      } catch { /* Not a URL. */ }
      return node.text;
    }
    if (ts.isNumericLiteral(node)) return Number(node.text);
    if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
    if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
    if (node.kind === ts.SyntaxKind.NullKeyword) return null;
    if (ts.isArrayLiteralExpression(node)) return node.elements.map(item => this.value(item, depth + 1));
    if (ts.isObjectLiteralExpression(node)) {
      const value: Record<string, JsonValue> = {};
      for (const prop of node.properties) {
        if (ts.isSpreadAssignment(prop)) { value['[spread]'] = { kind: 'dynamic' }; continue; }
        if (!ts.isPropertyAssignment(prop) && !ts.isShorthandPropertyAssignment(prop)) continue;
        const key = ts.isComputedPropertyName(prop.name) ? '[computed]' : prop.name.getText().replace(/^['"]|['"]$/g, '');
        const local = ts.isShorthandPropertyAssignment(prop) ? this.checker.getShorthandAssignmentValueSymbol(prop)?.valueDeclaration : undefined;
        const initializer = ts.isPropertyAssignment(prop) ? prop.initializer
          : local && ts.isVariableDeclaration(local) && local.initializer ? local.initializer : prop.name;
        const evaluated = this.value(initializer, depth + 1);
        value[key] = /secret|password|token|credential|authorization|private.?key/i.test(key)
          && !(key === 'credentials' && (typeof evaluated === 'boolean' || (typeof evaluated === 'object' && evaluated !== null && 'kind' in evaluated)))
          ? '[REDACTED]' : evaluated;
      }
      return value;
    }
    if (ts.isBinaryExpression(node) && [ts.SyntaxKind.AsteriskToken, ts.SyntaxKind.PlusToken,
      ts.SyntaxKind.MinusToken, ts.SyntaxKind.SlashToken].includes(node.operatorToken.kind)) {
      const left = this.value(node.left, depth + 1), right = this.value(node.right, depth + 1);
      if (typeof left === 'number' && typeof right === 'number') {
        const result = node.operatorToken.kind === ts.SyntaxKind.AsteriskToken ? left * right
          : node.operatorToken.kind === ts.SyntaxKind.PlusToken ? left + right
          : node.operatorToken.kind === ts.SyntaxKind.MinusToken ? left - right : left / right;
        if (Number.isFinite(result)) return result;
      }
    }
    const resolved = this.resolve(node);
    if (resolved !== node) return this.value(resolved, depth + 1);
    return { kind: 'dynamic' };
  }

  paths(node: ts.Node): string[] | undefined {
    const value = this.value(node);
    if (typeof value === 'string' && value.startsWith('/')) return [value];
    if (Array.isArray(value) && value.length && value.every(item => typeof item === 'string' && item.startsWith('/'))) {
      return value as string[];
    }
    return;
  }

  sqlShape(node: ts.Node, depth = 0): { text: string; interpolated: boolean } {
    if (depth > 12) return { text: '__dynamic__', interpolated: true };
    node = this.resolve(node);
    if (ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node)) return { text: node.text, interpolated: false };
    if (ts.isTemplateExpression(node)) return { text: node.head.text + node.templateSpans.map(span => `__dynamic__${span.literal.text}`).join(''), interpolated: true };
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const left = this.sqlShape(node.left, depth + 1), right = this.sqlShape(node.right, depth + 1);
      return { text: left.text + right.text, interpolated: left.interpolated || right.interpolated };
    }
    return { text: '__dynamic__', interpolated: true };
  }
}

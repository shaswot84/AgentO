import { lstat, open, readdir } from 'node:fs/promises';
import { basename, dirname, extname, join, resolve, sep } from 'node:path';
import ts from 'typescript-parser';
import type { Project } from '@agento/core';
import { authenticationPackages, databasePackages, frameworkPackages, middlewarePackages, ormPackages } from './catalog.js';
import type {
  DependencyKind, DiscoveredDependency, DiscoveredManifest, DiscoveryDiagnostic,
  DiscoveryOptions, DiscoveryResult, MiddlewareObservation, ProjectTarget,
} from './types.js';

const ignoredDirectories = new Set([
  'node_modules', 'dist', 'build', 'coverage', 'vendor', 'venv', '__pycache__',
  'target', 'out', 'bower_components',
]);
const manifestNames = new Set(['package.json', 'pyproject.toml', 'requirements.txt',
  'Pipfile', 'Cargo.toml', 'go.mod', 'Gemfile', 'composer.json', 'pom.xml', 'build.gradle']);
const sourceLanguages: Readonly<Record<string, string>> = {
  '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript', '.mts': 'typescript', '.cts': 'typescript',
  '.py': 'python', '.go': 'go', '.rs': 'rust', '.java': 'java', '.rb': 'ruby',
  '.php': 'php', '.cs': 'csharp', '.kt': 'kotlin',
};
const dependencyKinds: readonly DependencyKind[] = [
  'dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies',
];
// Bound repository traversal and parsing; limits cause a visible black-box fallback.
const maxEntries = 20_000;
const maxDepth = 40;
const maxFileBytes = 1_048_576;
const maxSourceBytes = 16_777_216;

function sorted(values: Iterable<string>): string[] { return [...new Set(values)].sort(); }
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function isTest(file: string): boolean {
  return /(^|\/)(tests?|__tests__|fixtures?)(\/|$)|\.(test|spec)\.[^.]+$/.test(file);
}
function packageName(specifier: string): string | undefined {
  if (specifier.startsWith('.') || specifier.startsWith('/') || specifier.startsWith('#')) return;
  if (specifier.startsWith('node:')) return specifier;
  return specifier.startsWith('@') ? specifier.split('/').slice(0, 2).join('/') : specifier.split('/')[0];
}

/** Read metadata and source syntax only. Never import target code or execute its scripts. */
export async function discoverProject(repositoryPath: string, options: DiscoveryOptions = {}): Promise<DiscoveryResult> {
  const root = resolve(repositoryPath);
  const diagnostics: DiscoveryDiagnostic[] = [];
  const files: string[] = [];
  const directories: string[] = [];
  let entryCount = 0;
  let traversalLimited = false;
  const diagnose = (code: DiscoveryDiagnostic['code'], file: string, message: string) => {
    diagnostics.push({ code, file, message });
  };

  async function walk(directory: string, depth: number): Promise<void> {
    if (depth > maxDepth) {
      diagnose('limit-reached', directory || '.', 'Repository depth limit reached.');
      return;
    }
    let entries;
    try { entries = await readdir(join(root, directory), { withFileTypes: true }); }
    catch { diagnose('read-failed', directory || '.', 'Directory could not be read.'); return; }
    entries.sort((a, b) => a.name.localeCompare(b.name, 'en'));
    for (const entry of entries) {
      if (entry.name.startsWith('.') || entry.isSymbolicLink()) continue;
      if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
      if (++entryCount > maxEntries) {
        if (!traversalLimited) diagnose('limit-reached', '.', 'Repository entry limit reached.');
        traversalLimited = true;
        return;
      }
      const path = directory ? `${directory}/${entry.name}` : entry.name;
      if (entry.isDirectory()) { directories.push(path); await walk(path, depth + 1); }
      else if (entry.isFile()) files.push(path);
      if (traversalLimited) return;
    }
  }

  let repositoryAvailable = false;
  try { repositoryAvailable = (await lstat(root)).isDirectory(); } catch { /* Report below. */ }
  if (repositoryAvailable) await walk('', 0);
  else diagnose('repository-unavailable', '.', 'Repository must be an existing, readable directory (not a symlink).');

  // Use a bounded read even if a file grows after the directory inventory.
  async function read(file: string): Promise<string | undefined> {
    let handle;
    try {
      handle = await open(join(root, ...file.split('/')), 'r');
      const buffer = Buffer.alloc(maxFileBytes + 1);
      let size = 0;
      while (size < buffer.length) {
        const result = await handle.read(buffer, size, buffer.length - size, null);
        if (result.bytesRead === 0) break;
        size += result.bytesRead;
      }
      if (size > maxFileBytes) {
        diagnose('limit-reached', file, 'File exceeds the discovery size limit.');
        return;
      }
      return buffer.subarray(0, size).toString('utf8');
    } catch { diagnose('read-failed', file, 'File could not be read.'); return; }
    finally { await handle?.close().catch(() => undefined); }
  }

  const manifests: DiscoveredManifest[] = [];
  const dependencies: DiscoveredDependency[] = [];
  let name = basename(root);
  for (const file of files.filter(file => manifestNames.has(basename(file)))) {
    const directory = dirname(file).split(sep).join('/');
    if (basename(file) !== 'package.json') {
      manifests.push({ file, directory, workspacePatterns: [] });
      continue; // Unsupported ecosystems are inventoried, not interpreted as Node projects.
    }
    const contents = await read(file);
    if (contents === undefined) continue;
    let manifest: unknown;
    try { manifest = JSON.parse(contents); }
    catch { diagnose('invalid-manifest', file, 'Manifest is not valid JSON.'); continue; }
    if (!isObject(manifest)) { diagnose('invalid-manifest', file, 'Manifest must be a JSON object.'); continue; }
    const workspaceValue = isObject(manifest.workspaces) ? manifest.workspaces.packages : manifest.workspaces;
    const workspacePatterns = Array.isArray(workspaceValue)
      ? workspaceValue.filter((value): value is string => typeof value === 'string') : [];
    const packageLabel = typeof manifest.name === 'string' ? manifest.name : undefined;
    manifests.push({ file, directory, ...(packageLabel !== undefined ? { name: packageLabel } : {}), workspacePatterns });
    if (file === 'package.json' && packageLabel) name = packageLabel;
    for (const kind of dependencyKinds) {
      const section = manifest[kind];
      if (section === undefined) continue;
      if (!isObject(section)) {
        diagnose('invalid-manifest', file, `Manifest ${kind} must be an object.`);
        continue;
      }
      for (const [dependency, version] of Object.entries(section).sort(([a], [b]) => a.localeCompare(b, 'en'))) {
        if (typeof version !== 'string') {
          diagnose('invalid-manifest', file, `Manifest ${kind} contains a non-string version.`);
          continue;
        }
        // Preserve semver/file aliases, but avoid exposing credentials in remote dependency URLs.
        dependencies.push({ name: dependency, version: /(?:https?|git|ssh):/.test(version) ? '[remote reference]' : version,
          kind, manifest: file });
      }
    }
  }

  const languages = new Set<string>();
  const frameworks = new Set<string>();
  const databases = new Set<string>();
  const orms = new Set<string>();
  const authentication = new Set<'session' | 'jwt' | 'passport' | 'auth-provider'>();
  const authPackages = new Set<string>();
  const middleware: MiddlewareObservation[] = [];

  function observePackage(packageId: string, file: string, basis: 'dependency' | 'import', line?: number) {
    if (Object.hasOwn(frameworkPackages, packageId)) frameworks.add(frameworkPackages[packageId]!);
    if (Object.hasOwn(databasePackages, packageId)) databases.add(databasePackages[packageId]!);
    if (packageId === 'node:sqlite') databases.add('sqlite');
    if (ormPackages.has(packageId)) orms.add(packageId);
    if (Object.hasOwn(authenticationPackages, packageId)) {
      authentication.add(authenticationPackages[packageId]!);
      authPackages.add(packageId);
    }
    if (Object.hasOwn(middlewarePackages, packageId)) middleware.push({
      kind: middlewarePackages[packageId]!, name: packageId, file, basis,
      ...(line !== undefined ? { line } : {}),
    });
  }

  // Development dependencies and peer declarations do not establish a runtime stack.
  for (const dependency of dependencies) {
    if (dependency.kind === 'dependencies' || dependency.kind === 'optionalDependencies') {
      observePackage(dependency.name, dependency.manifest, 'dependency');
      if (dependency.version.startsWith('npm:')) {
        const aliasedPackage = packageName(dependency.version.slice(4).replace(/@[^/]*$/, ''));
        if (aliasedPackage) observePackage(aliasedPackage, dependency.manifest, 'dependency');
      }
    }
  }

  const sourceFiles = files.filter(file => sourceLanguages[extname(file)] !== undefined);
  for (const file of sourceFiles) languages.add(sourceLanguages[extname(file)]!);
  if (languages.size === 0 && manifests.some(manifest => basename(manifest.file) === 'package.json')) languages.add('javascript');
  const runtimeSourceFiles = sourceFiles.filter(file => ['javascript', 'typescript'].includes(sourceLanguages[extname(file)]!)
    && !isTest(file) && !/\.d\.(ts|mts|cts)$/.test(file));
  const runtimeLanguages = new Set(runtimeSourceFiles.map(file => sourceLanguages[extname(file)]!));
  let parsedBytes = 0;
  for (const file of runtimeSourceFiles) {
    const contents = await read(file);
    if (contents === undefined) continue;
    parsedBytes += Buffer.byteLength(contents);
    if (parsedBytes > maxSourceBytes) {
      diagnose('limit-reached', file, 'Source parsing budget reached.');
      break;
    }
    function inspectSource(text: string): void {
      const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
      function visit(node: ts.Node): void {
        let specifier: ts.StringLiteralLike | undefined;
        if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier
          && ts.isStringLiteralLike(node.moduleSpecifier)) {
          // Type-only imports cannot establish a runtime dependency.
          let typeOnly = ts.isImportDeclaration(node) ? node.importClause?.isTypeOnly : node.isTypeOnly;
          if (ts.isImportDeclaration(node) && node.importClause && !node.importClause.name
            && node.importClause.namedBindings && ts.isNamedImports(node.importClause.namedBindings)) {
            const elements = node.importClause.namedBindings.elements;
            typeOnly ||= elements.length > 0 && elements.every(element => element.isTypeOnly);
          }
          if (ts.isExportDeclaration(node) && node.exportClause && ts.isNamedExports(node.exportClause)) {
            const elements = node.exportClause.elements;
            typeOnly ||= elements.length > 0 && elements.every(element => element.isTypeOnly);
          }
          if (!typeOnly) specifier = node.moduleSpecifier;
        } else if (ts.isImportEqualsDeclaration(node) && !node.isTypeOnly
          && ts.isExternalModuleReference(node.moduleReference) && node.moduleReference.expression
          && ts.isStringLiteralLike(node.moduleReference.expression)) {
          specifier = node.moduleReference.expression;
        } else if (ts.isCallExpression(node) && node.arguments[0] && ts.isStringLiteralLike(node.arguments[0])
          && ((ts.isIdentifier(node.expression) && node.expression.text === 'require')
            || node.expression.kind === ts.SyntaxKind.ImportKeyword)) {
          specifier = node.arguments[0];
        }
        if (specifier) {
          const packageId = packageName(specifier.text);
          if (packageId) observePackage(packageId, file, 'import', source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1);
        }
        if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)
          && ['setHeader', 'header', 'set'].includes(node.expression.name.text)
          && node.arguments[0] && ts.isStringLiteralLike(node.arguments[0])
          && node.arguments[0].text.toLowerCase() === 'access-control-allow-origin') {
          middleware.push({ kind: 'cors', name: 'custom-cors', file, basis: 'header',
            line: source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1 });
        }
        ts.forEachChild(node, visit);
      }
      visit(source);
    }
    try { inspectSource(contents); }
    catch { diagnose('parse-failed', file, 'Source could not be inspected.'); }
  }

  const availableAdapters = (options.adapters ?? []).filter(registration =>
    // Phase 3 recognizes other frameworks but V1 code-aware support is Express JS/TS only.
    registration.framework === 'express' && frameworks.has('express')
    && runtimeLanguages.size > 0 && [...runtimeLanguages].every(language => registration.languages.includes(language)));
  const expressAdapterAvailable = (options.adapters ?? []).some(registration => registration.framework === 'express');
  const fallbackReasons: string[] = [];
  if (!frameworks.has('express')) fallbackReasons.push('No Express application was detected; V1 source support requires Express.');
  if ([...frameworks].some(framework => framework !== 'express')) fallbackReasons.push('An unsupported framework was detected; V1 source support covers Express only.');
  if (runtimeSourceFiles.length === 0) fallbackReasons.push('No application JavaScript or TypeScript source was detected.');
  if (!expressAdapterAvailable) fallbackReasons.push('No Express framework adapter is registered.');
  else if (availableAdapters.length === 0) fallbackReasons.push('No registered Express adapter advertises compatibility with the detected languages.');
  if (diagnostics.length > 0) fallbackReasons.push('Repository discovery is incomplete; review diagnostics before enabling source analysis.');
  const supportedCodeAwareMode = fallbackReasons.length === 0;

  return {
    repositoryPath: root, name, languages: sorted(languages), frameworks: sorted(frameworks), dependencies,
    databases: sorted(databases), orms: sorted(orms), authentication: [...authentication].sort(),
    authenticationPackages: sorted(authPackages), middleware,
    structure: {
      manifests, directories: directories.sort(),
      sourceDirectories: directories.filter(directory => /(^|\/)(src|lib|app|server|client)$/.test(directory)).sort(),
      testDirectories: directories.filter(directory => /(^|\/)(tests?|__tests__)$/.test(directory)).sort(),
      staticDirectories: directories.filter(directory => /(^|\/)(public|static|assets)$/.test(directory)).sort(),
      sourceFileCount: sourceFiles.length,
    },
    expressAdapterAvailable, availableAdapterIds: sorted(availableAdapters.map(registration => registration.adapter.id)),
    supportedCodeAwareMode, mode: supportedCodeAwareMode ? 'code-aware' : 'black-box', fallbackReasons, diagnostics,
  };
}

/** Convert metadata to the Phase 2 contract without inventing an authorized URL or scope. */
export function toProject(discovery: DiscoveryResult, target: ProjectTarget): Project {
  return { id: target.id, name: target.name ?? discovery.name, mode: discovery.mode,
    repositoryPath: discovery.repositoryPath, baseUrl: target.baseUrl,
    allowedOrigins: [...target.allowedOrigins], languages: [...discovery.languages] };
}

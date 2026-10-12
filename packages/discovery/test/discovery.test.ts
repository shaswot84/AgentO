import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AgentOOrchestrator } from '@agento/core';
import type { FrameworkAdapter } from '@agento/core';
import { discoverProject, toProject } from '../src/index.js';
import type { DiscoveryOptions } from '../src/index.js';

const temporaryRoots: string[] = [];
async function repository(files: Record<string, string | object> = {}): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'agento-discovery-'));
  temporaryRoots.push(root);
  for (const [file, contents] of Object.entries(files)) {
    await mkdir(dirname(join(root, file)), { recursive: true });
    await writeFile(join(root, file), typeof contents === 'string' ? contents : JSON.stringify(contents));
  }
  return root;
}
afterEach(async () => { await Promise.all(temporaryRoots.splice(0).map(root => rm(root, { recursive: true, force: true }))); });

const expressAdapter: FrameworkAdapter = {
  id: 'fake-express', capabilities: ['route-extraction'],
  async supports(project) { return project.languages.includes('typescript') || project.languages.includes('javascript'); },
  async extract() { return { components: [], endpoints: [], resources: [], signals: [], evidence: [] }; },
};
const adapters: DiscoveryOptions = { adapters: [{ framework: 'express', languages: ['typescript', 'javascript'], adapter: expressAdapter }] };
const demoPath = fileURLToPath(new URL('../../../demo-apps/demo-app-01/', import.meta.url));
const demo02Path = fileURLToPath(new URL('../../../demo-apps/demo-app-02/', import.meta.url));

describe('Phase 3 project discovery', () => {
  it('identifies the real demo, including custom CORS, without claiming an absent adapter', async () => {
    const result = await discoverProject(demoPath);
    expect(result.name).toBe('demo-app');
    expect(result.languages).toEqual(['javascript', 'typescript']);
    expect(result.frameworks).toEqual(['express']);
    expect(result.databases).toEqual(['sqlite']);
    expect(result.orms).toEqual([]);
    expect(result.authentication).toEqual(['session']);
    expect(result.authenticationPackages).toEqual(['express-session']);
    expect(result.middleware).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: 'express-session', kind: 'session', basis: 'import', file: 'src/app.ts' }),
      expect.objectContaining({ name: 'cookie-parser', kind: 'cookie' }),
      expect.objectContaining({ name: 'cors', kind: 'cors', basis: 'dependency' }),
      expect.objectContaining({ name: 'custom-cors', kind: 'cors', basis: 'header', file: 'src/middleware/cors.ts' }),
    ]));
    const header = result.middleware.find(item => item.basis === 'header');
    const source = await readFile(join(demoPath, header!.file), 'utf8');
    expect(source.split('\n')[header!.line! - 1]).toContain('Access-Control-Allow-Origin');
    expect(result.structure.sourceDirectories).toContain('src');
    expect(result.structure.testDirectories).toContain('test');
    expect(result.structure.staticDirectories).toContain('public');
    expect(result.structure.manifests).toHaveLength(1);
    expect(result.diagnostics).toEqual([]);
    expect(result.expressAdapterAvailable).toBe(false);
    expect(result.supportedCodeAwareMode).toBe(false);
    expect(result.mode).toBe('black-box');
    expect(result.fallbackReasons.join(' ')).toContain('No Express framework adapter');
    expect(JSON.stringify(result)).not.toContain('agento-super-secret');
  });

  it('enables code-aware mode with a compatible injected adapter and feeds the Phase 2 core', async () => {
    const result = await discoverProject(demoPath, adapters);
    expect(result.expressAdapterAvailable).toBe(true);
    expect(result.availableAdapterIds).toEqual(['fake-express']);
    expect(result.supportedCodeAwareMode).toBe(true);
    expect(result.fallbackReasons).toEqual([]);
    const project = toProject(result, { id: 'demo', baseUrl: 'http://localhost:3000', allowedOrigins: ['http://localhost:3000'] });
    expect(project).toMatchObject({ id: 'demo', mode: 'code-aware', repositoryPath: result.repositoryPath,
      baseUrl: 'http://localhost:3000', allowedOrigins: ['http://localhost:3000'] });
    const adapter = { ...expressAdapter, supports: vi.fn(expressAdapter.supports), extract: vi.fn(expressAdapter.extract) };
    await new AgentOOrchestrator({ plugins: [], frameworkAdapter: adapter }).run({ project, identities: [] });
    expect(adapter.supports).toHaveBeenCalledWith(project);
    expect(adapter.extract).toHaveBeenCalledWith(project);
  });

  it('identifies demo-app-02 (Fastify + JWT + PostgreSQL + Redis + Drizzle) and gracefully enforces black-box mode', async () => {
    const result = await discoverProject(demo02Path, adapters);
    expect(result.name).toBe('demo-app-02');
    expect(result.languages).toEqual(['javascript', 'python', 'typescript']);
    expect(result.frameworks).toEqual(['fastify']);
    expect(result.databases).toEqual(['postgresql', 'redis']);
    expect(result.orms).toEqual(['drizzle-orm']);
    expect(result.authentication).toEqual(['jwt']);
    expect(result.authenticationPackages).toEqual(['@fastify/jwt']);
    expect(result.middleware).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: '@fastify/cors', kind: 'cors', basis: 'dependency' }),
      expect.objectContaining({ name: '@fastify/cookie', kind: 'cookie', basis: 'dependency' }),
      expect.objectContaining({ name: '@fastify/cors', kind: 'cors', basis: 'import', file: 'src/app.ts' }),
      expect.objectContaining({ name: '@fastify/cookie', kind: 'cookie', basis: 'import', file: 'src/app.ts' }),
      expect.objectContaining({ name: 'custom-cors', kind: 'cors', basis: 'header', file: 'src/routes/payment.ts' }),
    ]));
    const header = result.middleware.find(item => item.basis === 'header');
    const source = await readFile(join(demo02Path, header!.file), 'utf8');
    expect(source.split('\n')[header!.line! - 1]).toContain('Access-Control-Allow-Origin');
    expect(result.structure.sourceDirectories).toContain('src');
    expect(result.structure.testDirectories).toContain('test');
    expect(result.structure.staticDirectories).toContain('public');
    expect(result.structure.manifests.length).toBeGreaterThanOrEqual(2);
    expect(result.dependencies.find(item => item.name === 'safe-remote-reference')?.version).toBe('[remote reference]');
    expect(result.orms).not.toContain('@prisma/client');
    expect(result.diagnostics).toEqual([]);
    expect(result.expressAdapterAvailable).toBe(true);
    expect(result.supportedCodeAwareMode).toBe(false);
    expect(result.mode).toBe('black-box');
    expect(result.fallbackReasons).toContain('No Express application was detected; V1 source support requires Express.');
  });

  it('passes the fallback to core so unsupported projects never call source providers', async () => {
    const root = await repository({ 'package.json': { dependencies: { fastify: '^5' } }, 'src/main.js': 'import Fastify from "fastify";' });
    const discovery = await discoverProject(root, adapters);
    const adapter = { ...expressAdapter, supports: vi.fn(), extract: vi.fn() };
    const project = toProject(discovery, { id: 'unsupported', baseUrl: 'http://localhost:3000', allowedOrigins: [] });
    await new AgentOOrchestrator({ plugins: [], frameworkAdapter: adapter }).run({ project, identities: [] });
    expect(discovery.frameworks).toEqual(['fastify']);
    expect(discovery.mode).toBe('black-box');
    expect(adapter.supports).not.toHaveBeenCalled();
    expect(adapter.extract).not.toHaveBeenCalled();
  });

  it.each([
    {},
    { 'pyproject.toml': '[project]\nname="python-app"', 'main.py': 'print("hello")' },
    { 'Cargo.toml': '[package]\nname="rust-app"', 'src/main.rs': 'fn main() {}' },
    { 'package.json': { dependencies: { '@nestjs/core': '^11' } }, 'main.ts': 'export {};' },
  ])('handles unsupported and empty repositories without throwing', async files => {
    const result = await discoverProject(await repository(files), adapters);
    expect(result.mode).toBe('black-box');
    expect(result.supportedCodeAwareMode).toBe(false);
    expect(result.diagnostics).toEqual([]);
  });

  it.each(['{bad json', 'null', '[]', '{"dependencies":[]}', '{"dependencies":{"express":42}}'])
    ('reports malformed manifests while keeping discovery usable (%s)', async manifest => {
      const root = await repository({ 'package.json': manifest, 'src/app.ts': 'import express from "express";' });
      const result = await discoverProject(root, adapters);
      expect(result.diagnostics).toEqual(expect.arrayContaining([expect.objectContaining({ code: 'invalid-manifest', file: 'package.json' })]));
      expect(result.languages).toEqual(['typescript']);
      expect(result.mode).toBe('black-box');
    });

  it('handles nonexistent paths, file paths, and symlink roots with diagnostics', async () => {
    const root = await repository({ 'file.txt': 'text' });
    await symlink(root, join(root, 'link'));
    for (const path of [join(root, 'missing'), join(root, 'file.txt'), join(root, 'link')]) {
      const result = await discoverProject(path, adapters);
      expect(result.mode).toBe('black-box');
      expect(result.diagnostics[0]?.code).toBe('repository-unavailable');
    }
  });

  it('inventories nested packages and workspaces, retaining dependency sections and provenance', async () => {
    const root = await repository({
      'package.json': { name: 'workspace', workspaces: { packages: ['apps/*'] }, devDependencies: { typescript: '^7' } },
      'apps/api/package.json': { name: 'api', dependencies: { express: '^5', pg: '^8', 'drizzle-orm': '^1', jose: '^6' }, optionalDependencies: { cors: '^2' }, peerDependencies: { koa: '^2' } },
      'apps/api/src/main.ts': 'import express from "express"; export const app = express();',
      'apps/api/test/test.ts': 'export {};', 'apps/api/public/page.js': '',
    });
    const result = await discoverProject(root, adapters);
    expect(result.name).toBe('workspace');
    expect(result.structure.manifests).toEqual(expect.arrayContaining([
      expect.objectContaining({ file: 'package.json', workspacePatterns: ['apps/*'] }),
      expect.objectContaining({ file: 'apps/api/package.json', directory: 'apps/api', name: 'api' }),
    ]));
    expect(result.dependencies).toContainEqual({ name: 'koa', version: '^2', kind: 'peerDependencies', manifest: 'apps/api/package.json' });
    expect(result.frameworks).toEqual(['express']);
    expect(result.databases).toEqual(['postgresql']);
    expect(result.orms).toEqual(['drizzle-orm']);
    expect(result.authentication).toEqual(['jwt']);
    expect(result.mode).toBe('code-aware');
  });

  it('ignores artifacts, dependencies, hidden directories, symlinks, and test-only runtime hints', async () => {
    const outside = await repository({ 'package.json': { dependencies: { fastify: '^5' } } });
    const root = await repository({
      'package.json': { dependencies: { express: '^5' }, devDependencies: { fastify: '^5', '@types/koa': '^2' } },
      'src/app.js': 'const express = require("express");',
      'test/check.js': 'require("fastify");', 'src/example.spec.ts': 'import koa from "koa";',
      'node_modules/bad/package.json': 'bad json', 'dist/bad.js': 'require("koa");',
      '.hidden/package.json': 'bad json',
    });
    await symlink(outside, join(root, 'linked'));
    const result = await discoverProject(root, adapters);
    expect(result.frameworks).toEqual(['express']);
    expect(result.diagnostics).toEqual([]);
    expect(result.structure.directories).not.toContain('node_modules');
    expect(result.structure.manifests).toHaveLength(1);
  });

  it('parses runtime imports, aliases, subpaths, and dynamic imports without executing code', async () => {
    const root = await repository({
      'package.json': { dependencies: { web: 'npm:express@^5', db: 'npm:pg@^8' }, scripts: { postinstall: 'exit 1' } },
      'src/app.cjs': 'const web = require("express"); require("better-sqlite3"); require("cookie-session");',
      'src/tokens.mjs': 'await import("jose/jwt/verify"); throw new Error("must not execute");',
    });
    const result = await discoverProject(root, adapters);
    expect(result.frameworks).toEqual(['express']);
    expect(result.databases).toEqual(['postgresql', 'sqlite']);
    expect(result.authentication).toEqual(['jwt', 'session']);
    expect(result.mode).toBe('code-aware');
  });

  it('does not turn comments, strings, type imports, or ORM presence into runtime claims', async () => {
    const root = await repository({
      'package.json': { dependencies: { '@prisma/client': '^7', constructor: '^1' }, devDependencies: { express: '^5' } },
      'src/types.ts': 'import type { Request } from "express"; import { type Application } from "express"; export { type Application } from "express";\n// require("fastify")\nconst note = `res.setHeader("Access-Control-Allow-Origin", "*")`;',
    });
    const result = await discoverProject(root, adapters);
    expect(result.frameworks).toEqual([]);
    expect(result.databases).toEqual([]);
    expect(result.orms).toEqual(['@prisma/client']);
    expect(result.middleware).toEqual([]);
    expect(result.mode).toBe('black-box');
  });

  it('does not infer middleware vulnerability or configuration from custom header observations', async () => {
    const root = await repository({ 'src/app.js': 'response.setHeader("Access-Control-Allow-Origin", trustedOrigin);' });
    const result = await discoverProject(root);
    expect(result.middleware).toEqual([{ kind: 'cors', name: 'custom-cors', file: 'src/app.js', basis: 'header', line: 1 }]);
    expect(result).not.toHaveProperty('findings');
  });

  it('falls back for incompatible adapters, missing application source, and mixed frameworks', async () => {
    const root = await repository({ 'package.json': { dependencies: { express: '^5' } }, 'src/app.ts': 'export {};' });
    const incompatible = await discoverProject(root, { adapters: [{ framework: 'express', languages: ['python'], adapter: expressAdapter }] });
    expect(incompatible.expressAdapterAvailable).toBe(true);
    expect(incompatible.mode).toBe('black-box');
    expect(incompatible.availableAdapterIds).toEqual([]);
    const mixedLanguages = await repository({ 'package.json': { dependencies: { express: '^5' } }, 'src/app.ts': 'export {};', 'public/app.js': 'export {};' });
    const partial = await discoverProject(mixedLanguages, { adapters: [{ framework: 'express', languages: ['javascript'], adapter: expressAdapter }] });
    expect(partial.mode).toBe('black-box');
    expect(partial.availableAdapterIds).toEqual([]);
    const noSource = await discoverProject(await repository({ 'package.json': { dependencies: { express: '^5' } } }), adapters);
    expect(noSource.mode).toBe('black-box');
    const mixed = await discoverProject(await repository({ 'package.json': { dependencies: { express: '^5', fastify: '^5' } }, 'src/app.ts': 'export {};' }), adapters);
    expect(mixed.mode).toBe('black-box');
  });

  it('degrades visibly for oversized source files and manifests', async () => {
    const root = await repository({ 'package.json': { dependencies: { express: '^5' } }, 'src/app.ts': ' '.repeat(1_048_577) });
    const result = await discoverProject(root, adapters);
    expect(result.diagnostics).toContainEqual({ code: 'limit-reached', file: 'src/app.ts', message: 'File exceeds the discovery size limit.' });
    expect(result.mode).toBe('black-box');
    await writeFile(join(root, 'package.json'), ' '.repeat(1_048_577));
    expect((await discoverProject(root)).diagnostics.some(item => item.file === 'package.json' && item.code === 'limit-reached')).toBe(true);
  });

  it('contains parser failures from pathological source instead of crashing discovery', async () => {
    const root = await repository({ 'src/app.ts': `const value = ${'('.repeat(20_000)}0${')'.repeat(20_000)};` });
    const result = await discoverProject(root, adapters);
    expect(result.diagnostics).toContainEqual({ code: 'parse-failed', file: 'src/app.ts', message: 'Source could not be inspected.' });
    expect(result.mode).toBe('black-box');
  });

  it('returns deterministic, JSON-safe metadata and hides remote dependency credentials', async () => {
    const root = await repository({
      'package.json': { dependencies: { express: '^5', private: 'git+https://token@example.invalid/repo.git' }, workspaces: ['apps/*'] },
      'src/app.ts': 'import express from "express";',
    });
    const first = await discoverProject(root, adapters);
    expect(await discoverProject(root, adapters)).toEqual(first);
    const serialized = JSON.stringify(first);
    expect(JSON.parse(serialized)).toEqual(first);
    expect(serialized).not.toContain('token@example');
    expect(first.dependencies.find(item => item.name === 'private')?.version).toBe('[remote reference]');
    expect(first.structure.manifests[0]?.workspacePatterns).toEqual(['apps/*']);
  });
});

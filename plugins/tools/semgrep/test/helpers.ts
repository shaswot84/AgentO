import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { Project } from '@agento/core';
import { afterEach } from 'vitest';

const roots: string[] = [];
export const now = () => '2026-10-12T00:00:00.000Z';
export const project = (repositoryPath: string): Project => ({ id: 'shop', name: 'Shop', mode: 'code-aware',
  repositoryPath, baseUrl: 'http://localhost:3000', allowedOrigins: ['http://localhost:3000'], languages: ['javascript', 'typescript'] });
export async function repository(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'agento-static-test-'));
  roots.push(root);
  for (const [name, contents] of Object.entries(files)) {
    await mkdir(dirname(join(root, name)), { recursive: true });
    await writeFile(join(root, name), contents);
  }
  return root;
}
afterEach(async () => { await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true }))); });
export function match(code: string, needle: string, ruleId = 'agento.express.request-to-html', path = 'src/app.ts') {
  const offset = code.lastIndexOf(needle);
  const point = (index: number) => {
    const prefix = code.slice(0, index);
    return { line: prefix.split('\n').length, col: Buffer.byteLength(prefix.slice(prefix.lastIndexOf('\n') + 1)) + 1, offset: index };
  };
  return { check_id: ruleId, path, start: point(offset), end: point(offset + needle.length),
    extra: { message: 'RAW_SECRET', lines: 'SOURCE_SECRET', metadata: { cwe: 'CWE-999', token: 'TOKEN_SECRET' } } };
}
export function output(results: unknown[] = [], errors: unknown[] = [], files = ['src/app.ts']) {
  return { exitCode: 0, stdout: JSON.stringify({ results, errors, paths: { scanned: files }, version: '1.180.0',
    secrets: 'TOP_LEVEL_SECRET' }) };
}

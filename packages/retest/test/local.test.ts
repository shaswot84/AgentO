import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { LocalPatchEnvironment } from '../src/index.js';
import { authorization, fixture, repository } from './helpers.js';

const directories: string[] = [];
afterEach(async () => { for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true }); });
async function setup() {
  const state = await fixture(), source = await mkdtemp(join(tmpdir(), 'agento-retest-unit-')); directories.push(source);
  const file = state.input.remediation.files[0]!.path;
  await mkdir(join(source, 'src/routes'), { recursive: true });
  await writeFile(join(source, file), await readFile(repository + file));
  let copied = '';
  const target = { baseUrl: 'https://127.0.0.1:4567', dispose: vi.fn(async () => {}) };
  const options = { sourceDirectory: source, include: ['src'], start: vi.fn(async (directory: string) => { copied = directory; return target; }),
    regression: vi.fn(async () => ({ security: 'PASSED' as const, normalFlow: 'PASSED' as const })),
    replay: vi.fn(async () => authorization(target.baseUrl + '/api/orders/101', true)) };
  return { ...state, source, file, target, options, copied: () => copied };
}
describe('source-bound local patch environment', () => {
  it('patches only a copied source tree and removes it on disposal', async () => {
    const state = await setup(), before = await readFile(join(state.source, state.file), 'utf8');
    const session = await new LocalPatchEnvironment(state.options).create(state.input, new AbortController().signal);
    expect(await readFile(join(state.copied(), state.file), 'utf8')).not.toBe(before);
    expect(await readFile(join(state.source, state.file), 'utf8')).toBe(before);
    expect(await readFile(join(state.copied(), state.input.remediation.regressionTestPath), 'utf8')).toBe(state.input.remediation.regressionTest);
    await session.dispose();
    await expect(readFile(join(state.copied(), state.file))).rejects.toThrow(); expect(state.target.dispose).toHaveBeenCalledOnce();
  });
  it.each(['changed-source', 'changed-after-hash', 'traversal', 'extra-file', 'test-overwrite', 'symlink'])('refuses %s before startup', async mode => {
    const state = await setup(), input = structuredClone(state.input);
    if (mode === 'changed-source') await writeFile(join(state.source, state.file), 'Changed source');
    if (mode === 'changed-after-hash') (input.remediation.files[0] as any).afterSha256 = '0'.repeat(64);
    if (mode === 'traversal') (input.remediation.files[0] as any).path = '../outside.ts';
    if (mode === 'extra-file') (input.remediation as any).patch += '--- a/src/extra.ts\n+++ b/src/extra.ts\n@@ -1,1 +1,1 @@\n-before\n+after\n';
    if (mode === 'test-overwrite') (input.remediation as any).regressionTestPath = state.file;
    if (mode === 'symlink') { await rm(join(state.source, state.file)); await symlink(join(repository, state.file), join(state.source, state.file)); }
    await expect(new LocalPatchEnvironment(state.options).create(input, new AbortController().signal)).rejects.toThrow();
    expect(state.options.start).not.toHaveBeenCalled();
  });
  it.each(['../outside', '.env', 'node_modules', 'src/.env', '/absolute'])('rejects unsafe copy include %s', async path => {
    const state = await setup(); expect(() => new LocalPatchEnvironment({ ...state.options, include: [path] })).toThrow();
  });
  it('stops and removes a started target with an invalid URL', async () => {
    const state = await setup(); state.target.baseUrl = 'https://outside.test';
    await expect(new LocalPatchEnvironment(state.options).create(state.input, new AbortController().signal)).rejects.toThrow();
    expect(state.target.dispose).toHaveBeenCalledOnce();
    await expect(readFile(join(state.copied(), state.file))).rejects.toThrow();
  });
});

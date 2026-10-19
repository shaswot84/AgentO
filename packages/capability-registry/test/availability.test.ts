import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CapabilityRegistry, executableAvailable } from '../src/index.js';
import { request, tool } from './helpers.js';

describe('file-only executable availability', () => {
  let directory: string;
  beforeEach(async () => { directory = await mkdtemp(join(tmpdir(), 'agento-registry-')); });
  afterEach(async () => { vi.unstubAllEnvs(); await rm(directory, { recursive: true, force: true }); });

  it('checks an absolute executable without running it or exposing its path', async () => {
    const executable = join(directory, 'candidate'), marker = join(directory, 'must-not-exist');
    await writeFile(executable, `#!/bin/sh\ntouch '${marker}'\n`); await chmod(executable, 0o700);
    const check = vi.fn(async () => true);
    const registry = new CapabilityRegistry().register(tool('local', {}, { executable, checkAvailability: check }));
    expect((await registry.resolve(request)).report.status).toBe('READY'); expect(check).toHaveBeenCalledOnce();
    await expect(readFile(marker)).rejects.toThrow();
    expect(JSON.stringify(await registry.preflight())).not.toContain(directory);
  });

  it('finds a bare command through PATH and refreshes after deletion', async () => {
    const file = join(directory, 'available-tool');
    await writeFile(file, '#!/bin/sh\nexit 0\n'); await chmod(file, 0o700);
    vi.stubEnv('PATH', [join(directory, 'absent'), directory].join(delimiter));
    expect(await executableAvailable('available-tool')).toBe(true);
    await rm(file); expect(await executableAvailable('available-tool')).toBe(false);
  });

  it('skips non-executable files, directories and implicit current-directory PATH entries', async () => {
    const file = join(directory, 'blocked'); await writeFile(file, 'data'); await chmod(file, 0o600);
    expect(await executableAvailable(file)).toBe(false);
    expect(await executableAvailable(directory)).toBe(false);
    vi.stubEnv('PATH', `.${delimiter}${delimiter}relative`);
    expect(await executableAvailable('node')).toBe(false);
  });

  it('skips custom checks for absent executables and cleanly falls back', async () => {
    const check = vi.fn(async () => { throw new Error('must not run'); });
    const registry = new CapabilityRegistry().register(tool('missing', { priority: 1 }, {
      executable: join(directory, 'absent'), checkAvailability: check,
    })).register(tool('fallback'));
    const result = await registry.resolve(request);
    expect(result.report.selections[0]!.selectedToolId).toBe('fallback');
    expect(result.report.availability).toContainEqual({ toolId: 'missing', available: false, code: 'not-installed' });
    expect(check).not.toHaveBeenCalled();
  });

  it.each(['tool --version', 'tool;echo private', '$(echo private)', './tool', '../tool', '', 'bad\ncommand']) (
    'rejects command text and relative paths: %j', async executable => {
      expect(await executableAvailable(executable)).toBe(false);
      expect(() => new CapabilityRegistry().register(tool('invalid', {}, { executable }))).toThrow();
    });
});

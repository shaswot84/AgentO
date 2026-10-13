import { mkdtemp, readFile, writeFile, lstat, mkdir, symlink, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { FileSessionStore, MemorySessionStore } from '../src/sessions.js';
import { BrowserScope } from '../src/policy.js';
import { alice, context, state } from './helpers.js';

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map(path => rm(path, { recursive: true, force: true }))); });
async function directory() { const path = await mkdtemp(join(tmpdir(), 'agento-sessions-')); directories.push(path); return path; }
const binding = new BrowserScope(context.project).binding(context.project, alice);
const session = { binding, sessionRef: 'opaque-handle', expiresAt: Date.now() + 60_000, state };

describe('private session stores', () => {
  it('copies in-memory snapshots so callers cannot mutate another session', async () => {
    const store = new MemorySessionStore(); await store.save(session);
    const restored = (await store.load(binding))!;
    expect(restored).toEqual(session); expect(restored.state).not.toBe(session.state);
    (restored as { sessionRef: string }).sessionRef = 'changed';
    expect((await store.load(binding))?.sessionRef).toBe('opaque-handle');
    await store.delete(binding); expect(await store.load(binding)).toBeUndefined();
  });
  it('saves and reuses private files across store instances with restrictive permissions', async () => {
    const path = join(await directory(), 'private'), store = new FileSessionStore(path);
    await store.save(session);
    expect((await lstat(path)).mode & 0o777).toBe(0o700);
    expect((await lstat(join(path, `${binding}.json`))).mode & 0o777).toBe(0o600);
    expect(await new FileSessionStore(path).load(binding)).toEqual(session);
    await store.delete(binding); expect(await store.load(binding)).toBeUndefined();
  });
  it('refuses unsafe directories, symlinks, malformed files and path-like handles', async () => {
    const parent = await directory(), path = join(parent, 'store');
    await mkdir(path, { mode: 0o755 });
    const store = new FileSessionStore(path);
    await expect(store.save(session)).rejects.toThrow('session-store-failed');
    await chmod(path, 0o700);
    await expect(store.load('../private')).rejects.toThrow('session-store-failed');
    await writeFile(join(path, `${binding}.json`), '{"secret": "private-cookie"}', { mode: 0o600 });
    await expect(store.load(binding)).rejects.toThrow('session-store-failed');
    await rm(join(path, `${binding}.json`));
    const target = join(parent, 'target'); await writeFile(target, JSON.stringify(session), { mode: 0o600 });
    await symlink(target, join(path, `${binding}.json`));
    await expect(store.load(binding)).rejects.toThrow('session-store-failed');
    expect(await readFile(target, 'utf8')).toContain('private-session-cookie');
  });
});

import { mkdir, readFile, rename, rm, open, lstat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { BrowserError } from './policy.js';
import type { SessionStore, StoredSession } from './types.js';

export class MemorySessionStore implements SessionStore {
  private readonly sessions = new Map<string, StoredSession>();
  async load(binding: string): Promise<StoredSession | undefined> {
    const session = this.sessions.get(binding);
    return session === undefined ? undefined : structuredClone(session);
  }
  async save(session: StoredSession): Promise<void> { this.sessions.set(session.binding, structuredClone(session)); }
  async delete(binding: string): Promise<void> { this.sessions.delete(binding); }
}

/** Opt-in backend store. Files contain credentials and are excluded from reports and source control. */
export class FileSessionStore implements SessionStore {
  readonly directory: string;
  constructor(directory: string) { this.directory = resolve(directory); }
  private path(binding: string): string {
    if (!/^[a-f0-9]{64}$/.test(binding)) throw new BrowserError('session-store-failed');
    return join(this.directory, `${binding}.json`);
  }
  private async prepare(): Promise<void> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const info = await lstat(this.directory);
    if (!info.isDirectory() || (info.mode & 0o077) !== 0) throw new BrowserError('session-store-failed');
  }
  async load(binding: string): Promise<StoredSession | undefined> {
    try {
      await this.prepare();
      const path = this.path(binding), info = await lstat(path);
      if (!info.isFile() || (info.mode & 0o077) !== 0 || info.size > 2_097_152) throw new Error();
      const result: unknown = JSON.parse(await readFile(path, 'utf8'));
      if (!isStoredSession(result) || result.binding !== binding) throw new Error();
      return result;
    } catch (error) {
      if (typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT') return undefined;
      throw new BrowserError('session-store-failed');
    }
  }
  async save(session: StoredSession): Promise<void> {
    let temporary: string | undefined;
    try {
      await this.prepare();
      const path = this.path(session.binding);
      temporary = `${path}.${randomUUID()}.tmp`;
      const contents = JSON.stringify(session);
      if (Buffer.byteLength(contents) > 2_097_152) throw new Error();
      const file = await open(temporary, 'wx', 0o600);
      try { await file.writeFile(contents); } finally { await file.close(); }
      await rename(temporary, path);
    } catch { throw new BrowserError('session-store-failed'); }
    finally { if (temporary) await rm(temporary, { force: true }); }
  }
  async delete(binding: string): Promise<void> {
    try { await this.prepare(); await rm(this.path(binding), { force: true }); }
    catch { throw new BrowserError('session-store-failed'); }
  }
}

export function isStoredSession(value: unknown): value is StoredSession {
  if (!value || typeof value !== 'object') return false;
  const item = value as Partial<StoredSession>;
  return typeof item.binding === 'string' && typeof item.sessionRef === 'string'
    && typeof item.expiresAt === 'number' && Number.isFinite(item.expiresAt)
    && !!item.state && typeof item.state.format === 'string' && typeof item.state.version === 'number';
}

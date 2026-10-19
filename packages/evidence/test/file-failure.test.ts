import { mkdtempSync, readFileSync, rmSync, writeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FileEvidenceStore } from '../src/index.js';
import { evidence, scope } from './helpers.js';

vi.mock('node:fs', async importOriginal => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return { ...actual, writeSync: vi.fn(actual.writeSync) };
});
const paths: string[] = [];
const stores: FileEvidenceStore[] = [];
afterEach(() => { vi.mocked(writeSync).mockRestore(); for (const store of stores.splice(0)) store.close(); for (const path of paths.splice(0)) rmSync(path, { recursive: true, force: true }); });
function open() {
  const path = mkdtempSync(join(tmpdir(), 'agento-evidence-failure-')); paths.push(path);
  const store = new FileEvidenceStore(path); stores.push(store); return { path, store };
}
describe('failed journal writes', () => {
  it('keeps failed batches out of memory and returns only a fixed error', () => {
    const { path, store } = open();
    vi.mocked(writeSync).mockImplementationOnce(() => { throw new Error('PRIVATE_DISK_PATH PRIVATE_TOKEN'); });
    expect(() => store.capture([evidence()], scope)).toThrow('storage-failed');
    expect(() => store.get('proof')).toThrow('storage-failed');
    expect(readFileSync(join(path, 'evidence.jsonl'), 'utf8')).toBe('');
    store.close();
    const restored = new FileEvidenceStore(path); stores.push(restored); expect(restored.list()).toEqual([]);
  });
  it('handles short writes and rejects a partial write on reopen', async () => {
    const { path, store } = open();
    const actual = await vi.importActual<typeof import('node:fs')>('node:fs');
    vi.mocked(writeSync).mockImplementationOnce(((fd: number, buffer: Buffer) => actual.writeSync(fd, buffer, 0, 16)) as typeof writeSync)
      .mockImplementationOnce(() => { throw new Error('PRIVATE_FULL_DISK'); });
    expect(() => store.capture([evidence()], scope)).toThrow('storage-failed');
    expect(readFileSync(join(path, 'evidence.jsonl')).length).toBe(16);
    expect(() => store.list()).toThrow('storage-failed');
    store.close(); expect(() => new FileEvidenceStore(path)).toThrow('integrity-failed');
  });
  it('completes a short write before publishing a record', async () => {
    const { path, store } = open();
    const actual = await vi.importActual<typeof import('node:fs')>('node:fs');
    vi.mocked(writeSync).mockImplementationOnce(((fd: number, buffer: Buffer) => actual.writeSync(fd, buffer, 0, 16)) as typeof writeSync);
    store.capture([evidence()], scope); expect(store.get('proof')).toBeDefined();
    const head = store.headDigest; store.close();
    const restored = new FileEvidenceStore(path, { expectedHeadDigest: head }); stores.push(restored);
    expect(restored.get('proof')).toBeDefined();
  });
});

import { constants, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readSync, unlinkSync, writeSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { EvidenceError, type FileEvidenceStoreOptions, type JournalBatch, type StoredEvidence } from './contracts.js';
import { MemoryEvidenceStore } from './store.js';
import { canonical, digest, freeze, object } from './value.js';

/** Single-writer local journal. Failed writes poison the handle; partial or corrupt files fail closed on reopen. */
export class FileEvidenceStore extends MemoryEvidenceStore {
  readonly #directory: string;
  #file: number | undefined;
  #lock: number | undefined;
  #head: string | null = null;
  #bytes = 0;
  #failed = false;
  constructor(directory: string, options: FileEvidenceStoreOptions = {}) {
    super(options);
    if (typeof directory !== 'string' || !directory || directory.includes('\0')
      || options.expectedHeadDigest !== undefined && options.expectedHeadDigest !== null
      && !/^[a-f0-9]{64}$/.test(options.expectedHeadDigest)) throw new EvidenceError('invalid-options');
    this.#directory = resolve(directory);
    try {
      mkdirSync(this.#directory, { recursive: true, mode: 0o700 });
      const stat = lstatSync(this.#directory);
      if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) throw new EvidenceError('storage-failed');
      try {
        this.#lock = openSync(join(this.#directory, '.writer.lock'), constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new EvidenceError('store-locked');
        throw error;
      }
      this.#file = openSync(join(this.#directory, 'evidence.jsonl'), constants.O_CREAT | constants.O_APPEND | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
      const info = fstatSync(this.#file);
      if (!info.isFile() || info.nlink !== 1 || (info.mode & 0o077) !== 0) throw new EvidenceError('storage-failed');
      if (info.size > this.maxStoreBytes) throw new EvidenceError('store-limit');
      const buffer = Buffer.alloc(info.size);
      let offset = 0;
      while (offset < buffer.length) {
        const count = readSync(this.#file, buffer, offset, buffer.length - offset, offset);
        if (!count) throw new EvidenceError('integrity-failed');
        offset += count;
      }
      this.#bytes = buffer.length;
      this.load(buffer.toString('utf8'));
      if (options.expectedHeadDigest !== undefined && options.expectedHeadDigest !== this.#head) throw new EvidenceError('integrity-failed');
      const directoryFile = openSync(this.#directory, constants.O_RDONLY | constants.O_DIRECTORY);
      try { fsyncSync(directoryFile); } finally { closeSync(directoryFile); }
    } catch (error) {
      this.close();
      throw error instanceof EvidenceError ? error : new EvidenceError('storage-failed');
    }
  }
  /** Save this value externally to detect tail deletion or a fully rewritten journal. */
  get headDigest(): string | null { this.assertOpen(); return this.#head; }
  override close(): void {
    super.close();
    if (this.#file !== undefined) { closeSync(this.#file); this.#file = undefined; }
    if (this.#lock !== undefined) {
      closeSync(this.#lock); this.#lock = undefined;
      try { unlinkSync(join(this.#directory, '.writer.lock')); } catch { /* Keep original storage error sanitized. */ }
    }
  }
  protected override assertOpen(): void {
    super.assertOpen();
    if (this.#failed) throw new EvidenceError('storage-failed');
  }
  protected override persist(records: readonly StoredEvidence[]): void {
    this.assertOpen();
    const content = { schemaVersion: 1 as const, previous: this.#head, records };
    const batch: JournalBatch = freeze({ ...content, digest: digest(content) });
    const buffer = Buffer.from(canonical(batch) + '\n');
    if (this.#bytes + buffer.length > this.maxStoreBytes) throw new EvidenceError('store-limit');
    try {
      if (this.#file === undefined || fstatSync(this.#file).size !== this.#bytes) throw new Error();
      let offset = 0;
      while (offset < buffer.length) {
        const count = writeSync(this.#file, buffer, offset, buffer.length - offset);
        if (!count) throw new Error();
        offset += count;
      }
      fsyncSync(this.#file);
      this.#bytes += buffer.length;
      this.#head = batch.digest;
    } catch { this.#failed = true; throw new EvidenceError('storage-failed'); }
  }
  private load(source: string): void {
    if (!source) return;
    if (!source.endsWith('\n')) throw new EvidenceError('integrity-failed');
    try {
      for (const line of source.slice(0, -1).split('\n')) {
        const batch: unknown = JSON.parse(line);
        if (!object(batch) || batch.schemaVersion !== 1 || batch.previous !== this.#head
          || !Array.isArray(batch.records) || !batch.records.length || typeof batch.digest !== 'string'
          || Object.keys(batch).some(key => !['schemaVersion', 'previous', 'records', 'digest'].includes(key))) throw new Error();
        const { digest: supplied, ...content } = batch;
        if (digest(content) !== supplied) throw new Error();
        this.restore(batch.records);
        this.#head = supplied;
      }
    } catch { throw new EvidenceError('integrity-failed'); }
  }
}

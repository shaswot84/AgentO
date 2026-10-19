import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as fs from 'node:fs';
import { FileEvidenceStore, verifyEvidenceBundle } from '../src/index.js';
import { evidence, finding, scope } from './helpers.js';

const directories: string[] = [];
const handles: FileEvidenceStore[] = [];
function directory() { const path = mkdtempSync(join(tmpdir(), 'agento-evidence-test-')); directories.push(path); return path; }
function open(path: string, options = {}) { const store = new FileEvidenceStore(path, options); handles.push(store); return store; }
afterEach(() => { vi.restoreAllMocks(); for (const store of handles.splice(0)) store.close(); for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true }); });

describe('append-only local proof journal', () => {
  it('retains a confirmed finding across close/reopen without calling the scanner', () => {
    const path = directory();
    const first = open(path, { secrets: ['PRIVATE_SESSION'] });
    first.capture([evidence('proof', { facts: { note: 'PRIVATE_SESSION', status: 200 } })], scope);
    const before = readFileSync(join(path, 'evidence.jsonl'), 'utf8');
    first.capture([evidence('next')], scope);
    const after = readFileSync(join(path, 'evidence.jsonl'), 'utf8');
    expect(after.startsWith(before)).toBe(true); expect(after).not.toContain('PRIVATE_SESSION');
    const head = first.headDigest; first.close();
    const second = open(path, { expectedHeadDigest: head });
    expect(second.list()).toHaveLength(2); expect(second.headDigest).toBe(head);
    const bundle = second.exportFinding(finding());
    expect(verifyEvidenceBundle(JSON.parse(JSON.stringify(bundle))).evidence[0]!.facts.status).toBe(200);
    expect(Object.isFrozen(second.get('proof')!.facts)).toBe(true);
  });
  it('uses private directory, journal and lock permissions', () => {
    const path = join(directory(), 'vault'); const store = open(path);
    store.capture([evidence()], scope);
    expect(statSync(path).mode & 0o777).toBe(0o700);
    expect(statSync(join(path, 'evidence.jsonl')).mode & 0o777).toBe(0o600);
    expect(statSync(join(path, '.writer.lock')).mode & 0o777).toBe(0o600);
  });
  it('rejects concurrent writers and releases only its own lock', () => {
    const path = directory(); const first = open(path);
    expect(() => new FileEvidenceStore(path)).toThrow('store-locked');
    expect(() => new FileEvidenceStore(path)).toThrow('store-locked');
    first.capture([evidence()], scope); first.close();
    expect(open(path).get('proof')).toBeDefined();
  });
  it.each(['record', 'chain', 'partial', 'append', 'reorder'])('fails closed after %s corruption', mode => {
    const path = directory(); const store = open(path); store.capture([evidence()], scope); store.capture([evidence('next')], scope); store.close();
    const journal = join(path, 'evidence.jsonl'); const original = readFileSync(journal, 'utf8');
    let changed = original;
    if (mode === 'record') changed = original.replace('Synthetic response', 'Modified response');
    if (mode === 'chain') { const lines = original.trimEnd().split('\n').map(line => JSON.parse(line)); lines[1].previous = '0'.repeat(64); changed = lines.map(line => JSON.stringify(line)).join('\n') + '\n'; }
    if (mode === 'partial') changed = original.slice(0, -5);
    if (mode === 'append') changed += 'PRIVATE_GARBAGE\n';
    if (mode === 'reorder') changed = original.trimEnd().split('\n').reverse().join('\n') + '\n';
    writeFileSync(journal, changed);
    expect(() => new FileEvidenceStore(path)).toThrow('integrity-failed');
    expect(readFileSync(journal, 'utf8')).toBe(changed);
    // Failure releases the owned lock, allowing a later repaired copy to be opened.
    writeFileSync(journal, original); expect(open(path).list()).toHaveLength(2);
  });
  it('detects deleted tails through a trusted external checkpoint', () => {
    const path = directory(); const store = open(path); store.capture([evidence()], scope); store.capture([evidence('next')], scope);
    const checkpoint = store.headDigest; store.close();
    const journal = join(path, 'evidence.jsonl'); const lines = readFileSync(journal, 'utf8').trimEnd().split('\n');
    writeFileSync(journal, lines[0] + '\n');
    expect(() => new FileEvidenceStore(path, { expectedHeadDigest: checkpoint })).toThrow('integrity-failed');
    expect(() => new FileEvidenceStore(path, { expectedHeadDigest: null })).toThrow('integrity-failed');
  });
  it('never persists a partially valid or duplicate batch', () => {
    const path = directory(); const store = open(path); store.capture([evidence()], scope);
    const before = readFileSync(join(path, 'evidence.jsonl'), 'utf8');
    expect(() => store.capture([evidence('next'), evidence()], scope)).toThrow('duplicate-evidence');
    expect(readFileSync(join(path, 'evidence.jsonl'), 'utf8')).toBe(before);
    expect(store.get('next')).toBeUndefined();
  });
  it('rejects an unsafe directory and symlinked journal', () => {
    const path = directory(); chmodSync(path, 0o755);
    expect(() => new FileEvidenceStore(path)).toThrow('storage-failed');
    chmodSync(path, 0o700);
    const target = join(directory(), 'PRIVATE_TARGET'); writeFileSync(target, 'private', { mode: 0o600 });
    symlinkSync(target, join(path, 'evidence.jsonl'));
    expect(() => new FileEvidenceStore(path)).toThrow('storage-failed');
    expect(readFileSync(target, 'utf8')).toBe('private');
  });
  it('enforces disk limits before writes and on reopen', () => {
    const path = directory(); const store = open(path, { maxStoreBytes: 50 });
    expect(() => store.capture([evidence()], scope)).toThrow('store-limit');
    expect(readFileSync(join(path, 'evidence.jsonl'), 'utf8')).toBe(''); store.close();
    const next = open(path); next.capture([evidence()], scope); next.close();
    expect(() => new FileEvidenceStore(path, { maxStoreBytes: 50 })).toThrow('store-limit');
  });
  it('poisons the handle after an external append and does not expose an uncommitted record', () => {
    const path = directory(); const store = open(path); store.capture([evidence()], scope);
    fs.appendFileSync(join(path, 'evidence.jsonl'), 'unexpected\n');
    expect(() => store.capture([evidence('next')], scope)).toThrow('storage-failed');
    expect(() => store.get('next')).toThrow('storage-failed');
    store.close(); expect(() => new FileEvidenceStore(path)).toThrow('integrity-failed');
  });
});

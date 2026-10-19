import { describe, expect, it } from 'vitest';
import { EVIDENCE_KINDS, MemoryEvidenceStore, verifyEvidenceBundle } from '../src/index.js';
import { evidence, finding, project, scope } from './helpers.js';

describe('immutable evidence records', () => {
  it.each(EVIDENCE_KINDS)('retains %s facts with a probe, capability, timestamp and target', kind => {
    const store = new MemoryEvidenceStore();
    const item = store.capture([evidence('proof', { kind })], scope)[0]!;
    expect(item).toMatchObject({ kind, schemaVersion: 1, producerId: 'probe:authorization', capturedAt: '2026-10-19T00:00:00Z',
      provenance: { probeId: 'authorization', capabilityIds: ['request-executor', 'response-collector'],
        environment: { id: 'test', baseUrl: project.baseUrl, targetUrl: project.baseUrl } }, digest: expect.stringMatching(/^[a-f0-9]{64}$/) });
    expect(store.get('proof')).toBe(item);
    expect(store.list({ kind, probeId: 'authorization', projectId: project.id, producerId: item.producerId })).toEqual([item]);
    expect(store.list({ projectId: 'other' })).toEqual([]);
  });
  it('copies all provider data and freezes all nested records and collection views', () => {
    const source = { file: 'src/route.ts', startLine: 10, endLine: 12 };
    const facts = { nested: { items: [{ status: 200 }] } };
    const input = evidence('proof', { facts, source });
    const store = new MemoryEvidenceStore();
    const [item] = store.capture([input], scope);
    facts.nested.items[0]!.status = 500; source.startLine = 99;
    expect(item!.source?.startLine).toBe(10);
    expect(item!.facts.nested).toEqual({ items: [{ status: 200 }] });
    function check(value: unknown): void {
      if (!value || typeof value !== 'object') return;
      expect(Object.isFrozen(value)).toBe(true);
      for (const child of Object.values(value)) check(child);
    }
    check(item); check(store.list()); check(store.forFinding(finding()));
    expect(() => { (item!.facts as Record<string, unknown>).changed = true; }).toThrow();
    expect(() => { (item as unknown as { source: { startLine: number } }).source.startLine = 1; }).toThrow();
    expect('delete' in store).toBe(false); expect('update' in store).toBe(false);
  });
  it('produces equal hashes for different property order and changes hashes when facts change', () => {
    const a = new MemoryEvidenceStore().capture([evidence('proof', { facts: { a: 1, b: 2 } })], scope)[0]!;
    const b = new MemoryEvidenceStore().capture([evidence('proof', { facts: { b: 2, a: 1 } })], scope)[0]!;
    const c = new MemoryEvidenceStore().capture([evidence('proof', { facts: { b: 3, a: 1 } })], scope)[0]!;
    expect(a.digest).toBe(b.digest); expect(c.digest).not.toBe(a.digest);
  });
  it('rejects a duplicate ID, including an identical record, without changing facts', () => {
    const store = new MemoryEvidenceStore(); store.capture([evidence()], scope);
    expect(() => store.capture([evidence()], scope)).toThrow('duplicate-evidence');
    expect(() => store.capture([evidence('next'), evidence('proof', { summary: 'Changed.' })], scope)).toThrow('duplicate-evidence');
    expect(store.list()).toHaveLength(1); expect(store.get('next')).toBeUndefined();
  });
  it('validates the entire batch before retaining any record', () => {
    const store = new MemoryEvidenceStore();
    expect(() => store.capture([evidence('a'), evidence('a')], scope)).toThrow('duplicate-evidence');
    expect(() => store.capture([evidence('a'), evidence('b', { projectId: 'other' })], scope)).toThrow('project-mismatch');
    expect(store.list()).toEqual([]);
  });
  it('limits record counts, sizes and total retained bytes', () => {
    const store = new MemoryEvidenceStore({ maxRecords: 1 }); store.capture([evidence()], scope);
    expect(() => store.capture([evidence('next')], scope)).toThrow('record-limit');
    expect(() => new MemoryEvidenceStore({ maxRecordBytes: 50 }).capture([evidence()], scope)).toThrow('record-limit');
    expect(() => new MemoryEvidenceStore({ maxStoreBytes: 50 }).capture([evidence()], scope)).toThrow('store-limit');
    for (const maxRecords of [0, -1, 1.1, Infinity]) expect(() => new MemoryEvidenceStore({ maxRecords })).toThrow('invalid-options');
  });
  it('rejects malformed evidence without exposing private values', () => {
    for (const extra of [{ kind: 'PRIVATE_KIND' }, { capturedAt: 'PRIVATE_TIME' }, { id: '' }, { facts: [] },
      { source: { file: 'PRIVATE_PATH', startLine: 0 } }, { source: { file: 'x', startLine: 3, endLine: 2 } },
      { facts: { value: NaN } }, { facts: { value: undefined } }, { facts: new Date() }]) {
      const store = new MemoryEvidenceStore();
      expect(() => store.capture([evidence('proof', extra as never)], scope)).toThrow('invalid-evidence');
      expect(store.list()).toEqual([]);
    }
  });
  it('rejects cycles, deep nesting, provider instances and accessors without invoking getters', () => {
    const cyclic: Record<string, unknown> = {}; cyclic.self = cyclic;
    let getterCalled = false;
    const accessor = Object.defineProperty({}, 'secret', { enumerable: true, get() { getterCalled = true; return 'PRIVATE'; } });
    let deep: unknown = {}; for (let i = 0; i < 45; i++) deep = { child: deep };
    for (const facts of [cyclic, accessor, deep, new Map(), { value: new Uint8Array([1]) }, { value: [, 1] }]) {
      expect(() => new MemoryEvidenceStore().capture([evidence('proof', { facts: facts as never })], scope)).toThrow('invalid-evidence');
    }
    expect(getterCalled).toBe(false);
  });
  it('rejects prototype-changing property names', () => {
    for (const name of ['__proto__', 'constructor', 'prototype']) {
      const facts = JSON.parse(`{"${name}":{"polluted":true}}`);
      expect(() => new MemoryEvidenceStore().capture([evidence('proof', { facts })], scope)).toThrow('invalid-evidence');
    }
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
  it('does not retain mutable external artifact references or provider extras', () => {
    const input = { ...evidence(), artifactRef: '/private/image.png', providerSDK: 'PRIVATE' };
    const item = new MemoryEvidenceStore().capture([input], scope)[0]!;
    expect(item.artifactRef).toBeUndefined(); expect(JSON.stringify(item)).not.toContain('PRIVATE');
  });
  it('requires valid capability and target attribution', () => {
    for (const options of [{ capabilityIds: [] }, { project: { ...project, baseUrl: 'file:///PRIVATE' } },
      { targetUrl: 'PRIVATE' }, { probeId: '' }, { environmentId: '' }]) {
      expect(() => new MemoryEvidenceStore().capture([evidence()], { ...scope, ...options })).toThrow('invalid-evidence');
    }
  });
  it('blocks all operations after close', () => {
    const store = new MemoryEvidenceStore(); store.close(); store.close();
    for (const action of [() => store.get('proof'), () => store.list(), () => store.capture([], scope), () => store.forFinding(finding())]) {
      expect(action).toThrow('store-closed');
    }
  });
});

describe('finding proof without another scan', () => {
  it('exports and verifies a portable, frozen bundle with direct immutable references', () => {
    const store = new MemoryEvidenceStore(); store.capture([evidence()], scope);
    const bundle = store.exportFinding(finding());
    const restored = verifyEvidenceBundle(JSON.parse(JSON.stringify(bundle)), bundle.digest);
    expect(restored).toEqual(bundle); expect(Object.isFrozen(restored.evidence[0]?.facts)).toBe(true);
    expect(restored.finding.evidenceIds).toEqual(['proof']);
    expect(JSON.stringify(restored)).not.toContain('rootCause');
  });
  it('rejects confirmed findings without proof, unknown IDs, duplicate IDs and other projects', () => {
    const store = new MemoryEvidenceStore(); store.capture([evidence()], scope);
    expect(() => store.forFinding(finding([]))).toThrow('missing-evidence');
    expect(() => store.forFinding(finding(['unknown']))).toThrow('missing-evidence');
    expect(() => store.forFinding(finding(['proof', 'proof']))).toThrow('missing-evidence');
    expect(() => store.forFinding(finding(['proof'], { projectId: 'other' }))).toThrow('project-mismatch');
    expect(store.forFinding(finding([], { status: 'NOT_REPRODUCED' }))).toEqual([]);
  });
  it('detects edits, missing facts, reordered references and a wrong external digest', () => {
    const store = new MemoryEvidenceStore(); store.capture([evidence('a'), evidence('b')], scope);
    const bundle = store.exportFinding(finding(['a', 'b']));
    for (const mutate of [(value: any) => { value.evidence[0].facts.status = 403; },
      (value: any) => { value.finding.evidenceIds.reverse(); }, (value: any) => { value.evidence.pop(); },
      (value: any) => { value.evidence[0].provenance.environment.id = 'other'; }]) {
      const value = structuredClone(bundle); mutate(value);
      expect(() => verifyEvidenceBundle(value)).toThrow('integrity-failed');
    }
    expect(() => verifyEvidenceBundle(bundle, '0'.repeat(64))).toThrow('integrity-failed');
  });
});

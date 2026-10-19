import type { Evidence, EvidenceCaptureContext, EvidenceStore, Finding } from '@agento/core';
import { EvidenceError, type EvidenceBundle, type EvidenceFilter, type EvidenceStoreOptions, type StoredEvidence } from './contracts.js';
import { createRecord, restoreRecord } from './records.js';
import { Redactor } from './redaction.js';
import { canonical, digest, freeze, jsonCopy, object, positive, text } from './value.js';

export class MemoryEvidenceStore implements EvidenceStore {
  readonly #records = new Map<string, StoredEvidence>();
  readonly #redactor: Redactor;
  readonly #maxRecordBytes: number;
  readonly #maxRecords: number;
  protected readonly maxStoreBytes: number;
  #bytes = 0;
  #closed = false;
  constructor(options: EvidenceStoreOptions = {}) {
    this.#redactor = new Redactor(options.secrets);
    this.#maxRecordBytes = positive(options.maxRecordBytes ?? 1_048_576, 16_777_216);
    this.#maxRecords = positive(options.maxRecords ?? 10_000, 1_000_000);
    this.maxStoreBytes = positive(options.maxStoreBytes ?? 67_108_864, 1_073_741_824);
  }
  capture(evidence: readonly Evidence[], context: EvidenceCaptureContext): readonly StoredEvidence[] {
    this.assertOpen();
    if (!Array.isArray(evidence) || evidence.length > this.#maxRecords) throw new EvidenceError('record-limit');
    const records = evidence.map(item => createRecord(item, context, this.#redactor));
    this.validateBatch(records);
    if (records.length) this.persist(records);
    this.commit(records);
    return Object.freeze(records);
  }
  get(id: string): StoredEvidence | undefined { this.assertOpen(); return this.#records.get(id); }
  list(filter: EvidenceFilter = {}): readonly StoredEvidence[] {
    this.assertOpen();
    return Object.freeze([...this.#records.values()].filter(item =>
      (filter.projectId === undefined || item.projectId === filter.projectId)
      && (filter.kind === undefined || item.kind === filter.kind)
      && (filter.producerId === undefined || item.producerId === filter.producerId)
      && (filter.probeId === undefined || item.provenance.probeId === filter.probeId)));
  }
  forFinding(finding: Finding): readonly StoredEvidence[] {
    this.assertOpen();
    if (!Array.isArray(finding.evidenceIds) || finding.status === 'CONFIRMED' && !finding.evidenceIds.length
      || new Set(finding.evidenceIds).size !== finding.evidenceIds.length) throw new EvidenceError('missing-evidence');
    return Object.freeze(finding.evidenceIds.map(id => {
      const record = this.#records.get(id);
      if (!record) throw new EvidenceError('missing-evidence');
      if (record.projectId !== finding.projectId) throw new EvidenceError('project-mismatch');
      return record;
    }));
  }
  exportFinding(finding: Finding): EvidenceBundle {
    const evidence = this.forFinding(finding);
    const content = { schemaVersion: 1 as const,
      finding: { id: finding.id, projectId: finding.projectId, cweId: finding.cweId,
        status: finding.status, evidenceIds: [...finding.evidenceIds] }, evidence };
    // Validate exported identifiers as well; free-form titles and explanations never enter bundles.
    for (const value of [finding.id, finding.projectId, finding.cweId]) {
      if (!text(value) || this.#redactor.text(value) !== value) throw new EvidenceError('invalid-evidence');
    }
    return freeze({ ...content, digest: digest(content) });
  }
  close(): void { this.#closed = true; }
  protected assertOpen(): void { if (this.#closed) throw new EvidenceError('store-closed'); }
  protected persist(_records: readonly StoredEvidence[]): void { /* Memory store has no I/O. */ }
  protected restore(records: readonly unknown[]): void {
    const checked = records.map(restoreRecord);
    this.validateBatch(checked);
    this.commit(checked);
  }
  private validateBatch(records: readonly StoredEvidence[]): void {
    if (this.#records.size + records.length > this.#maxRecords) throw new EvidenceError('record-limit');
    const ids = new Set<string>();
    let bytes = this.#bytes;
    for (const item of records) {
      if (ids.has(item.id) || this.#records.has(item.id)) throw new EvidenceError('duplicate-evidence');
      ids.add(item.id);
      const size = Buffer.byteLength(canonical(item));
      if (size > this.#maxRecordBytes) throw new EvidenceError('record-limit');
      bytes += size;
    }
    if (bytes > this.maxStoreBytes) throw new EvidenceError('store-limit');
  }
  private commit(records: readonly StoredEvidence[]): void {
    for (const item of records) {
      this.#records.set(item.id, item);
      this.#bytes += Buffer.byteLength(canonical(item));
    }
  }
}

/** Verify a portable JSON proof bundle. An external expected digest detects a complete rewrite. */
export function verifyEvidenceBundle(input: unknown, expectedDigest?: string): EvidenceBundle {
  try {
    const value = jsonCopy(input);
    if (!object(value) || value.schemaVersion !== 1 || typeof value.digest !== 'string'
      || !object(value.finding) || !Array.isArray(value.evidence)) throw new EvidenceError('integrity-failed');
    const { digest: supplied, ...content } = value;
    if (digest(content) !== supplied || expectedDigest !== undefined && supplied !== expectedDigest) throw new EvidenceError('integrity-failed');
    const finding = value.finding;
    if (!['id', 'projectId', 'cweId'].every(key => text(finding[key])) || !/^CWE-\d+$/.test(finding.cweId as string)
      || !['HYPOTHESIS', 'LIKELY', 'CONFIRMED', 'NOT_REPRODUCED', 'REJECTED'].includes(finding.status as string)
      || !Array.isArray(finding.evidenceIds) || !finding.evidenceIds.every(text)
      || finding.status === 'CONFIRMED' && !finding.evidenceIds.length
      || new Set(finding.evidenceIds).size !== finding.evidenceIds.length) throw new EvidenceError('integrity-failed');
    const records = value.evidence.map(restoreRecord);
    if (records.length !== finding.evidenceIds.length || records.some((record, index) =>
      record.id !== (finding.evidenceIds as string[])[index] || record.projectId !== finding.projectId)) throw new EvidenceError('integrity-failed');
    if (Object.keys(value).some(key => !['schemaVersion', 'finding', 'evidence', 'digest'].includes(key))
      || Object.keys(finding).some(key => !['id', 'projectId', 'cweId', 'status', 'evidenceIds'].includes(key))) throw new EvidenceError('integrity-failed');
    return freeze({ ...value, evidence: records }) as unknown as EvidenceBundle;
  } catch { throw new EvidenceError('integrity-failed'); }
}

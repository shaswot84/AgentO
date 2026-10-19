import type { Evidence, EvidenceKind, Finding, JsonValue } from '@agento/core';

export interface EvidenceProvenance {
  readonly probeId: string;
  readonly capabilityIds: readonly string[];
  readonly environment: {
    readonly id: string;
    readonly baseUrl: string;
    readonly targetUrl: string;
  };
}
export interface StoredEvidence extends Evidence {
  readonly schemaVersion: 1;
  readonly provenance: EvidenceProvenance;
  /** SHA-256 of the canonical, redacted record, excluding this field. */
  readonly digest: string;
}
export type SourceEvidence = StoredEvidence & { readonly kind: 'source-location' };
export type HttpEvidence = StoredEvidence & { readonly kind: 'http-request' | 'http-response' };
export type HeaderEvidence = StoredEvidence & { readonly kind: 'header' };
export type CookieSecurityEvidence = StoredEvidence & { readonly kind: 'cookie-security' };
export type CrossOriginEvidence = StoredEvidence & { readonly kind: 'cross-origin' };
export type AuthorizationEvidence = StoredEvidence & { readonly kind: 'authorization' };
export type BrowserEvidence = StoredEvidence & { readonly kind: 'browser-observation' | 'screenshot' };
export type ScannerEvidence = StoredEvidence & { readonly kind: 'scanner-output' };

export interface EvidenceFilter {
  readonly projectId?: string;
  readonly kind?: EvidenceKind;
  readonly producerId?: string;
  readonly probeId?: string;
}
export interface EvidenceStoreOptions {
  /** Private host values, applied to strings and property names before retention. Never persisted. */
  readonly secrets?: readonly string[];
  readonly maxRecordBytes?: number;
  readonly maxRecords?: number;
  readonly maxStoreBytes?: number;
}
export interface FileEvidenceStoreOptions extends EvidenceStoreOptions {
  /** Trusted checkpoint from a previous close; null means the journal must be empty. */
  readonly expectedHeadDigest?: string | null;
}
/** Portable proof bundle. It contains no executable plan, raw tool output, or finding prose. */
export interface EvidenceBundle {
  readonly schemaVersion: 1;
  readonly finding: Pick<Finding, 'id' | 'projectId' | 'cweId' | 'status' | 'evidenceIds'>;
  readonly evidence: readonly StoredEvidence[];
  readonly digest: string;
}
export interface JournalBatch {
  readonly schemaVersion: 1;
  readonly previous: string | null;
  readonly records: readonly StoredEvidence[];
  readonly digest: string;
}
export type EvidenceErrorCode = 'invalid-evidence' | 'invalid-options' | 'duplicate-evidence'
  | 'record-limit' | 'store-limit' | 'missing-evidence' | 'project-mismatch'
  | 'integrity-failed' | 'storage-failed' | 'store-locked' | 'store-closed';
export class EvidenceError extends Error {
  constructor(readonly code: EvidenceErrorCode) { super(code); this.name = 'EvidenceError'; }
}
export type JsonRecord = Readonly<Record<string, JsonValue>>;

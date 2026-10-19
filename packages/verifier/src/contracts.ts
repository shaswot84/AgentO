import type { AnalysisContext, EvidenceStore, Finding, SecurityHypothesis, SecurityTestPlan, SecurityTestResult } from '@agento/core';
import type { CWEPlugin } from '@agento/cwe';

export interface VerificationInput {
  readonly context: AnalysisContext;
  readonly hypothesis: SecurityHypothesis;
  readonly plans: readonly SecurityTestPlan[];
  readonly results: readonly SecurityTestResult[];
}
export interface VerifierOptions {
  readonly plugins: readonly CWEPlugin[];
  readonly evidenceStore: EvidenceStore;
  /** A host-selected run/environment label; records from other environments are excluded. */
  readonly environmentId?: string;
}
export type VerificationDiagnostic = 'invalid-plan' | 'invalid-result' | 'unusable-evidence'
  | 'incomplete-execution' | 'conflicting-evidence' | 'model-assessment-rejected';
export interface CitedClaim {
  readonly text: string;
  readonly evidenceIds: readonly string[];
}
/** Optional model explanation. It cannot choose or override the deterministic verdict. */
export interface ModelAssessment {
  readonly status: Finding['status'];
  readonly claims: readonly CitedClaim[];
}
export interface VerificationDecision {
  readonly schemaVersion: 1;
  readonly finding: Finding;
  readonly staticEvidenceIds: readonly string[];
  readonly runtimeEvidenceIds: readonly string[];
  readonly diagnostics: readonly VerificationDiagnostic[];
  readonly modelAssessment: ModelAssessment | null;
}
export class VerificationError extends Error {
  constructor(readonly code: 'invalid-options' | 'invalid-context' | 'invalid-hypothesis' | 'missing-evidence') {
    super(code); this.name = 'VerificationError';
  }
}

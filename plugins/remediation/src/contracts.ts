import type { EvidenceStore, RemediationSuggestion } from '@agento/core';

/** The authorized host reads files. The provider has no filesystem or execution port. */
export interface SourceSnapshot {
  readonly path: string;
  readonly content: string;
  readonly sha256: string;
  readonly evidenceIds: readonly string[];
}
export interface ExpressRemediationOptions {
  readonly evidenceStore: EvidenceStore;
  readonly sources: readonly SourceSnapshot[];
  readonly secrets?: readonly string[];
  readonly maxPatchBytes?: number;
}
export interface PreparedRemediation extends RemediationSuggestion {
  readonly status: 'SUGGESTED';
  readonly recipeId: string;
  readonly sourceEvidenceIds: readonly string[];
  readonly files: readonly {
    readonly path: string;
    readonly beforeSha256: string;
    readonly afterSha256: string;
  }[];
  readonly regressionTestPath: string;
  /** Generating a patch does not establish that it fixes the finding. */
  readonly validation: 'NOT_RUN';
  readonly patch: string;
  readonly regressionTest: string;
}
export type RemediationErrorCode = 'invalid-input' | 'not-confirmed' | 'unsupported-source'
  | 'missing-source' | 'source-mismatch' | 'unrelated-evidence' | 'integrity-failed'
  | 'unsafe-output' | 'patch-limit';
export class RemediationError extends Error {
  constructor(readonly code: RemediationErrorCode) {
    super(`Remediation failed: ${code}`);
    this.name = 'RemediationError';
  }
}
export interface RecipeFile {
  readonly path: string;
  /** Reviewed template revision. Unknown revisions require a new reviewed recipe. */
  readonly sha256: string;
  readonly edits: readonly { readonly before: string; readonly after: string }[];
}
export interface ExpressRecipe {
  readonly id: string;
  readonly cweId: string;
  readonly endpoint: string;
  readonly explanation: string;
  readonly files: readonly RecipeFile[];
}

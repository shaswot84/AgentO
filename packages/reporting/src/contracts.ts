import type {
  AnalysisContext, CWEId, EvidenceStore, Finding, FindingStatus, RemediationSuggestion, RetestResult,
  SecurityHypothesis, SecurityTestPlan, SecurityTestResult, Severity, SourceLocation,
} from '@agento/core';
import type { StoredEvidence } from '@agento/evidence';

export interface CitedText {
  readonly text: string;
  readonly evidenceIds: readonly string[];
}
/** Compatible with the verification judge; model prose is deliberately excluded. */
export interface ReportDecision {
  readonly finding: Finding;
  readonly staticEvidenceIds: readonly string[];
  readonly runtimeEvidenceIds: readonly string[];
  readonly diagnostics: readonly string[];
}
/** Core and A01/A02/A05 scan reports can be supplied directly. */
export interface ReportInput {
  readonly context: Pick<AnalysisContext, 'project' | 'endpoints'>;
  readonly findings: readonly Finding[];
  readonly hypotheses?: readonly SecurityHypothesis[];
  readonly plans?: readonly SecurityTestPlan[];
  readonly results?: readonly SecurityTestResult[];
  readonly decisions?: readonly ReportDecision[];
  readonly remediation?: readonly RemediationSuggestion[];
  /** Supply one selected fix attempt per finding; all prior evidence stays in the store. */
  readonly retests?: readonly RetestResult[];
}
export interface ReportingOptions {
  readonly evidenceStore: EvidenceStore;
  /** Private values that must also be removed from finding and plan prose. */
  readonly secrets?: readonly string[];
  /** Supply a fixed timestamp for reproducible exports. Defaults to the current UTC time. */
  readonly generatedAt?: string;
  readonly maxFindings?: number;
  readonly maxEvidence?: number;
  readonly maxReportBytes?: number;
}
export interface ReportPlan {
  readonly id: string;
  readonly executor: SecurityTestPlan['executor'];
  readonly risk: SecurityTestPlan['risk'];
  readonly targetUrl: string;
  readonly requiredCapabilities: readonly string[];
  readonly identityIds: readonly string[];
  readonly steps: readonly { readonly id: string; readonly action: string; readonly expectedObservation: string }[];
  readonly evidenceIds: readonly string[];
}
export interface ReportExecution {
  readonly id: string;
  readonly planId: string;
  readonly outcome: SecurityTestResult['outcome'];
  readonly evidenceIds: readonly string[];
}
export interface ReportFinding {
  readonly id: string;
  readonly hypothesisId: string;
  readonly title: string;
  readonly cweId: CWEId;
  readonly owaspCategory: string;
  readonly status: FindingStatus;
  /** Null for hypotheses which have not received a rule assessment. */
  readonly severity: Severity | null;
  readonly confidence: Finding['confidence'] | null;
  readonly assessment: CitedText | null;
  readonly rootCause: CitedText | null;
  readonly endpoint: { readonly id: string; readonly method: string; readonly path: string; readonly evidenceIds: readonly string[] } | null;
  readonly source: { readonly location: SourceLocation; readonly evidenceIds: readonly string[] } | null;
  readonly evidenceIds: readonly string[];
  readonly staticEvidenceIds: readonly string[];
  readonly runtimeEvidenceIds: readonly string[];
  readonly otherEvidenceIds: readonly string[];
  /** Additional endpoint/source records, separate from the assessment's proof. */
  readonly contextEvidenceIds: readonly string[];
  readonly testPlans: readonly ReportPlan[];
  readonly executions: readonly ReportExecution[];
  readonly verification: { readonly source: 'judge' | 'supplied-finding' | 'hypothesis'; readonly diagnostics: readonly string[] };
  readonly remediation: {
    readonly status: 'NOT_PROVIDED' | 'SUGGESTED';
    readonly explanation: CitedText | null;
    readonly patch: CitedText | null;
    readonly regressionTest: CitedText | null;
  };
  /** Initial assessment results never imply a fix has been tested. */
  readonly retest: { readonly status: 'NOT_RUN' } | RetestResult;
  readonly diagnostics: readonly string[];
}
export interface SecurityReport {
  readonly schemaVersion: 1;
  readonly generatedAt: string;
  readonly project: { readonly id: string; readonly name: string; readonly baseUrl: string };
  readonly summary: {
    readonly total: number;
    readonly byStatus: Readonly<Record<FindingStatus, number>>;
    readonly confirmedBySeverity: Readonly<Record<Severity, number>>;
  };
  readonly findings: readonly ReportFinding[];
  /** Exact, digest-checked store records. Reporting never rewrites their facts. */
  readonly evidence: readonly StoredEvidence[];
  readonly limitations: readonly string[];
  /** SHA-256 of the canonical report, excluding this field. This is not a signature. */
  readonly digest: string;
}
export type ReportingErrorCode = 'invalid-options' | 'invalid-input' | 'duplicate-id' | 'project-mismatch'
  | 'missing-evidence' | 'integrity-failed' | 'unsafe-evidence' | 'unrelated-reference' | 'report-limit';
export class ReportingError extends Error {
  constructor(readonly code: ReportingErrorCode) { super(code); this.name = 'ReportingError'; }
}

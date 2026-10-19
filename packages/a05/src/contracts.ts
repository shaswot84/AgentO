import type { AnalysisContext, EvidenceStore, Finding, FrameworkAdapter, Identity, Project, SecurityTestResult, StaticAnalyzer } from '@agento/core';
import type { AuthenticationManager, BrowserController, HttpTransport } from '@agento/runtime';
import type { GroundedHypothesis } from '@agento/hypothesis-engine';
import type { StructuredTestPlan } from '@agento/test-planner';
import type { PolicyAuditRecord, PolicyConfiguration } from '@agento/policy-engine';
import type { ToolRegistration } from '@agento/capability-registry';
import type { VerificationDecision } from '@agento/verifier';

export interface InjectionTarget {
  readonly path: string;
  readonly cweId: 'CWE-79' | 'CWE-89';
  /** Private baseline query values. Only model inputs reached by a static signal are tested. */
  readonly inputs: Readonly<Record<string, string>>;
  /** Explicit host knowledge of a SQL string delimiter and the JSON result field. */
  readonly sqlBooleanContext?: 'quoted-string' | 'like-pattern';
  readonly responseJsonPointer?: string;
}
export interface A05ScanOptions {
  readonly project: Project;
  readonly targets: readonly InjectionTarget[];
  readonly policy: PolicyConfiguration;
  readonly allowAnonymous?: boolean;
  readonly identities?: readonly Identity[];
  readonly authentication?: AuthenticationManager;
  readonly browser?: BrowserController;
  readonly transport?: HttpTransport;
  readonly frameworkAdapter?: FrameworkAdapter;
  readonly staticAnalyzer?: StaticAnalyzer;
  readonly semgrepExecutable?: string;
  /** Capability registrations permit tool replacement without probe/vendor coupling. */
  readonly scanners?: readonly ToolRegistration[];
  readonly maxScannerRequests?: number;
  readonly evidenceStore?: EvidenceStore;
  readonly signal?: AbortSignal;
}
export interface A05Execution {
  readonly planId: string;
  readonly probeId: 'xss' | 'sql-injection';
  readonly outcome: SecurityTestResult['outcome'];
  readonly code: string;
}
export interface A05ScanReport {
  readonly schemaVersion: 1;
  readonly category: 'A05:2025';
  readonly discovery: { readonly mode: Project['mode']; readonly frameworks: readonly string[]; readonly adapterId: string };
  readonly diagnostics: readonly string[];
  readonly context: AnalysisContext;
  readonly hypotheses: readonly GroundedHypothesis[];
  readonly plans: readonly StructuredTestPlan[];
  readonly results: readonly SecurityTestResult[];
  readonly executions: readonly A05Execution[];
  readonly decisions: readonly VerificationDecision[];
  readonly findings: readonly Finding[];
  readonly audit: readonly PolicyAuditRecord[];
}
export class A05Error extends Error {
  constructor(readonly code: 'invalid-options' | 'discovery-unavailable' | 'route-unavailable' | 'cancelled') {
    super(code); this.name = 'A05Error';
  }
}

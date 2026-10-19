import type { AnalysisContext, BrowserWorkflowRuntimeDriver, Credentials, EvidenceStore, Finding, FrameworkAdapter,
  Persona, Project, SecurityTestResult, TargetApplicationProfile } from '@agento/core';
import type { BrowserController, HttpTransport } from '@agento/runtime';
import type { GroundedHypothesis } from '@agento/hypothesis-engine';
import type { StructuredTestPlan } from '@agento/test-planner';
import type { PolicyAuditRecord, PolicyConfiguration } from '@agento/policy-engine';
import type { VerificationDecision } from '@agento/verifier';

export interface AuthorizationTarget {
  readonly path: string;
  readonly cweId: 'CWE-639' | 'CWE-862';
  /** Public, opaque assessment ID, distinct from the target's private input values. */
  readonly resourceId: string;
  readonly ownerIdentityId: string;
  readonly attackerIdentityId: string;
  readonly attackerIsUnauthorized: boolean;
  readonly anonymousIsUnauthorized: boolean;
  /** Private path bindings for ordinary :name route segments. No enumeration. */
  readonly pathValues?: Readonly<Record<string, string>>;
  /** Private resource-specific content. Every marker must occur in both responses. */
  readonly ownerMarkers: readonly string[];
}
export interface A01ScanOptions {
  readonly project: Project;
  readonly targets: readonly AuthorizationTarget[];
  readonly target: TargetApplicationProfile;
  readonly policy: PolicyConfiguration;
  readonly credentials?: (identity: Persona, project: Project) => Promise<Credentials>;
  readonly browserDriver?: BrowserWorkflowRuntimeDriver;
  readonly browser?: BrowserController;
  readonly transport?: HttpTransport;
  readonly frameworkAdapter?: FrameworkAdapter;
  readonly evidenceStore?: EvidenceStore;
  readonly signal?: AbortSignal;
}
export interface A01Execution {
  readonly planId: string;
  readonly probeId: 'authorization';
  readonly outcome: SecurityTestResult['outcome'];
  readonly code: string;
}
export interface A01ScanReport {
  readonly schemaVersion: 1;
  readonly category: 'A01:2025';
  readonly discovery: { readonly mode: Project['mode']; readonly frameworks: readonly string[]; readonly adapterId: string };
  readonly diagnostics: readonly string[];
  readonly context: AnalysisContext;
  readonly hypotheses: readonly GroundedHypothesis[];
  readonly plans: readonly StructuredTestPlan[];
  readonly results: readonly SecurityTestResult[];
  readonly executions: readonly A01Execution[];
  readonly decisions: readonly VerificationDecision[];
  readonly findings: readonly Finding[];
  readonly audit: readonly PolicyAuditRecord[];
}
export class A01Error extends Error {
  constructor(readonly code: 'invalid-options' | 'discovery-unavailable' | 'route-unavailable' | 'cancelled') {
    super(code); this.name = 'A01Error';
  }
}

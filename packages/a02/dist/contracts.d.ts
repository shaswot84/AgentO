import type { AnalysisContext, EvidenceStore, Finding, FrameworkAdapter, Identity, Project, SecurityTestResult } from '@agento/core';
import type { AuthenticationManager, HttpTransport } from '@agento/runtime';
import type { GroundedHypothesis } from '@agento/hypothesis-engine';
import type { StructuredTestPlan } from '@agento/test-planner';
import type { PolicyAuditRecord, PolicyConfiguration } from '@agento/policy-engine';
import type { VerificationDecision } from '@agento/verifier';
export interface A02ScanOptions {
    readonly project: Project;
    /** Explicit literal route paths. Only discovered GET routes are eligible. */
    readonly paths: readonly string[];
    readonly identities: readonly Identity[];
    readonly sensitiveCookieNames: readonly string[];
    readonly untrustedOrigins: readonly string[];
    readonly policy: PolicyConfiguration;
    readonly allowAnonymous?: boolean;
    readonly authentication?: AuthenticationManager;
    readonly transport?: HttpTransport;
    readonly frameworkAdapter?: FrameworkAdapter;
    /** Use a fresh store per run. The caller owns its lifetime. */
    readonly evidenceStore?: EvidenceStore;
    readonly signal?: AbortSignal;
}
export interface A02Execution {
    readonly planId: string;
    readonly probeId: 'cookie-security' | 'cross-origin';
    readonly collectionId: string | null;
    readonly reused: boolean;
    readonly outcome: SecurityTestResult['outcome'];
    /** Fixed host, planner, availability, or policy code; never a raw exception. */
    readonly code: string;
}
export interface A02ScanReport {
    readonly schemaVersion: 1;
    readonly category: 'A02:2025';
    readonly discovery: {
        readonly mode: Project['mode'];
        readonly frameworks: readonly string[];
        readonly adapterId: string;
    };
    readonly diagnostics: readonly string[];
    readonly context: AnalysisContext;
    readonly hypotheses: readonly GroundedHypothesis[];
    readonly plans: readonly StructuredTestPlan[];
    readonly results: readonly SecurityTestResult[];
    readonly executions: readonly A02Execution[];
    readonly decisions: readonly VerificationDecision[];
    readonly findings: readonly Finding[];
    readonly audit: readonly PolicyAuditRecord[];
}
export declare class A02Error extends Error {
    readonly code: 'invalid-options' | 'discovery-unavailable' | 'route-unavailable' | 'cancelled';
    constructor(code: 'invalid-options' | 'discovery-unavailable' | 'route-unavailable' | 'cancelled');
}

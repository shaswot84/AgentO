import type { AnalysisContext, EvidenceStore, Finding, SecurityTestResult } from '@agento/core';
import type { CWEPlugin, NormalizedProbeEvidence, ProbeTestPlan } from '@agento/cwe';
import type { PreparedRemediation } from '@agento/remediation';
export interface RetestInput {
    readonly context: AnalysisContext;
    readonly finding: Finding;
    readonly plan: ProbeTestPlan;
    readonly originalResult: SecurityTestResult;
    readonly remediation: PreparedRemediation;
}
export interface RegressionResult {
    readonly security: 'PASSED' | 'FAILED' | 'NOT_RUN';
    readonly normalFlow: 'PASSED' | 'FAILED' | 'NOT_RUN';
}
/** Trusted host callbacks own process/session/policy isolation and exact private payload replay. */
export interface RetestSession {
    readonly id: string;
    readonly baseUrl: string;
    runRegression(signal: AbortSignal): Promise<RegressionResult>;
    /** Reuse original inputs, identities and payloads; only rebase the origin to the test server. */
    replay(plan: ProbeTestPlan, targetUrl: string, signal: AbortSignal): Promise<NormalizedProbeEvidence>;
    dispose(): Promise<void>;
}
export interface RetestEnvironment {
    /** Own cleanup on partial creation failure, including patch/start errors. */
    create(input: RetestInput, signal: AbortSignal): Promise<RetestSession>;
}
export interface RetestOptions {
    readonly evidenceStore: EvidenceStore;
    readonly rules: readonly CWEPlugin[];
    readonly environment: RetestEnvironment;
    readonly timeoutMs?: number;
}
export declare class RetestError extends Error {
    readonly code: 'invalid-input' | 'invalid-options' | 'unrelated-evidence' | 'integrity-failed' | 'not-confirmed';
    constructor(code: 'invalid-input' | 'invalid-options' | 'unrelated-evidence' | 'integrity-failed' | 'not-confirmed');
}

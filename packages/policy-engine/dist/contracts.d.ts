import type { ExecutionGuard, Project, SecurityTestPlan, Severity } from '@agento/core';
import type { CapabilityRegistry } from '@agento/runtime';
export type Risk = SecurityTestPlan['risk'];
export interface ToolPolicy {
    readonly allowedOrigins?: readonly string[];
    readonly allowedMethods?: readonly string[];
    readonly capabilities?: readonly string[];
    readonly maxRisk?: Risk;
    readonly maxRequests?: number;
}
export interface PolicyConfiguration {
    readonly allowedOrigins: readonly string[];
    /** Default: GET, HEAD, OPTIONS. CONNECT and TRACE are always refused. */
    readonly allowedMethods?: readonly string[];
    /** Explicit tool allowlist. Unlisted tools cannot execute. */
    readonly tools: Readonly<Record<string, ToolPolicy>>;
    readonly maxRisk?: Risk;
    readonly rateLimit?: {
        readonly maxRequests: number;
        readonly windowMs: number;
    };
    readonly maxRequestsPerExecution?: number;
    readonly executionTtlMs?: number;
    /** Default: active risk requires approval. Empty lists disable approval checks. */
    readonly approval?: {
        readonly risks: readonly Risk[];
        readonly severities?: readonly Severity[];
        readonly ttlMs?: number;
    };
    readonly maxAuditRecords?: number;
}
export interface PolicyPlan extends Pick<SecurityTestPlan, 'id' | 'requiredCapabilities' | 'risk' | 'targetUrl'> {
    readonly projectId?: string;
    readonly readiness?: 'READY' | 'BLOCKED';
    readonly probeId?: string;
    readonly request?: {
        readonly method: string;
    };
}
export interface PolicyRequest {
    readonly project: Pick<Project, 'id' | 'baseUrl' | 'allowedOrigins'>;
    readonly plan: PolicyPlan;
    /** Operational test severity, independent of any vulnerability verdict. */
    readonly severity?: Severity;
}
export type PolicyCode = 'allowed' | 'invalid-request' | 'target-denied' | 'redirect-denied' | 'method-denied' | 'tool-denied' | 'risk-denied' | 'plan-blocked' | 'selection-unavailable' | 'approval-required' | 'approval-invalid' | 'rate-limited' | 'request-limit' | 'execution-closed' | 'cancelled' | 'guard-unsupported' | 'audit-unavailable';
export interface PolicyDecision {
    readonly id: string;
    readonly outcome: 'ALLOW' | 'DENY' | 'APPROVAL_REQUIRED';
    readonly code: PolicyCode;
    readonly risk: Risk;
    readonly severity: Severity;
}
/** Projection excludes URL paths, queries, headers, bodies, selectors and private inputs. */
export interface PolicyAuditRecord extends PolicyDecision {
    readonly sequence: number;
    readonly recordedAt: string;
    readonly operation: 'plan' | 'approval' | 'execution' | 'request' | 'redirect' | 'tool';
    readonly executionId?: string;
    readonly toolId?: string;
    readonly origin?: string;
    readonly method?: string;
    readonly planFingerprint?: string;
    readonly reviewId?: string;
    readonly reviewerHash?: string;
    readonly stage?: 'start' | 'finish';
}
export interface PolicyOptions {
    /** Trusted synchronous durable sink. Failure stops execution before the next effect. */
    readonly auditSink?: (record: PolicyAuditRecord) => void;
    /** Injectable clock for deterministic tests. Must return finite epoch milliseconds. */
    readonly now?: () => number;
}
export interface PolicyExecution {
    readonly id: string;
    readonly capabilities: CapabilityRegistry;
    /** Origin intersection for probe contexts. No target can extend it. */
    readonly allowedOrigins: readonly string[];
    readonly signal: AbortSignal;
    guardFor(toolId: string): ExecutionGuard;
}
export declare class PolicyError extends Error {
    readonly code: PolicyCode;
    constructor(code: PolicyCode);
}

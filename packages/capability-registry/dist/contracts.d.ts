import type { CWEId, SecurityTestPlan } from '@agento/core';
import type { CapabilityCatalog, CapabilityRegistry as BoundCapabilities, ProbeRegistry } from '@agento/runtime';
export type CapabilityId = Extract<keyof CapabilityCatalog, string>;
export type Risk = SecurityTestPlan['risk'];
export type Protocol = 'http' | 'https';
/** Public metadata. Executable paths, private configuration and SDK objects stay in the registration. */
export interface ToolMetadata {
    readonly id: string;
    readonly capabilities: readonly CapabilityId[];
    readonly supportedCwes: readonly CWEId[] | 'all';
    readonly protocols: readonly Protocol[];
    readonly risk: Risk;
    /** Higher priority wins between equally risky adapters; ID breaks ties. Default: zero. */
    readonly priority?: number;
}
export interface ToolRegistration {
    readonly metadata: ToolMetadata;
    readonly capabilities: Readonly<Partial<CapabilityCatalog>>;
    /** Bare command on PATH or absolute file path. Checked without running a shell or the executable. */
    readonly executable?: string;
    /** Trusted local preflight only. Do not contact a target or establish a session here. */
    checkAvailability?(signal: AbortSignal): Promise<boolean>;
}
export type AvailabilityCode = 'available' | 'not-installed' | 'not-configured' | 'check-failed' | 'timeout' | 'cancelled';
export interface ToolAvailability {
    readonly toolId: string;
    readonly available: boolean;
    readonly code: AvailabilityCode;
}
export interface RegistryOptions {
    readonly probes?: ProbeRegistry;
    /** Bound each adapter check. Default: 2 seconds; maximum: 30 seconds. */
    readonly availabilityTimeoutMs?: number;
}
export interface LookupRequest {
    readonly capability: string;
    readonly cweId: CWEId;
    readonly protocol: Protocol;
}
/** Structural subset accepted from core, rule and structured planner plans. */
export interface SelectionRequest extends Pick<SecurityTestPlan, 'cweId' | 'targetUrl' | 'requiredCapabilities' | 'risk'> {
    readonly optionalCapabilities?: readonly string[];
    readonly probeId?: string;
    readonly readiness?: 'READY' | 'BLOCKED';
}
export type CandidateCode = AvailabilityCode | 'protocol-unsupported' | 'cwe-unsupported';
export interface CandidateSelection {
    readonly toolId: string;
    readonly risk: Risk;
    readonly code: CandidateCode;
}
export interface CapabilitySelection {
    readonly capability: string;
    readonly required: boolean;
    readonly selectedToolId: string | null;
    readonly candidates: readonly CandidateSelection[];
}
export interface SelectionDiagnostic {
    readonly code: 'invalid-request' | 'plan-blocked' | 'probe-unavailable' | 'capability-unavailable' | 'optional-unavailable' | 'cancelled';
    readonly capability?: string;
}
/** JSON-safe selection data. READY describes availability and never grants execution permission. */
export interface SelectionReport {
    readonly status: 'READY' | 'UNAVAILABLE' | 'BLOCKED' | 'CANCELLED';
    readonly risk: Risk;
    readonly probeId: string | null;
    readonly selections: readonly CapabilitySelection[];
    readonly availability: readonly ToolAvailability[];
    readonly diagnostics: readonly SelectionDiagnostic[];
}
export interface CapabilityResolution {
    readonly report: SelectionReport;
    /** Private adapter instances. Null unless every required capability and probe is available. */
    readonly capabilities: BoundCapabilities | null;
}

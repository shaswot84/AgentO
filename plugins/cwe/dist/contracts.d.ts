import type { CWEId, CWEPlugin as CoreCWEPlugin, SecurityHypothesis, SecurityTestPlan, Severity } from '@agento/core';
import type { AuthorizationEvidence, CookieSecurityEvidence, CrossOriginEvidence, SQLInjectionEvidence, XSSEvidence } from '@agento/runtime';
export interface ProbeEvidenceCatalog {
    'cookie-security': CookieSecurityEvidence;
    'cross-origin': CrossOriginEvidence;
    authorization: AuthorizationEvidence;
    xss: XSSEvidence;
    'sql-injection': SQLInjectionEvidence;
}
export type NormalizedProbeEvidence = ProbeEvidenceCatalog[keyof ProbeEvidenceCatalog];
export interface CWEMetadata {
    readonly cweId: CWEId;
    readonly title: string;
    /** OWASP Top 10 2025 category identifier. */
    readonly owaspCategory: string;
    readonly severity: Severity;
    readonly probeId: keyof ProbeEvidenceCatalog;
    readonly requiredCapabilities: readonly string[];
    readonly optionalCapabilities: readonly string[];
}
/** Trusted application policy. Successful HTTP responses alone cannot establish a violation. */
export interface AuthorizationPolicy {
    readonly resourceId: string;
    readonly ownerIdentityId: string;
    readonly attackerIdentityId: string;
    readonly attackerIsUnauthorized: boolean;
    readonly anonymousIsUnauthorized: boolean;
}
export interface RuleOptions {
    /** Explicit sensitivity declarations; cookie names are never guessed. */
    readonly sensitiveCookieNames?: readonly string[];
    /** Explicitly untrusted Origin header values, including "null" when appropriate. */
    readonly untrustedOrigins?: readonly string[];
    readonly authorizationPolicies?: readonly AuthorizationPolicy[];
}
export interface EvaluationScope {
    readonly projectId: string;
    readonly targetUrl: string;
    readonly method: string;
    readonly identityIds?: readonly string[];
    readonly parameter?: {
        readonly name: string;
        readonly location: 'query' | 'body';
    };
    readonly sensitiveCookieNames?: readonly string[];
    readonly untrustedOrigins?: readonly string[];
    readonly authorization?: AuthorizationPolicy;
}
export interface CWEHypothesis extends SecurityHypothesis {
    readonly scope: EvaluationScope;
}
export interface ProbeTestPlan extends SecurityTestPlan {
    readonly probeId: keyof ProbeEvidenceCatalog;
    readonly scope: EvaluationScope;
}
export interface CWEVerdict {
    readonly cweId: CWEId;
    readonly status: 'CONFIRMED' | 'NOT_REPRODUCED' | 'REJECTED';
    readonly confidence: 'low' | 'medium' | 'high';
    readonly summary: string;
    readonly evidenceIds: readonly string[];
    readonly limitations: readonly string[];
}
/** Also implements the existing core lifecycle, without a new execution path in core. */
export interface CWEPlugin extends CoreCWEPlugin {
    metadata(): CWEMetadata;
    evaluate(evidence: readonly NormalizedProbeEvidence[], scope: EvaluationScope): Promise<CWEVerdict>;
}

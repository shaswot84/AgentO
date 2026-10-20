import type { CWEPlugin, Endpoint, JsonValue, SecurityTestPlan } from '@agento/core';

export type ProbeId = 'authorization' | 'cookie-security' | 'cross-origin' | 'xss' | 'sql-injection';
export interface AccessPolicy {
  readonly resourceId: string;
  readonly ownerIdentityId: string;
  readonly attackerIdentityId: string;
  readonly attackerIsUnauthorized: boolean;
  readonly anonymousIsUnauthorized: boolean;
}
export interface PlanScope {
  readonly projectId: string;
  readonly targetUrl: string;
  readonly method: Endpoint['method'];
  readonly identityIds: readonly string[];
  readonly parameter?: { readonly name: string; readonly location: 'query' | 'body' };
  readonly sensitiveCookieNames?: readonly string[];
  readonly untrustedOrigins?: readonly string[];
  readonly authorization?: AccessPolicy;
}
/** Resolve references privately in the execution host. Plans never contain input values. */
export interface InputBinding {
  readonly name: string;
  readonly location: Endpoint['parameters'][number]['location'];
  readonly valueRef: string;
}
export interface PlanningBindings {
  readonly inputs?: readonly InputBinding[];
  /** Select an identity already declared by the rule; never introduce a new principal. */
  readonly identityId?: string;
  readonly bodyEncoding?: 'json-body' | 'form-body';
  /** Explicit choice for endpoints whose authentication requirement is unknown. */
  readonly allowAnonymous?: boolean;
}
export type PrerequisiteCode = 'authorization-policy-required' | 'unauthorized-control-required'
  | 'distinct-authenticated-identities-required' | 'eligible-identity-required' | 'authentication-unknown'
  | 'owned-resource-required' | 'conflicting-ownership' | 'input-required' | 'body-encoding-required'
  | 'sensitive-cookie-names-required' | 'untrusted-origins-required' | 'https-required';
export interface PlanPrerequisite {
  readonly code: PrerequisiteCode;
  readonly parameter?: { readonly name: string; readonly location: InputBinding['location'] };
}
export interface PlannedParameter {
  readonly name: string;
  readonly location: InputBinding['location'];
  readonly required: boolean;
  readonly source: { readonly kind: 'private-input'; readonly ref: string } | null;
}
export type PlanAction = 'session.establish' | 'resource.identify' | 'request.baseline'
  | 'request.as-attacker' | 'request.anonymous' | 'cookies.collect' | 'cors.preflight'
  | 'cors.actual' | 'xss.inject-canary' | 'xss.collect-execution'
  | 'sql.syntax' | 'sql.boolean-true' | 'sql.boolean-false' | 'responses.compare' | 'verify';
export interface PlannedStep {
  readonly id: string;
  readonly action: PlanAction;
  readonly dependsOn: readonly string[];
  readonly parameters: Readonly<Record<string, JsonValue>>;
  readonly expectedObservation: string;
  readonly onFailure: 'INCONCLUSIVE';
}
export interface VerificationBase {
  readonly evidenceRequirements: readonly string[];
  readonly otherwise: 'INCONCLUSIVE';
}
/** Criteria describe observations to collect; only the CWE rule produces a verdict. */
export type VerificationCriteria = VerificationBase & (
  { readonly strategy: 'authorization'; readonly controls: readonly ('attacker' | 'anonymous')[];
    readonly baseline: { readonly statusRange: readonly [200, 299]; readonly complete: true };
    readonly violation: { readonly statusRange: readonly [200, 299]; readonly ownerMarkersMatch: true; readonly complete: true };
    readonly secure: { readonly deniedStatuses: readonly [401, 403, 404]; readonly allControls: true; readonly outcome: 'COMPLETED' } }
  | { readonly strategy: 'cookie-attribute'; readonly attribute: 'httpOnly' | 'secure';
    readonly cookieNames: readonly string[]; readonly violation: { readonly attributeValue: false };
    readonly secure: { readonly attributeValue: true; readonly atLeastOneMatchingCookie: true; readonly outcome: 'COMPLETED' } }
  | { readonly strategy: 'cors'; readonly origins: readonly string[];
    readonly violation: { readonly actualStatusRange: readonly [200, 299]; readonly allowCredentials: true;
      readonly identityRequiredForReflectedOrigin: true;
      readonly allowOrigin: readonly ['credentialed-untrusted-origin', 'wildcard-configuration'] };
    readonly secure: { readonly actualStatusRange: readonly [200, 299]; readonly noUntrustedOrWildcardGrant: true; readonly outcome: 'COMPLETED' } }
  | { readonly strategy: 'xss'; readonly violation: { readonly executionConfirmed: true };
    readonly secure: { readonly executionConfirmed: false; readonly domSinkReached: false; readonly completeResponses: true; readonly outcome: 'COMPLETED' } }
  | { readonly strategy: 'sql-injection'; readonly baseline: { readonly statusRange: readonly [200, 299]; readonly complete: true };
    readonly violation: { readonly anyOf: readonly ['database-specific-syntax-error-after-successful-baseline', 'true-equals-baseline-and-false-differs'];
      readonly databaseError: { readonly variant: 'syntax'; readonly statusMin: 500; readonly fingerprintMatchesIndicator: true };
      readonly booleanControls: { readonly statusRange: readonly [200, 299]; readonly trueBodyEqualBaseline: true; readonly falseBodyDifferent: true };
      readonly completeResponses: true };
    readonly secure: { readonly variants: readonly ['syntax', 'boolean-true', 'boolean-false']; readonly allSuccessful: true;
      readonly allBodiesEqualBaseline: true; readonly noDatabaseErrors: true; readonly scannerObservedDifference: false; readonly outcome: 'COMPLETED' } }
);
export interface StructuredTestPlan extends SecurityTestPlan {
  readonly schemaVersion: 1;
  readonly projectId: string;
  readonly endpointId: string;
  readonly probeId: ProbeId;
  readonly scope: PlanScope;
  /** READY means bindings are present, not that execution has been approved or tools are available. */
  readonly readiness: 'READY' | 'BLOCKED';
  readonly prerequisites: readonly PlanPrerequisite[];
  readonly optionalCapabilities: readonly string[];
  readonly identities: Readonly<Record<string, string | null>>;
  readonly request: {
    readonly method: Endpoint['method'];
    readonly urlTemplate: string;
    readonly parameters: readonly PlannedParameter[];
    readonly bodyEncoding?: 'json-body' | 'form-body';
  };
  readonly steps: readonly PlannedStep[];
  readonly verification: VerificationCriteria;
  readonly evidenceIds: readonly string[];
  readonly limitations: readonly string[];
}
export interface PlanningDiagnostic {
  readonly code: 'endpoint-unvalidated' | 'invalid-hypothesis' | 'unsupported-cwe' | 'plugin-failed' | 'invalid-plan'
    | 'unsupported-method' | 'no-plans' | 'plan-limit' | 'invalid-bindings';
}
export interface PlanningResult {
  readonly plans: readonly StructuredTestPlan[];
  readonly diagnostics: readonly PlanningDiagnostic[];
}
export interface PlanningPlugin extends Pick<CWEPlugin, 'cweId' | 'generateTests'> {
  metadata?(): { readonly optionalCapabilities: readonly string[] };
}
export interface TestPlannerOptions {
  readonly plugins: readonly PlanningPlugin[];
  readonly maxPlans?: number;
}

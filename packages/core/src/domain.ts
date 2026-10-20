/** JSON-safe normalized values. Provider SDK objects must stay in adapters. */
export type JsonValue = string | number | boolean | null | readonly JsonValue[] | { readonly [key: string]: JsonValue };
export type CWEId = `CWE-${number}`;
export const MVP_CWES = ['CWE-639', 'CWE-862', 'CWE-942', 'CWE-1004', 'CWE-614', 'CWE-79', 'CWE-89'] as const satisfies readonly CWEId[];
export type FindingStatus = 'HYPOTHESIS' | 'LIKELY' | 'CONFIRMED' | 'NOT_REPRODUCED' | 'REJECTED';
/** Fix lifecycle is separate from the immutable original vulnerability assessment. */
export type FixVerificationStatus = 'FIX_VERIFIED' | 'FIX_FAILED' | 'FIX_INCONCLUSIVE';
export interface RetestResult {
  readonly id: string;
  readonly findingId: string;
  readonly projectId: string;
  readonly cweId: CWEId;
  readonly status: FixVerificationStatus;
  readonly comparisonEvidenceId: string;
  readonly beforeEvidenceIds: readonly string[];
  readonly afterEvidenceIds: readonly string[];
}
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface SourceLocation {
  readonly file: string;
  readonly startLine: number;
  readonly endLine?: number;
  readonly symbol?: string;
}

export interface Project {
  readonly id: string;
  readonly name: string;
  readonly mode: 'code-aware' | 'black-box';
  readonly repositoryPath?: string;
  readonly baseUrl: string;
  /** Declared scope, not an authorization or policy-engine decision. */
  readonly allowedOrigins: readonly string[];
  readonly languages: readonly string[];
}

export interface Component {
  readonly id: string;
  readonly projectId: string;
  readonly name: string;
  readonly kind: 'service' | 'frontend' | 'database' | 'library';
  readonly source?: SourceLocation;
}

export interface Endpoint {
  readonly id: string;
  readonly componentId: string;
  readonly method: 'GET' | 'HEAD' | 'OPTIONS' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  readonly path: string;
  readonly parameters: readonly {
    readonly name: string;
    readonly location: 'path' | 'query' | 'body' | 'header' | 'cookie';
    readonly required: boolean;
  }[];
  readonly authentication: 'required' | 'optional' | 'unknown';
  readonly roles: readonly string[];
  readonly handler?: SourceLocation;
  readonly evidenceIds: readonly string[];
  /** Static inventory is not permission to execute a test. Omitted for existing host declarations. */
  readonly discovery?: {
    readonly providerId: string;
    readonly validation: 'candidate' | 'source-corroborated';
  };
}

/** Keep unvalidated inventory out of execution, including after model serialization. */
export function isEndpointTestable(endpoint: Endpoint): boolean {
  return endpoint.discovery === undefined || endpoint.discovery.validation === 'source-corroborated';
}

export interface Identity {
  readonly id: string;
  readonly label: string;
  readonly roles: readonly string[];
  readonly authentication: 'anonymous' | 'session-cookie' | 'jwt';
  /** Opaque handle managed by an adapter; never a password, cookie, or JWT. */
  readonly sessionRef?: string;
}

export interface Resource {
  readonly id: string;
  readonly projectId: string;
  readonly type: string;
  readonly externalKey: string;
  readonly ownerIdentityId?: string;
  readonly endpointId?: string;
  readonly evidenceIds: readonly string[];
}

export type EvidenceKind = 'source-location' | 'static-analysis' | 'http-request' | 'http-response'
  | 'browser-observation' | 'identity-session' | 'resource-ownership' | 'scanner-output'
  | 'screenshot' | 'configuration' | 'header' | 'cookie-security' | 'cross-origin' | 'authorization';

/** Core freezes evidence at ingestion. Dedicated retention and redaction use the EvidenceStore port. */
export interface Evidence {
  readonly id: string;
  readonly projectId: string;
  readonly kind: EvidenceKind;
  readonly producerId: string;
  readonly capturedAt: string;
  readonly summary: string;
  readonly source?: SourceLocation;
  readonly endpointId?: string;
  readonly identityId?: string;
  /** Normalized, redacted facts, never raw provider output or credentials. */
  readonly facts: Readonly<Record<string, JsonValue>>;
  readonly artifactRef?: string;
}

/** A signal is a candidate observation, not a verified vulnerability. */
export interface SecuritySignal {
  readonly id: string;
  readonly projectId: string;
  readonly producerId: string;
  readonly cweIds: readonly CWEId[];
  readonly summary: string;
  readonly source?: SourceLocation;
  readonly endpointId?: string;
  readonly evidenceIds: readonly string[];
}

export interface SecurityHypothesis {
  readonly id: string;
  readonly projectId: string;
  readonly cweId: CWEId;
  readonly status: 'HYPOTHESIS';
  readonly reason: string;
  readonly endpointId?: string;
  readonly source?: SourceLocation;
  readonly evidenceIds: readonly string[];
}

export interface SecurityTestPlan {
  readonly id: string;
  readonly hypothesisId: string;
  readonly cweId: CWEId;
  readonly executor: 'scanner' | 'browser';
  readonly requiredCapabilities: readonly string[];
  readonly risk: 'passive' | 'active';
  readonly targetUrl: string;
  readonly identityIds: readonly string[];
  readonly steps: readonly {
    readonly id: string;
    readonly action: string;
    readonly parameters: Readonly<Record<string, JsonValue>>;
    readonly expectedObservation: string;
  }[];
}

/** Tool outcome is deliberately distinct from a finding verdict. */
export interface SecurityTestResult {
  readonly id: string;
  readonly planId: string;
  readonly producerId: string;
  readonly outcome: 'COMPLETED' | 'FAILED' | 'SKIPPED';
  readonly summary: string;
  readonly evidence: readonly Evidence[];
  readonly error?: { readonly code: string; readonly message: string };
}

export interface Finding {
  readonly id: string;
  readonly projectId: string;
  readonly hypothesisId: string;
  readonly cweId: CWEId;
  readonly owaspCategory: string;
  readonly title: string;
  readonly status: FindingStatus;
  readonly severity: Severity;
  readonly confidence: 'low' | 'medium' | 'high';
  readonly rootCause: string;
  readonly endpointId?: string;
  readonly source?: SourceLocation;
  readonly evidenceIds: readonly string[];
  readonly testPlanIds: readonly string[];
}

/** Flat exchange context; richer merging and lineage live in @agento/security-model. */
export interface AnalysisContext {
  readonly project: Project;
  readonly components: readonly Component[];
  readonly endpoints: readonly Endpoint[];
  readonly identities: readonly Identity[];
  readonly resources: readonly Resource[];
  readonly signals: readonly SecuritySignal[];
  readonly evidence: readonly Evidence[];
}

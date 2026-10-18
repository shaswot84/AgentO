import type { Project } from '@agento/core';
import type {
  AuthSession, CookieEvidence, HeaderEvidence, HttpRequest, HttpResponse,
  HttpResponseEvidence, RequestExecutor, TestIdentity,
} from '../contracts.js';
import type { CapabilityRegistry } from './registry.js';

export interface ProbeMetadata {
  readonly id: string;
  readonly requiredCapabilities: readonly string[];
  readonly optionalCapabilities: readonly string[];
}
export interface SecurityProbe<TContext, TEvidence> {
  metadata(): ProbeMetadata;
  supports(context: TContext): boolean;
  execute(context: TContext): Promise<TEvidence>;
}
export interface ProbeContext {
  readonly project: Project;
  readonly capabilities: CapabilityRegistry;
  readonly signal?: AbortSignal;
}
export interface ProbeEvidence {
  readonly id: string;
  readonly probeId: string;
  readonly projectId: string;
  readonly capturedAt: string;
  /** Collection coverage, independent of any security judgment. */
  readonly outcome: 'COMPLETED' | 'PARTIAL';
  readonly diagnostics: readonly ('scanner-unavailable' | 'browser-unavailable' | 'response-truncated')[];
}
export interface CookieSecurityContext extends ProbeContext {
  readonly request: HttpRequest;
  readonly identities?: readonly TestIdentity[];
}
export interface CookieSecurityEvidence extends ProbeEvidence {
  readonly observations: readonly {
    readonly identityId: string | null;
    readonly context: 'anonymous' | 'authenticated';
    readonly response: HttpResponseEvidence;
    readonly cookies: readonly CookieEvidence[];
  }[];
}
export interface CrossOriginContext extends ProbeContext {
  readonly request: HttpRequest;
  /** Origin header values only; these origins are never navigation targets. */
  readonly origins?: readonly string[];
  readonly requestedHeaders?: readonly string[];
  readonly identity?: TestIdentity;
}
export interface CrossOriginEvidence extends ProbeEvidence {
  readonly observations: readonly {
    readonly requestedOrigin: string;
    readonly identityId: string | null;
    readonly credentialMode: 'omit' | 'session';
    readonly preflight: { readonly response: HttpResponseEvidence; readonly cors: HeaderEvidence['cors'] };
    readonly actual: { readonly response: HttpResponseEvidence; readonly cors: HeaderEvidence['cors'] };
  }[];
}
export interface ResponseComparison {
  readonly statusDelta: number;
  readonly bodyEqual: boolean | null;
  readonly byteLengthDelta: number;
  readonly durationDeltaMs: number;
  /** Null when either body is incomplete or no private owner markers were supplied. */
  readonly ownerMarkersMatch: boolean | null;
}
export interface ResponseComparator {
  compare(reference: HttpResponse, candidate: HttpResponse, ownerMarkers?: readonly string[]): ResponseComparison;
}
export interface AuthorizationResource {
  readonly id: string;
  readonly ownerIdentityId: string;
  readonly request: HttpRequest;
  /** Trusted private resource contents to look for; never included in public evidence. */
  readonly ownerMarkers?: readonly string[];
}
export interface AuthorizationContext extends ProbeContext {
  readonly owner: TestIdentity;
  readonly attacker: TestIdentity;
  readonly resource?: AuthorizationResource;
  /** Trusted discovery callback; use session.http or session.withBrowser to discover ownership. */
  readonly discoverResource?: (owner: AuthSession) => Promise<AuthorizationResource>;
}
export interface AuthorizationEvidence extends ProbeEvidence {
  readonly resourceId: string;
  readonly ownerIdentityId: string;
  readonly attackerIdentityId: string;
  readonly owner: HttpResponseEvidence;
  readonly attacker: HttpResponseEvidence;
  readonly anonymous: HttpResponseEvidence;
  readonly attackerComparison: ResponseComparison;
  readonly anonymousComparison: ResponseComparison;
}
export interface InjectionPoint {
  readonly name: string;
  readonly location: 'query' | 'json-body' | 'form-body';
}
export interface InjectionContext extends ProbeContext {
  readonly request: HttpRequest;
  readonly parameter: InjectionPoint;
  readonly identity?: TestIdentity;
  /** A registered anonymous persona for optional browser observation without authentication. */
  readonly anonymousIdentity?: TestIdentity;
}
export interface ScannerRequest {
  readonly project: Project;
  readonly request: HttpRequest;
  readonly parameter: InjectionPoint;
  readonly canary: string;
  /** Private, scoped HTTP capability, including the selected identity's session when supplied. */
  readonly executor: RequestExecutor;
  /** Adapters must enforce these bounds and the project's exact origins. */
  readonly maxRequests: number;
  readonly signal?: AbortSignal;
}
/** Objective adapter ports. A scanner's finding/verdict output is not accepted here. */
export interface XSSScanner {
  scan(request: ScannerRequest): Promise<{
    readonly executionConfirmed: boolean | null;
    readonly domSinkReached: boolean | null;
  }>;
}
export type DatabaseFingerprint = 'SQLite' | 'PostgreSQL' | 'MySQL' | 'SQLServer' | 'Oracle';
export interface SQLScanner {
  scan(request: ScannerRequest): Promise<{
    readonly technique: 'error' | 'boolean' | 'time';
    readonly dbmsFingerprint: DatabaseFingerprint | null;
    readonly observedDifference: boolean | null;
  }>;
}
export interface XSSEvidence extends ProbeEvidence {
  readonly parameter: InjectionPoint;
  readonly baseline: HttpResponseEvidence;
  readonly injected: HttpResponseEvidence;
  readonly canary: string;
  readonly literalReflection: boolean | null;
  readonly reflectionContexts: readonly ('html' | 'attribute' | 'script' | 'text')[];
  readonly browser: { readonly url: string; readonly canaryVisible: boolean } | null;
  readonly executionConfirmed: boolean | null;
  readonly domSinkReached: boolean | null;
}
export interface SQLInjectionEvidence extends ProbeEvidence {
  readonly parameter: InjectionPoint;
  readonly baseline: HttpResponseEvidence;
  readonly observations: readonly {
    readonly variant: 'syntax' | 'boolean-true' | 'boolean-false';
    readonly technique: 'error' | 'boolean';
    readonly response: HttpResponseEvidence;
    readonly comparison: ResponseComparison;
    readonly errorIndicators: readonly string[];
    /** Heuristic response fingerprint, not proof of the database in use. */
    readonly dbmsFingerprint: DatabaseFingerprint | null;
  }[];
  readonly booleanComparison: ResponseComparison;
  readonly scanner: Awaited<ReturnType<SQLScanner['scan']>> | null;
}

import type { AnalysisContext, BrowserAction, BrowserContextCookie, BrowserObservation, BrowserPageInspection, BrowserWorkflow,
  Credentials, ExecutionGuard, Persona, Project, ResponseExpectation, SessionVerification, TargetApplicationProfile, WorkflowPlanner } from '@agento/core';
export type { BrowserAction, Credentials, ResponseExpectation, SessionVerification } from '@agento/core';

export interface FormAuthentication {
  readonly loginUrl: string;
  readonly usernameSelector: string;
  readonly passwordSelector: string;
  readonly submitSelector: string;
  readonly response: ResponseExpectation;
  readonly successUrl?: string;
  readonly verification: (identity: Persona) => SessionVerification;
}
/** Raw state is adapter-private credential material. It must never enter core evidence. */
export interface BrowserState { readonly format: string; readonly version: number; readonly data: unknown }
export interface StoredSession {
  readonly binding: string;
  readonly sessionRef: string;
  readonly expiresAt: number;
  readonly state: BrowserState;
}
export interface SessionStore {
  load(binding: string): Promise<StoredSession | undefined>;
  save(session: StoredSession): Promise<void>;
  delete(binding: string): Promise<void>;
}
export interface NetworkRecord {
  readonly url: string;
  readonly method: string;
  readonly resourceType: string;
  readonly status: number | null;
  readonly blocked: boolean;
  readonly initiatingPage?: string;
  readonly timestamp?: string;
  /** Only the explicit safe response-header allowlist is retained. */
  readonly headers?: Readonly<Record<string, string>>;
  readonly blockedReason?: 'origin-scope' | 'policy-denied' | 'popup-unsupported' | 'worker-unsupported' | 'websocket-unsupported';
}
export interface BrowserSnapshot { readonly url: string; readonly screenshotPath?: string }
export interface BrowserSession {
  readCookies?(): Promise<readonly BrowserContextCookie[]>;
  replaceCookies?(cookies: readonly BrowserContextCookie[]): Promise<void>;
  perform(action: BrowserAction): Promise<void>;
  inspect(): Promise<BrowserPageInspection>;
  verify(verification: SessionVerification): Promise<boolean>;
  captureState(): Promise<BrowserState>;
  snapshot(): Promise<BrowserSnapshot>;
  close(): Promise<void>;
}
export interface BrowserRuntimeRequest {
  readonly executionGuard?: ExecutionGuard;
  readonly project: Project;
  readonly signal: AbortSignal;
  readonly timeoutMs: number;
  readonly state?: BrowserState;
  readonly assertUrl: (url: string) => string;
  readonly onNetwork: (record: NetworkRecord) => void;
  readonly screenshot?: { readonly directory: string; readonly maskSelectors: readonly string[] };
}
/** Replaceable adapter-local seam. Core never imports e2e or Playwright. */
export interface BrowserRuntime { start(request: BrowserRuntimeRequest): Promise<BrowserSession> }
export type GoalResolver = (context: AnalysisContext, workflow: BrowserWorkflow) => readonly BrowserAction[] | undefined;
export type BrowserDiagnosticCode = 'invalid-workflow' | 'scope-denied' | 'authentication-failed'
  | 'browser-failed' | 'timeout' | 'network-limit' | 'session-store-failed' | 'unable-to-proceed' | 'model-budget';
export interface BrowserDiagnostic { readonly code: BrowserDiagnosticCode; readonly message: string }
export interface WorkflowObservation extends BrowserObservation {
  readonly outcome: 'COMPLETED' | 'FAILED' | 'SKIPPED';
  readonly diagnostics: readonly BrowserDiagnostic[];
}
export interface TesterArmyE2EOptions {
  readonly executionGuard?: ExecutionGuard;
  readonly target?: TargetApplicationProfile;
  readonly workflowPlanner?: WorkflowPlanner;
  readonly maxWorkflowActions?: number;
  readonly resolveGoal?: GoalResolver;
  /** Compatibility shorthand for a FormLoginStrategy. */
  readonly authentication?: FormAuthentication;
  readonly credentials?: (identity: Persona, project: Project) => Promise<Credentials>;
  readonly runtime?: BrowserRuntime;
  readonly sessionStore?: SessionStore;
  readonly timeoutMs?: number;
  readonly sessionTtlMs?: number;
  readonly maxNetworkRecords?: number;
  /** Screenshots are off by default. Masks are trusted app-specific selectors. */
  readonly screenshot?: { readonly directory: string; readonly maskSelectors: readonly string[] };
}

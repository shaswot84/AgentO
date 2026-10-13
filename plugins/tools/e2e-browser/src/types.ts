import type { AnalysisContext, BrowserObservation, BrowserWorkflow, Identity, Project } from '@agento/core';

export interface ResponseExpectation {
  /** Absolute URL or path; an optional trailing * matches a path prefix. */
  readonly url: string;
  readonly method?: string;
  readonly status?: number;
}
/** Trusted backend recipes, never evaluated JavaScript, shell commands, or model prose. */
export type BrowserAction =
  | { readonly action: 'navigate'; readonly url: string; readonly response?: ResponseExpectation }
  | { readonly action: 'fill'; readonly selector: string; readonly value: string }
  | { readonly action: 'click'; readonly selector: string; readonly response?: ResponseExpectation }
  | { readonly action: 'wait-url'; readonly url: string }
  | { readonly action: 'wait-visible'; readonly selector: string };

export interface Credentials { readonly username: string; readonly password: string }
export interface SessionVerification {
  readonly url: string;
  /** Path in the authenticated JSON response, for example ['user', 'username']. */
  readonly identityPath: readonly string[];
  readonly expectedIdentity: string;
}
export interface FormAuthentication {
  readonly loginUrl: string;
  readonly usernameSelector: string;
  readonly passwordSelector: string;
  readonly submitSelector: string;
  readonly response: ResponseExpectation;
  readonly successUrl?: string;
  readonly verification: (identity: Identity) => SessionVerification;
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
  readonly blockedReason?: 'origin-scope' | 'popup-unsupported' | 'worker-unsupported' | 'websocket-unsupported';
}
export interface BrowserSnapshot { readonly url: string; readonly screenshotPath?: string }
export interface BrowserSession {
  perform(action: BrowserAction): Promise<void>;
  verify(verification: SessionVerification): Promise<boolean>;
  captureState(): Promise<BrowserState>;
  snapshot(): Promise<BrowserSnapshot>;
  close(): Promise<void>;
}
export interface BrowserRuntimeRequest {
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
  | 'browser-failed' | 'timeout' | 'network-limit' | 'session-store-failed';
export interface BrowserDiagnostic { readonly code: BrowserDiagnosticCode; readonly message: string }
export interface WorkflowObservation extends BrowserObservation {
  readonly outcome: 'COMPLETED' | 'FAILED' | 'SKIPPED';
  readonly diagnostics: readonly BrowserDiagnostic[];
}
export interface TesterArmyE2EOptions {
  readonly resolveGoal?: GoalResolver;
  readonly authentication?: FormAuthentication;
  readonly credentials?: (identity: Identity, project: Project) => Promise<Credentials>;
  readonly runtime?: BrowserRuntime;
  readonly sessionStore?: SessionStore;
  readonly timeoutMs?: number;
  readonly sessionTtlMs?: number;
  readonly maxNetworkRecords?: number;
  /** Screenshots are off by default. Masks are trusted app-specific selectors. */
  readonly screenshot?: { readonly directory: string; readonly maskSelectors: readonly string[] };
}

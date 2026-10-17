import type { BrowserAction, BrowserContextCookie, BrowserPageInspection, Persona, TargetApplicationProfile, WorkflowPlanner } from './browser.js';
import type { AnalysisContext, JsonValue } from './domain.js';
import type { BrowserObservation, BrowserWorkflow, BrowserWorkflowDriver } from './contracts.js';

export type WorkflowFailureCode = 'invalid-workflow' | 'scope-denied' | 'authentication-failed'
  | 'browser-failed' | 'timeout' | 'unable-to-proceed' | 'model-budget' | 'session-store-failed' | 'network-limit';
export class BrowserWorkflowFailure extends Error {
  constructor(readonly code: WorkflowFailureCode) { super(code); }
}
export interface BrowserNetworkObservation {
  readonly url: string; readonly method: string; readonly status: number | null; readonly blocked: boolean;
}
/** Trusted backend capability port; never passed to a model. */
export interface BrowserWorkflowSession {
  readonly signal: AbortSignal;
  readonly persona: Persona;
  inspect(): Promise<BrowserPageInspection>;
  perform(action: BrowserAction): Promise<void>;
  /** Resolves backend secrets only after external deterministic credential policy allows it. */
  fillCredential(selector: string, field: 'username' | 'password', guard?: { readonly stateId: string }): Promise<void>;
  assertUrl(url: string): string;
  network(): readonly BrowserNetworkObservation[];
  /** Optional trusted backend operations; raw values must never reach a model or public evidence. */
  readCookies?(): Promise<readonly BrowserContextCookie[]>;
  replaceCookies?(cookies: readonly BrowserContextCookie[]): Promise<void>;
}
export interface BrowserWorkflowRuntimeDriver extends BrowserWorkflowDriver {
  runWorkflow(context: AnalysisContext, workflow: BrowserWorkflow,
    execute: (session: BrowserWorkflowSession) => Promise<void>, target?: TargetApplicationProfile): Promise<BrowserExecutionObservation>;
}
export interface BrowserExecutionObservation extends BrowserObservation {
  readonly outcome: 'COMPLETED' | 'FAILED' | 'SKIPPED';
  readonly diagnostics: readonly { readonly code: string; readonly message: string }[];
}

/** Redacted application-derived fields are explicitly untrusted data. No selectors or SDK objects. */
export interface PageModel {
  readonly id: string;
  readonly trust: 'untrusted-application-data';
  readonly url: string;
  readonly origin: string | null;
  readonly title: string;
  readonly headings: readonly string[];
  readonly visibleTextSummary: string;
  readonly forms: readonly { readonly id: string; readonly fieldIds: readonly string[]; readonly submitElementIds: readonly string[] }[];
  readonly interactiveElements: readonly {
    readonly id: string; readonly role: 'link' | 'button' | 'input' | 'form'; readonly label: string;
    readonly text: string; readonly visible: boolean; readonly enabled: boolean; readonly inputType?: string;
  }[];
  readonly navigationCandidates: readonly { readonly id: string; readonly elementId?: string; readonly url: string; readonly label: string }[];
}
export type PlannedActionType = 'click' | 'fill' | 'submit' | 'navigate-within-scope' | 'inspect'
  | 'wait-for-state' | 'goal-complete' | 'unable-to-proceed';
/** Required nullable fields keep the schema portable across strict JSON-schema model APIs. */
export interface PlannedAction {
  readonly pageId: string;
  readonly actionType: PlannedActionType;
  readonly elementId: string | null;
  readonly navigationId: string | null;
  readonly inputRef: string | null;
  readonly confidence: number;
  readonly explanation: string | null;
  readonly expectedOutcome: string;
}
export interface WorkflowHistoryEntry {
  readonly pageId: string;
  readonly actionType: PlannedActionType | BrowserAction['action'];
  readonly elementId?: string;
  readonly outcome: 'completed' | 'failed' | 'rejected';
  readonly url: string;
  readonly code?: string;
}
export interface SemanticPlannerInput {
  readonly goal: string;
  readonly pageModel: PageModel;
  readonly history: readonly WorkflowHistoryEntry[];
  readonly target: { readonly id: string; readonly baseOrigins: readonly string[]; readonly workflowHints?: Readonly<Record<string, JsonValue>> };
  readonly persona: { readonly id: string; readonly label: string; readonly roles: readonly string[] };
  readonly signal: AbortSignal;
}
export interface SemanticWorkflowPlanner extends WorkflowPlanner<SemanticPlannerInput, PlannedAction> {}
/** Explicit trusted destination/field permissions; never inferred by the model. */
export interface CredentialPolicy {
  allows(request: { readonly persona: Persona; readonly field: 'username' | 'password'; readonly origin: string;
    readonly pageUrl: string; readonly element: PageModel['interactiveElements'][number] }): boolean;
}

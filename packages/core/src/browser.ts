import type { Identity, JsonValue } from './domain.js';
import type { BrowserWorkflow } from './contracts.js';

export interface ResponseExpectation {
  /** Absolute URL or path; a trailing * matches a path prefix. */
  readonly url: string;
  readonly method?: string;
  readonly status?: number;
}

/** Bounded browser instructions. No scripts or provider SDK objects. */
export type BrowserAction =
  | { readonly action: 'navigate'; readonly url: string; readonly response?: ResponseExpectation }
  | { readonly action: 'fill'; readonly selector: string; readonly value: string }
  | { readonly action: 'click' | 'submit'; readonly selector: string; readonly response?: ResponseExpectation }
  | { readonly action: 'wait-url'; readonly url: string }
  | { readonly action: 'wait-visible'; readonly selector: string };

export interface Persona extends Identity {
  /** Opaque backend lookup key, never inline credentials. */
  readonly credentialsRef?: string;
  readonly expectedRole?: string;
  readonly authenticationStrategyId?: string;
  readonly metadata?: Readonly<Record<string, JsonValue>>;
}

/** Private backend material; exclude from profiles, context, evidence and planner input. */
export interface Credentials { readonly username: string; readonly password: string }
export type SessionVerification = {
  readonly url: string;
  readonly expectedIdentity: string;
} & (
  | { readonly identityPath: readonly string[]; readonly role?: { readonly path: readonly string[]; readonly expected: string } }
  | { readonly identitySelector: string; readonly role?: { readonly selector: string; readonly expected: string } }
);

export type AuthenticationAction = BrowserAction
  | { readonly action: 'fill-credential'; readonly selector: string; readonly field: keyof Credentials };
export interface AuthenticationPreparation {
  readonly verification: SessionVerification;
  /** Omit for stored-session-only authentication. */
  readonly actions?: readonly AuthenticationAction[];
}
/** Trusted, declarative authentication boundary, independent of browser providers. */
export interface AuthenticationStrategy {
  readonly id: string;
  prepare(persona: Persona): AuthenticationPreparation;
}

export interface TargetApplicationProfile {
  readonly id: string;
  /** Explicit application origins. No wildcard or inferred hosts. */
  readonly baseOrigins: readonly string[];
  readonly personas?: readonly Persona[];
  readonly authentication?: readonly AuthenticationStrategy[];
  readonly defaultAuthenticationStrategyId?: string;
  readonly workflowHints?: Readonly<Record<string, JsonValue>>;
  readonly scope?: { readonly allowedOrigins: readonly string[] };
  readonly metadata?: Readonly<Record<string, JsonValue>>;
}

export interface BrowserPageInspection {
  readonly url: string;
  /** Opaque native state guard; kept out of model input and public PageModel. */
  readonly stateId?: string;
  readonly title?: string;
  readonly headings?: readonly string[];
  readonly visibleTextSummary?: string;
  /** Visible controls only; field values and complete HTML are excluded. */
  readonly controls: readonly {
    readonly selector: string;
    readonly kind: 'link' | 'button' | 'input' | 'form';
    readonly label: string;
    readonly href?: string;
    readonly enabled?: boolean;
    readonly inputType?: string;
    readonly formSelector?: string;
  }[];
}
export interface WorkflowPlannerInput {
  readonly target: TargetApplicationProfile;
  readonly persona: Persona;
  readonly workflow: BrowserWorkflow;
  readonly page: BrowserPageInspection;
  readonly executedActions: number;
}
export type WorkflowDecision =
  | { readonly outcome: 'action'; readonly action: BrowserAction }
  | { readonly outcome: 'complete' | 'unsupported' };
/** Inspect, choose one bounded action, execute, then inspect again. */
export interface WorkflowPlanner<Input = WorkflowPlannerInput, Decision = WorkflowDecision> {
  next(input: Input): Promise<Decision>;
}

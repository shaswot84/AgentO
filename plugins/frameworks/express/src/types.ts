import type { FrameworkAnalysis, SourceLocation } from '@agento/core';

export interface ExpressDiagnostic {
  readonly code: 'repository-unavailable' | 'read-failed' | 'parse-failed' | 'limit-reached'
    | 'unresolved-route' | 'unresolved-handler' | 'router-cycle' | 'conditional-registration';
  readonly message: string;
  readonly source: SourceLocation;
}

/** Partial syntax observations remain useful, but diagnostics must accompany them. */
export interface ExpressAnalysis extends FrameworkAnalysis {
  readonly diagnostics: readonly ExpressDiagnostic[];
}

export interface ExpressAdapterOptions {
  /** Injectable timestamp for repeatable snapshots. */
  readonly now?: () => string;
}

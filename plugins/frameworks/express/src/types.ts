import type { EndpointDiscoveryDiagnostic, EndpointDiscoveryProvider, FrameworkAnalysis, SourceLocation } from '@agento/core';

export interface ExpressDiagnostic {
  readonly code: EndpointDiscoveryDiagnostic['code'] | 'unvalidated-endpoint' | 'repository-unavailable' | 'read-failed' | 'parse-failed' | 'limit-reached'
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
  readonly endpointDiscoveryProvider?: EndpointDiscoveryProvider;
  readonly noir?: NoirOptions;
  readonly excludePaths?: readonly string[];
}

export interface NoirOptions {
  readonly executable?: string;
  readonly now?: () => string;
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
  /** Additional repository-relative directories to omit, including their children. */
  readonly excludePaths?: readonly string[];
}

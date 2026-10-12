import type { FrameworkAnalysis, SourceLocation, StaticAnalysis } from '@agento/core';

export type DiagnosticCode = 'mode-not-code-aware' | 'repository-unavailable' | 'unsupported-language'
  | 'read-failed' | 'parse-failed' | 'limit-reached' | 'tool-not-found' | 'tool-failed'
  | 'timeout' | 'output-limit' | 'invalid-output' | 'invalid-match' | 'unknown-rule' | 'scan-error';
export interface SemgrepDiagnostic {
  readonly code: DiagnosticCode;
  readonly message: string;
  readonly source?: SourceLocation;
}
export interface SemgrepAnalysis extends StaticAnalysis {
  readonly status: 'completed' | 'partial' | 'failed' | 'skipped';
  readonly diagnostics: readonly SemgrepDiagnostic[];
}
/** Adapter-local process boundary, never part of the core analysis context. */
export interface SemgrepInvocation {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
}
export interface SemgrepProcessResult {
  readonly exitCode: number;
  readonly stdout: string;
}
export interface SemgrepAdapterOptions {
  /** Trusted backend configuration, not target-provided executable or shell text. */
  readonly executable?: string;
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
  readonly now?: () => string;
  /** Precomputed normalized framework context; the adapter never invokes other providers. */
  readonly frameworkAnalysis?: FrameworkAnalysis;
  readonly runner?: (invocation: SemgrepInvocation) => Promise<SemgrepProcessResult>;
}

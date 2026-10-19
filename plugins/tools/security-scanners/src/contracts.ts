import type { AnalysisContext, SecurityTestPlan } from '@agento/core';
import type { SecurityScannerRequest } from '@agento/runtime';

export type ScannerErrorCode = 'invalid-input' | 'not-installed' | 'not-configured' | 'disabled'
  | 'timeout' | 'cancelled' | 'output-limit' | 'invalid-output' | 'tool-failed'
  | 'scope-denied' | 'request-limit' | 'transport-failed' | 'incomplete-output';
export class ScannerError extends Error {
  constructor(readonly code: ScannerErrorCode) { super(code); this.name = 'ScannerError'; }
}
/** Private process boundary. Never store this input or its raw output in public evidence. */
export interface ProcessInput {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: Readonly<Record<string, string>>;
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  readonly signal: AbortSignal;
}
export interface ProcessOutput { readonly stdout: string; readonly stderr: string; readonly exitCode: number }
export type ProcessRunner = (input: ProcessInput) => Promise<ProcessOutput>;
export interface ScannerOptions {
  readonly executable?: string;
  readonly enabled?: boolean;
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
  /** Trusted host/test seam; it must honor cancellation and process limits. */
  readonly runner?: ProcessRunner;
  /** Resolve private input bindings on the host. Never interpret planner prose as CLI options. */
  readonly resolveInput?: (context: AnalysisContext, plan: SecurityTestPlan) => Promise<SecurityScannerRequest>;
}
export interface NucleiOptions extends ScannerOptions {
  /** Trusted local HTTP templates only. No remote templates, workflows, code or headless engines. */
  readonly templates?: readonly string[];
}
/** Public, projected scanner claims. These are observations, never vulnerability verdicts. */
export interface ScannerObservation {
  readonly ruleDigest: string;
  readonly cweIds: readonly string[];
  readonly reportedSeverity: 'info' | 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  readonly reportedConfidence: 'low' | 'medium' | 'high' | 'unknown';
  readonly technique: 'error' | 'boolean' | 'time' | null;
  readonly dbmsFingerprint: 'SQLite' | 'PostgreSQL' | 'MySQL' | 'SQLServer' | 'Oracle' | null;
}

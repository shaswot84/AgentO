/** Trusted backend gate. Implementations must throw before an unauthorized effect. */
export interface ExecutionGuard {
  readonly signal?: AbortSignal;
  assertActive(): void;
  /** Called once immediately before each outgoing exchange, including browser redirect hops. */
  assertRequest(request: { readonly url: string; readonly method: string }): void;
  /** Validate a redirect without sending it or consuming another request allowance. */
  assertRedirect(from: string, destination: string): void;
}

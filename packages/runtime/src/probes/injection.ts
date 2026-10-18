import type { AuthSession, HttpRequest, RequestExecutor } from '../contracts.js';
import { RuntimeError } from '../safety.js';
import type { InjectionContext, ScannerRequest } from './contracts.js';
import { assertActive, request, withIdentity } from './shared.js';

export function withInjectionExecutor<T>(context: InjectionContext,
  execute: (executor: RequestExecutor, session?: AuthSession) => Promise<T>): Promise<T> {
  const guard = (executor: RequestExecutor): RequestExecutor => ({ execute: async input => {
    assertActive(context);
    if (input.signal?.aborted) throw new RuntimeError('cancelled');
    const response = await executor.execute(input);
    assertActive(context); return response;
  } });
  if (context.identity) {
    if (context.identity.authentication === 'anonymous') throw new RuntimeError('invalid-request');
    return withIdentity(context, context.identity, session => execute(guard(session.http), session));
  }
  return execute(guard(context.capabilities.get('request-executor')));
}
function scannerRequest(context: InjectionContext, executor: RequestExecutor,
  canary: string): { input: ScannerRequest; revoke(): void } {
  let remaining = 8;
  // Adapters receive a bounded capability. Retaining it after scan() returns is forbidden.
  let active = true;
  const controller = new AbortController();
  const scoped: RequestExecutor = Object.freeze({ execute: async (input: HttpRequest) => {
    assertActive(context);
    if (!active) throw new RuntimeError('session-closed');
    if (remaining-- <= 0) throw new RuntimeError('record-limit');
    const prepared = request(context, input, true);
    if (new URL(prepared.url).origin !== new URL(context.request.url).origin
      || new URL(prepared.url).pathname !== new URL(context.request.url).pathname
      || prepared.method !== context.request.method) throw new RuntimeError('scope-denied');
    const response = await executor.execute({ ...prepared, signal: prepared.signal
      ? AbortSignal.any([controller.signal, prepared.signal]) : controller.signal });
    if (!active) throw new RuntimeError('session-closed');
    return response;
  } });
  const input: ScannerRequest = { project: structuredClone(context.project), request: { ...context.request, headers: { ...context.request.headers } },
    parameter: { ...context.parameter }, canary, executor: scoped, maxRequests: 8,
    ...(context.signal ? { signal: context.signal } : {}) };
  return { input, revoke: () => { active = false; controller.abort(); } };
}
export async function scan<T>(context: InjectionContext, executor: RequestExecutor, canary: string,
  invoke: (input: ScannerRequest) => Promise<T>): Promise<T> {
  const capability = scannerRequest(context, executor, canary);
  try { const result = await invoke(capability.input); assertActive(context); return result; }
  finally { capability.revoke(); }
}

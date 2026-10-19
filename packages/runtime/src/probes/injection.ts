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
  const maximum = context.maxScannerRequests ?? 8;
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 512) throw new RuntimeError('invalid-request');
  let remaining = maximum;
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
    if (context.parameter.location === 'query') {
      const before = new URL(context.request.url), after = new URL(prepared.url);
      if (after.searchParams.getAll(context.parameter.name).length !== 1 || prepared.body !== context.request.body) throw new RuntimeError('scope-denied');
      before.searchParams.delete(context.parameter.name); after.searchParams.delete(context.parameter.name);
      before.searchParams.sort(); after.searchParams.sort();
      if (before.search !== after.search) throw new RuntimeError('scope-denied');
    }
    const response = await executor.execute({ ...prepared, signal: prepared.signal
      ? AbortSignal.any([controller.signal, prepared.signal]) : controller.signal });
    if (!active) throw new RuntimeError('session-closed');
    return response;
  } });
  const input: ScannerRequest = { project: structuredClone(context.project), request: { ...context.request, headers: { ...context.request.headers } },
    parameter: { ...context.parameter }, canary, executor: scoped, maxRequests: maximum,
    ...(context.signal ? { signal: context.signal } : {}) };
  return { input, revoke: () => { active = false; controller.abort(); } };
}
export async function scan<T>(context: InjectionContext, executor: RequestExecutor, canary: string,
  invoke: (input: ScannerRequest) => Promise<T>): Promise<T> {
  const capability = scannerRequest(context, executor, canary);
  try { const result = await invoke(capability.input); assertActive(context); return result; }
  finally { capability.revoke(); }
}

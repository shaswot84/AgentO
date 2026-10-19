import type { ExecutionGuard } from '@agento/core';
import { CapabilityRegistry } from '@agento/runtime';
import type { AuthenticationManager, CapabilityCatalog, HttpRequest, RequestExecutor, ScannerRequest, SQLScanner, XSSScanner } from '@agento/runtime';
import type { CapabilityResolution } from '@agento/capability-registry';
import { PolicyError } from './contracts.js';

export interface BindingHost {
  readonly signal: AbortSignal;
  readonly allowedOrigins: readonly string[];
  guardFor(toolId: string): ExecutionGuard;
  tool<T>(toolId: string, execute: () => Promise<T>): Promise<T>;
}

export function bindCapabilities(resolution: CapabilityResolution, host: BindingHost) {
  const bound = new CapabilityRegistry(), cleanup: (() => Promise<void>)[] = [];
  const reads: Record<string, readonly string[]> = { 'response-collector': ['collect', 'evidence'], 'header-analyzer': ['analyze'],
    'cookie-analyzer': ['analyze'], 'cookie-inspector': ['inspect'], 'response-comparator': ['compare'] };
  for (const selection of resolution.report.selections) {
    if (!selection.selectedToolId) continue;
    const id = selection.capability as keyof CapabilityCatalog, toolId = selection.selectedToolId;
    const source = resolution.capabilities!.get(id), guard = host.guardFor(toolId);
    let port: unknown;
    if (id === 'request-executor') port = executor(source as RequestExecutor, guard, host.signal);
    else if (id === 'authentication-manager' || id === 'browser-controller') {
      const provider = source as { withGuard?: (guard: ExecutionGuard) => unknown };
      if (typeof provider.withGuard !== 'function') throw new PolicyError('guard-unsupported');
      try { port = provider.withGuard(guard); } catch { throw new PolicyError('guard-unsupported'); }
      if (!port || port === source) throw new PolicyError('guard-unsupported');
      if (id === 'authentication-manager') {
        const manager = port as AuthenticationManager;
        if (!manager.close) throw new PolicyError('guard-unsupported');
        cleanup.push(() => manager.close!());
      }
      port = guardedMethods(port, guard, id === 'authentication-manager' ? ['establishSession'] : ['withSession']);
    } else if (id === 'xss-scanner' || id === 'sql-scanner') {
      const scanner = source as XSSScanner | SQLScanner;
      port = Object.freeze({ scan: (input: ScannerRequest) => host.tool(toolId, async () => {
        guard.assertActive();
        // The executor is already guarded. The ambient tool binding adds this scanner's restrictions.
        return scanner.scan({ ...input, project: { ...input.project, allowedOrigins: [...host.allowedOrigins] },
          signal: input.signal ? AbortSignal.any([input.signal, host.signal]) : host.signal });
      }) });
    } else if (Object.hasOwn(reads, id)) port = guardedMethods(source, guard, reads[id]!);
    else throw new PolicyError('guard-unsupported');
    bound.register(id, port as CapabilityCatalog[typeof id]);
  }
  return { capabilities: bound, close: async () => { await Promise.all(cleanup.map(close => close())); } };
}

function executor(source: RequestExecutor, guard: ExecutionGuard, signal: AbortSignal): RequestExecutor {
  return Object.freeze({ execute: async (input: HttpRequest) => {
    const request = { ...input, ...(input.headers ? { headers: { ...input.headers } } : {}) };
    guard.assertActive();
    if (request.signal?.aborted) throw new PolicyError('cancelled');
    guard.assertRequest({ url: request.url, method: request.method ?? 'GET' });
    const response = await source.execute({ ...request, signal: request.signal ? AbortSignal.any([request.signal, signal]) : signal });
    guard.assertActive();
    if (response.url !== request.url) guard.assertRedirect(request.url, response.url);
    if (response.status >= 300 && response.status < 400) {
      for (const [key, values] of Object.entries(response.headers)) if (key.toLowerCase() === 'location') {
        for (const value of values) guard.assertRedirect(request.url, value);
      }
    }
    return response;
  } });
}

function guardedMethods(source: unknown, guard: ExecutionGuard, methods: readonly string[]): unknown {
  const target = source as Record<string, (...args: unknown[]) => unknown>;
  return Object.freeze(Object.fromEntries(methods.map(name => {
    if (typeof target[name] !== 'function') throw new PolicyError('guard-unsupported');
    return [name, (...args: unknown[]) => { guard.assertActive(); return target[name]!.apply(source, args); }];
  })));
}

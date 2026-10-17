import { vi } from 'vitest';
import type { AnalysisContext, BrowserContextCookie, BrowserWorkflowRuntimeDriver, BrowserWorkflowSession } from '@agento/core';
import type { HttpResponse, TestIdentity, TransportResponse } from '../src/index.js';
import { NormalizedResponseCollector } from '../src/index.js';

export const origin = 'http://127.0.0.1:3000';
export const identities: readonly TestIdentity[] = [
  { id: 'alice', label: 'Alice', roles: ['customer'], authentication: 'session-cookie' },
  { id: 'bob', label: 'Bob', roles: ['customer'], authentication: 'session-cookie' },
  { id: 'admin', label: 'Admin', roles: ['admin'], authentication: 'session-cookie' },
];
export const context: AnalysisContext = { project: { id: 'runtime-test', name: 'Runtime', mode: 'black-box',
  baseUrl: origin, allowedOrigins: [origin], languages: [] }, identities, components: [], endpoints: [], resources: [], signals: [], evidence: [] };
export const raw = (headers: Record<string, readonly string[]> = {}, body = 'hello'): TransportResponse => ({
  status: 200, headers, body: Buffer.from(body), truncated: false, firstByteMs: 2,
});
export function response(headers: Record<string, readonly string[]> = {}, url = `${origin}/account/login`): HttpResponse {
  return new NormalizedResponseCollector().collect({ url, method: 'GET' }, raw(headers),
    { startedAt: new Date().toISOString(), firstByteMs: 2, durationMs: 3 });
}
export function fakeDriver() {
  const cookies = new Map<string, BrowserContextCookie[]>();
  const ports: BrowserWorkflowSession[] = [];
  const perform = vi.fn(async () => undefined);
  const driver: BrowserWorkflowRuntimeDriver = {
    id: 'fake-browser', capabilities: ['browser-workflow'],
    observe: async () => ({ endpoints: [], resources: [], signals: [], evidence: [] }),
    execute: async () => { throw new Error('unused'); },
    runWorkflow: vi.fn<BrowserWorkflowRuntimeDriver['runWorkflow']>(async (_context, workflow, execute) => {
      const identityId = workflow.identityId;
      cookies.set(identityId, cookies.get(identityId) ?? [{ name: 'sid', value: `private-${identityId}`, domain: '127.0.0.1', path: '/',
        expires: -1, httpOnly: true, secure: false, sameSite: 'Lax' }]);
      const port: BrowserWorkflowSession = { signal: new AbortController().signal, persona: identities.find(item => item.id === identityId)!,
        perform, fillCredential: async () => undefined, assertUrl: value => new URL(value, origin).href,
        inspect: async () => ({ url: origin, controls: [] }),
        network: () => [{ url: `${origin}/api/me?token=private-${identityId}`, method: 'GET', status: 200, blocked: false }],
        readCookies: async () => cookies.get(identityId)!, replaceCookies: async incoming => { cookies.set(identityId, [...incoming]); } };
      ports.push(port); await execute(port);
      return { outcome: 'COMPLETED', diagnostics: [], endpoints: [], resources: [], signals: [], evidence: [] };
    }),
  };
  return { driver, cookies, ports, perform };
}

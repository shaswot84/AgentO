import { vi } from 'vitest';
import type { AnalysisContext, Identity, SecurityTestPlan } from '@agento/core';
import type { BrowserAction, BrowserRuntime, BrowserRuntimeRequest, BrowserState } from '../src/types.js';

export const alice: Identity = { id: 'alice', label: 'Alice', roles: ['customer'], authentication: 'session-cookie' };
export const anonymous: Identity = { id: 'anonymous', label: 'Anonymous', roles: [], authentication: 'anonymous' };
export const context: AnalysisContext = {
  project: { id: 'demo', name: 'Demo', mode: 'black-box', baseUrl: 'http://127.0.0.1:3000', allowedOrigins: ['http://127.0.0.1:3000'], languages: [] },
  components: [], endpoints: [], identities: [alice, { ...alice, id: 'bob', label: 'Bob' }, { ...alice, id: 'admin', label: 'Admin', roles: ['admin'] }, anonymous],
  resources: [], signals: [], evidence: [],
};
export const state: BrowserState = { format: 'playwright-storage-state', version: 1,
  data: { cookies: [{ domain: '127.0.0.1', name: 'auth', value: 'private-session-cookie' }], origins: [] } };
export const workflow = { id: 'orders', identityId: 'alice', goal: 'open newest order' };
export const plan: SecurityTestPlan = { id: 'plan', hypothesisId: 'hypothesis', cweId: 'CWE-639', executor: 'browser',
  targetUrl: context.project.baseUrl, requiredCapabilities: ['browser-workflow'], identityIds: ['anonymous'], risk: 'passive',
  steps: [{ id: 'open', action: 'navigate', parameters: { url: '/orders' }, expectedObservation: 'Page loaded' }] };

export function fakeRuntime(options: { verify?: () => boolean; perform?: (action: BrowserAction, request: BrowserRuntimeRequest) => Promise<void> } = {}) {
  const sessions: { perform: ReturnType<typeof vi.fn>; close: ReturnType<typeof vi.fn>; verify: ReturnType<typeof vi.fn> }[] = [];
  const start = vi.fn(async (request: BrowserRuntimeRequest) => {
    const perform = vi.fn(async (action: BrowserAction) => {
      if (options.perform) await options.perform(action, request);
      else if (action.action === 'navigate') request.onNetwork({ url: request.assertUrl(action.url), method: 'GET', status: 200, resourceType: 'document', blocked: false });
    });
    const session = { perform, verify: vi.fn(async () => options.verify?.() ?? true),
      captureState: async () => state, snapshot: async () => ({ url: 'http://127.0.0.1:3000/orders' }), close: vi.fn(async () => undefined) };
    sessions.push(session); return session;
  });
  return { start, sessions } satisfies BrowserRuntime & { sessions: typeof sessions };
}

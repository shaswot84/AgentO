import { vi } from 'vitest';
import { CapabilityRegistry } from '@agento/capability-registry';
import { NormalizedResponseCollector } from '@agento/runtime';
import type { CapabilityCatalog, HttpRequest, RequestExecutor } from '@agento/runtime';
import type { PolicyConfiguration, PolicyRequest } from '../src/index.js';

export const origin = 'https://shop.test';
export const collector = new NormalizedResponseCollector();
export function response(input: HttpRequest, status = 200, headers: Record<string, string[]> = {}) {
  return collector.collect({ url: input.url, method: input.method ?? 'GET' }, {
    status, headers, body: Buffer.from('PRIVATE_BODY'), truncated: false, firstByteMs: 1,
  }, { startedAt: '2026-10-19T00:00:00Z', firstByteMs: 1, durationMs: 2 });
}
export function request(overrides: Partial<PolicyRequest['plan']> = {}): PolicyRequest {
  return { project: { id: 'test-project', baseUrl: origin, allowedOrigins: [origin] },
    plan: { id: 'test-plan', risk: 'passive', targetUrl: `${origin}/search?secret=PRIVATE_QUERY`,
      requiredCapabilities: ['request-executor'], ...overrides } };
}
export function config(overrides: Partial<PolicyConfiguration> = {}): PolicyConfiguration {
  return { allowedOrigins: [origin], tools: { runtime: {} }, approval: { risks: [], severities: [] }, ...overrides };
}
export async function setup(ports: Partial<CapabilityCatalog> = {}, input = request()) {
  const send = vi.fn<RequestExecutor['execute']>(async input => response(input));
  const registry = new CapabilityRegistry();
  const capabilities = { 'request-executor': { execute: send }, ...ports };
  registry.register({ metadata: { id: 'runtime', capabilities: Object.keys(capabilities) as (keyof CapabilityCatalog)[],
    supportedCwes: 'all', protocols: ['http', 'https'], risk: 'passive' }, capabilities });
  const resolution = await registry.resolvePlan({ ...input.plan, cweId: 'CWE-89' });
  return { send, registry, resolution, input };
}

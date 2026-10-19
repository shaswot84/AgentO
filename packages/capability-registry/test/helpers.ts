import type { CapabilityCatalog, RequestExecutor } from '@agento/runtime';
import { AuthorizationProbe, CookieSecurityProbe, CrossOriginProbe, NormalizedCookieAnalyzer,
  NormalizedHeaderAnalyzer, NormalizedResponseCollector, NormalizedResponseComparator, ProbeRegistry,
  SQLInjectionProbe, XSSProbe } from '@agento/runtime';
import { vi } from 'vitest';
import { CapabilityRegistry, type SelectionRequest, type ToolMetadata, type ToolRegistration } from '../src/index.js';

export const targetUrl = 'https://shop.test/search?q=private-input';
export const request: SelectionRequest = { cweId: 'CWE-89', targetUrl,
  requiredCapabilities: ['sql-scanner'], risk: 'active' };
export const scanner = () => ({ scan: vi.fn(async () => ({ technique: 'boolean' as const,
  dbmsFingerprint: null, observedDifference: false })) });
export function tool(id: string, overrides: Partial<ToolMetadata> = {}, options: Partial<ToolRegistration> = {}): ToolRegistration {
  return { metadata: { id, capabilities: ['sql-scanner'], supportedCwes: ['CWE-89'],
    protocols: ['http', 'https'], risk: 'active', ...overrides }, capabilities: { 'sql-scanner': scanner() }, ...options };
}
export const probes = () => new ProbeRegistry().register('authorization', new AuthorizationProbe())
  .register('cookie-security', new CookieSecurityProbe()).register('cross-origin', new CrossOriginProbe())
  .register('xss', new XSSProbe()).register('sql-injection', new SQLInjectionProbe());
export const collector = new NormalizedResponseCollector();
export function fixtureResponse(url = targetUrl, fixed = true) {
  return collector.collect({ url, method: 'GET' }, { status: 200,
    headers: { 'set-cookie': [`sid=PRIVATE_COOKIE; Path=/;${fixed ? ' HttpOnly; Secure;' : ''} SameSite=Lax`] },
    body: Buffer.from('PRIVATE_RESPONSE_BODY'), truncated: false, firstByteMs: 1 },
  { startedAt: '2026-10-19T00:00:00Z', firstByteMs: 1, durationMs: 2 });
}
export function runtime(registry = new CapabilityRegistry({ probes: probes() })) {
  const execute = vi.fn<RequestExecutor['execute']>(async input => fixtureResponse(input.url));
  const ports: Partial<CapabilityCatalog> = { 'request-executor': { execute }, 'response-collector': collector,
    'response-comparator': new NormalizedResponseComparator(), 'header-analyzer': new NormalizedHeaderAnalyzer(),
    'cookie-analyzer': new NormalizedCookieAnalyzer(),
    'authentication-manager': { establishSession: vi.fn(async () => { throw new Error('Session must not start during selection'); }) },
    'cookie-inspector': { inspect: vi.fn(async () => []) },
    'browser-controller': { withSession: vi.fn(async () => { throw new Error('Browser must not start during selection'); }) } };
  registry.register({ metadata: { id: 'runtime', capabilities: Object.keys(ports) as (keyof CapabilityCatalog)[],
    supportedCwes: 'all', protocols: ['http', 'https'], risk: 'passive' }, capabilities: ports });
  return { registry, ports, execute };
}

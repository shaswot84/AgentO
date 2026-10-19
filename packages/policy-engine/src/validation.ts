import type { PolicyConfiguration, ToolPolicy } from './contracts.js';

export const severities = ['info', 'low', 'medium', 'high', 'critical'] as const;
export const risks = ['passive', 'active'] as const;
export function identifier(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 160 && /^[a-zA-Z0-9][a-zA-Z0-9_.:-]*$/.test(value);
}
export function parseUrl(value: string, base?: string): URL {
  if (typeof value !== 'string' || !value || value.length > 16_384 || /[\u0000-\u0020\\]/.test(value)) throw new Error();
  const url = new URL(value, base);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hostname.includes('*') || url.hostname.endsWith('.')) throw new Error();
  return url;
}
export function origins(values: readonly string[]): readonly string[] {
  if (!Array.isArray(values) || !values.length || values.length > 128) throw new Error();
  return [...new Set(values.map(value => {
    const url = parseUrl(value);
    if (url.pathname !== '/' || url.search || url.hash) throw new Error();
    return url.origin;
  }))].sort();
}
export function methods(values: readonly string[]): readonly string[] {
  const supported = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'];
  if (!Array.isArray(values) || !values.length || !values.every(value => supported.includes(value))) throw new Error();
  return [...new Set(values)].sort();
}
export function limit(value: number, maximum = 100_000): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new Error();
  return value;
}
export function freeze<T>(value: T): T {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}
export function configuration(input: PolicyConfiguration) {
  try {
    const allowedOrigins = origins(input.allowedOrigins), allowedMethods = methods(input.allowedMethods ?? ['GET', 'HEAD', 'OPTIONS']);
    if (!input.tools || typeof input.tools !== 'object' || Array.isArray(input.tools)
      || Object.keys(input.tools).length > 128 || !risks.includes(input.maxRisk ?? 'active')) throw new Error();
    const tools: Record<string, ToolPolicy> = Object.create(null);
    for (const [id, rule] of Object.entries(input.tools)) {
      if (!identifier(id) || !rule || !risks.includes(rule.maxRisk ?? 'active')
        || rule.capabilities !== undefined && (!Array.isArray(rule.capabilities) || !rule.capabilities.every(identifier))) throw new Error();
      tools[id] = { ...(rule.allowedOrigins ? { allowedOrigins: origins(rule.allowedOrigins) } : {}),
        ...(rule.allowedMethods ? { allowedMethods: methods(rule.allowedMethods) } : {}),
        ...(rule.capabilities ? { capabilities: [...rule.capabilities] } : {}), maxRisk: rule.maxRisk ?? 'active',
        maxRequests: limit(rule.maxRequests ?? 1000) };
    }
    const approval = input.approval ?? { risks: ['active'] };
    if (!Array.isArray(approval.risks) || !approval.risks.every(value => risks.includes(value))
      || approval.severities !== undefined && (!Array.isArray(approval.severities) || !approval.severities.every(value => severities.includes(value)))) throw new Error();
    return freeze({ allowedOrigins, allowedMethods, tools, maxRisk: input.maxRisk ?? 'active',
      rateLimit: { maxRequests: limit(input.rateLimit?.maxRequests ?? 60), windowMs: limit(input.rateLimit?.windowMs ?? 60_000, 3_600_000) },
      maxRequestsPerExecution: limit(input.maxRequestsPerExecution ?? 100),
      executionTtlMs: limit(input.executionTtlMs ?? 300_000, 3_600_000),
      approval: { risks: [...approval.risks], severities: [...(approval.severities ?? ['high', 'critical'])], ttlMs: limit(approval.ttlMs ?? 300_000, 3_600_000) },
      maxAuditRecords: limit(input.maxAuditRecords ?? 10_000) });
  } catch { throw new Error('Invalid policy configuration'); }
}

import { createHash } from 'node:crypto';
import type { HttpResponseEvidence } from '@agento/runtime';
import type { CWEVerdict, EvaluationScope } from './contracts.js';

export function freeze<T>(value: T): T {
  if (value && typeof value === 'object') {
    for (const nested of Object.values(value)) freeze(nested);
    Object.freeze(value);
  }
  return value;
}
export function identifier(...parts: unknown[]): string {
  return createHash('sha256').update(JSON.stringify(parts)).digest('hex');
}
export function url(value: string): URL {
  const parsed = new URL(value);
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hash) {
    throw new Error('Invalid rule target');
  }
  return parsed;
}
/** Query values are private inputs, not endpoint identity. Parameter binding is checked separately. */
export function sameTarget(response: HttpResponseEvidence, scope: EvaluationScope): boolean {
  try {
    const observed = url(response.url), target = url(scope.targetUrl);
    // Match ordinary route templates by segment, never by a permissive regex supplied by a provider.
    const actual = observed.pathname.split('/'), expected = target.pathname.split('/');
    return observed.origin === target.origin && response.method === scope.method
      && actual.length === expected.length && expected.every((segment, index) =>
        /^:[A-Za-z_][A-Za-z0-9_]*$/.test(segment) ? !!actual[index] : segment === actual[index]);
  } catch { return false; }
}
export function sameExchangeTarget(a: HttpResponseEvidence, b: HttpResponseEvidence): boolean {
  try {
    const left = url(a.url), right = url(b.url);
    return left.origin === right.origin && left.pathname === right.pathname && a.method === b.method;
  } catch { return false; }
}
export function successful(response: HttpResponseEvidence): boolean { return response.status >= 200 && response.status < 300; }
export function complete(response: HttpResponseEvidence): boolean { return !response.body.truncated; }
export type Decision = Pick<CWEVerdict, 'status' | 'summary'> & { readonly limitations?: readonly string[] };
export const unknown = (summary: string, ...limitations: string[]): Decision => ({ status: 'NOT_REPRODUCED', summary, limitations });
export const confirmed = (summary: string): Decision => ({ status: 'CONFIRMED', summary });
export const rejected = (summary: string): Decision => ({ status: 'REJECTED', summary });

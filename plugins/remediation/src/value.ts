import { createHash } from 'node:crypto';
import { RemediationError } from './contracts.js';

export const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(',')}}`;
}
/** Reject executable objects, accessors, cycles, and oversized host input. */
export function copy<T>(value: T, depth = 0, seen = new Set<object>(), budget = { nodes: 0 }): T {
  if (++budget.nodes > 100_000 || depth > 32 || typeof value === 'string' && value.length > 1_048_576) throw new RemediationError('patch-limit');
  if (value === null || typeof value === 'string' || typeof value === 'boolean'
    || typeof value === 'number' && Number.isFinite(value)) return value;
  if (!value || typeof value !== 'object' || seen.has(value)
    || !Array.isArray(value) && ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Object.getOwnPropertySymbols(value).length) throw new RemediationError('invalid-input');
  seen.add(value);
  try {
    const result: Record<string, unknown> = Object.create(null);
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
      if (Array.isArray(value) && key === 'length') continue;
      if (!descriptor.enumerable || !('value' in descriptor) || ['__proto__', 'constructor', 'prototype'].includes(key)
        || Array.isArray(value) && !/^(0|[1-9]\d*)$/.test(key)) throw new RemediationError('invalid-input');
      result[key] = copy(descriptor.value, depth + 1, seen, budget);
    }
    if (!Array.isArray(value)) return result as T;
    if (Object.keys(result).length !== value.length) throw new RemediationError('invalid-input');
    return Array.from({ length: value.length }, (_, index) => result[String(index)]) as T;
  } finally { seen.delete(value); }
}
export function freeze<T>(value: T): T {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
export function safePath(value: unknown): value is string {
  return typeof value === 'string' && /^(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_.-]+\.(?:ts|js)$/.test(value)
    && value.split('/').every(part => part !== '.' && part !== '..' && part !== '.git');
}
export function strings(value: unknown): asserts value is readonly string[] {
  if (!Array.isArray(value) || !value.length || value.length > 1000
    || !value.every(item => typeof item === 'string' && item.length > 0 && item.length < 1024)
    || new Set(value).size !== value.length) throw new RemediationError('invalid-input');
}

import { createHash } from 'node:crypto';
import type { Evidence } from '@agento/core';
import { verifyEvidenceBundle, type StoredEvidence } from '@agento/evidence';
import { ReportingError } from './contracts.js';

/** Copy plain JSON without invoking getters, retaining provider instances, or accepting cycles. */
export function copy<T>(value: T, depth = 0, seen = new Set<object>(), budget = { nodes: 0 }): T {
  if (++budget.nodes > 500_000 || depth > 40) throw new ReportingError('report-limit');
  if (typeof value === 'string' && value.length > 16_777_216) throw new ReportingError('report-limit');
  if (value === null || typeof value === 'string' || typeof value === 'boolean'
    || typeof value === 'number' && Number.isFinite(value)) return value;
  if (!value || typeof value !== 'object' || seen.has(value)
    || !Array.isArray(value) && ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Object.getOwnPropertySymbols(value).length) throw new ReportingError('invalid-input');
  seen.add(value);
  try {
    const result: Record<string, unknown> = Object.create(null);
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
      if (Array.isArray(value) && key === 'length') continue;
      if (!descriptor.enumerable || !('value' in descriptor) || ['__proto__', 'constructor', 'prototype'].includes(key)
        || Array.isArray(value) && !/^(0|[1-9]\d*)$/.test(key)) throw new ReportingError('invalid-input');
      result[key] = copy(descriptor.value, depth + 1, seen, budget);
    }
    if (!Array.isArray(value)) return result as T;
    if (Object.keys(result).length !== value.length) throw new ReportingError('invalid-input');
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
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(',')}}`;
}
export const digest = (value: unknown): string => createHash('sha256').update(canonical(value)).digest('hex');
export const text = (value: unknown): value is string => typeof value === 'string' && value.trim().length > 0;
export const sorted = (ids: readonly string[]): string[] => [...new Set(ids)].sort();
export function strings(value: unknown): asserts value is readonly string[] {
  if (!Array.isArray(value) || !value.every(text)) throw new ReportingError('invalid-input');
  if (new Set(value).size !== value.length) throw new ReportingError('duplicate-id');
}
export function index<T extends { readonly id: string }>(values: readonly T[]): Map<string, T> {
  if (!Array.isArray(values)) throw new ReportingError('invalid-input');
  const result = new Map<string, T>();
  for (const value of values) {
    if (!value || !text(value.id)) throw new ReportingError('invalid-input');
    if (result.has(value.id)) throw new ReportingError('duplicate-id');
    result.set(value.id, value);
  }
  return result;
}
export function checkedRecord(value: Evidence): StoredEvidence {
  const content = { schemaVersion: 1, finding: { id: 'report-proof', projectId: value.projectId,
    cweId: 'CWE-0', status: 'HYPOTHESIS', evidenceIds: [value.id] }, evidence: [value] };
  try { return verifyEvidenceBundle({ ...content, digest: digest(content) }).evidence[0]!; }
  catch { throw new ReportingError('integrity-failed'); }
}
export function limit(value: number, max: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) throw new ReportingError('invalid-options');
  return value;
}

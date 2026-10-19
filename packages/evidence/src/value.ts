import { createHash } from 'node:crypto';
import type { JsonValue } from '@agento/core';
import { EvidenceError } from './contracts.js';

/** Reject accessors, provider instances, cycles, sparse arrays and non-JSON numbers without invoking getters. */
export function jsonCopy(value: unknown, depth = 0, ancestors = new Set<object>(), budget = { nodes: 0 }): JsonValue {
  if (++budget.nodes > 100_000 || depth > 40) throw new EvidenceError('invalid-evidence');
  if (typeof value === 'string' && value.length > 16_777_216) throw new EvidenceError('record-limit');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (!value || typeof value !== 'object' || ancestors.has(value)) throw new EvidenceError('invalid-evidence');
  const array = Array.isArray(value);
  if (!array && ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new EvidenceError('invalid-evidence');
  if (Object.getOwnPropertySymbols(value).length) throw new EvidenceError('invalid-evidence');
  ancestors.add(value);
  try {
    const output: Record<string, JsonValue> = Object.create(null);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (array && key === 'length') continue;
      if (!descriptor.enumerable || !('value' in descriptor) || ['__proto__', 'constructor', 'prototype'].includes(key)) {
        throw new EvidenceError('invalid-evidence');
      }
      if (array && !/^(0|[1-9]\d*)$/.test(key)) throw new EvidenceError('invalid-evidence');
      output[key] = jsonCopy(descriptor.value, depth + 1, ancestors, budget);
    }
    if (!array) return output;
    if (Object.keys(output).length !== value.length) throw new EvidenceError('invalid-evidence');
    return Array.from({ length: value.length }, (_, index) => output[String(index)]!);
  } finally { ancestors.delete(value); }
}
export function freeze<T>(value: T): T {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
export function canonical(value: unknown): string {
  const item = jsonCopy(value);
  function serialize(value: JsonValue): string {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map(serialize).join(',')}]`;
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${serialize((value as Record<string, JsonValue>)[key]!)}`).join(',')}}`;
  }
  return serialize(item);
}
export const digest = (value: unknown): string => createHash('sha256').update(canonical(value)).digest('hex');
export function object(value: unknown): value is Record<string, JsonValue> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
export function text(value: unknown): value is string { return typeof value === 'string' && value.trim().length > 0; }
export function positive(value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new EvidenceError('invalid-options');
  return value;
}

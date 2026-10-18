import { createHash } from 'node:crypto';

export function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().filter(key => record[key] !== undefined)
    .map(key => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(',')}}`;
}

export function identifier(kind: string, value: unknown): string {
  return `model:${kind}:${createHash('sha256').update(stableJson(value)).digest('hex').slice(0, 32)}`;
}

export function unique(values: readonly string[]): string[] { return [...new Set(values)].sort(); }

export function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}

export function distinct<T>(values: readonly T[]): T[] {
  const entries = new Map(values.map(value => [stableJson(value), value]));
  return [...entries.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, value]) => value);
}

export function byId<T extends { readonly id: string }>(values: readonly T[], kind: string): T[] {
  const entries = new Map<string, T>();
  for (const value of values) {
    if (!value.id || typeof value.id !== 'string') throw new Error(`Invalid ${kind} ID`);
    const previous = entries.get(value.id);
    if (previous && stableJson(previous) !== stableJson(value)) throw new Error(`Conflicting ${kind} ID`);
    entries.set(value.id, value);
  }
  return [...entries.values()].sort((a, b) => a.id.localeCompare(b.id));
}

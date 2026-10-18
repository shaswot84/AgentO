import { createHash } from 'node:crypto';

export function freeze<T>(value: T): T {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
export function identifier(...values: unknown[]): string {
  return createHash('sha256').update(JSON.stringify(values)).digest('hex').slice(0, 24);
}
export function record(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}
export function exact(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
export function strings(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(item => typeof item === 'string' && item.length > 0);
}
export function cancelled(signal?: AbortSignal): void {
  if (signal?.aborted) throw new Error('Hypothesis generation cancelled');
}

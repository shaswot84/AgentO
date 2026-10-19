import { createHash } from 'node:crypto';
import type { Evidence } from '@agento/core';
import { verifyEvidenceBundle, type StoredEvidence } from '@agento/evidence';

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
/** Reuse the Evidence Engine's JSON, schema and record digest validation. */
export function checkedRecord(value: Evidence): StoredEvidence {
  const content = { schemaVersion: 1, finding: { id: 'verification', projectId: value.projectId,
    cweId: 'CWE-0', status: 'HYPOTHESIS', evidenceIds: [value.id] }, evidence: [value] };
  const digest = createHash('sha256').update(canonical(content)).digest('hex');
  return verifyEvidenceBundle({ ...content, digest }).evidence[0]!;
}
export function targetMatches(observed: string, expected: string): boolean {
  try {
    const a = new URL(observed), b = new URL(expected);
    if (![a, b].every(url => ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password && !url.hash)) return false;
    const actual = a.pathname.split('/'), template = b.pathname.split('/');
    return a.origin === b.origin && actual.length === template.length && template.every((part, index) =>
      /^:[A-Za-z_][A-Za-z0-9_]*$/.test(part) ? !!actual[index] : part === actual[index]);
  } catch { return false; }
}

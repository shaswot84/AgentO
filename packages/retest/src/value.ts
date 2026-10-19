import { createHash } from 'node:crypto';
import type { Evidence } from '@agento/core';
import { verifyEvidenceBundle, type StoredEvidence } from '@agento/evidence';
import { RetestError } from './contracts.js';

export const sha256 = (text: string) => createHash('sha256').update(text).digest('hex');
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(',')}}`;
}
export function freeze<T>(value: T): T {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}
export function checkedRecord(value: Evidence): StoredEvidence {
  const record = value as StoredEvidence;
  const content = { schemaVersion: 1 as const, finding: { id: 'retest-check', projectId: record.projectId,
    cweId: 'CWE-639' as const, status: 'CONFIRMED' as const, evidenceIds: [record.id] }, evidence: [record] };
  try { verifyEvidenceBundle({ ...content, digest: sha256(canonical(content)) }); }
  catch { throw new RetestError('integrity-failed'); }
  return record;
}
export const safePath = (path: string): boolean => typeof path === 'string' && /^(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_.-]+$/.test(path)
  && path.split('/').every(part => !part.startsWith('.'));
export function loopbackOrigin(value: string): string {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || !['127.0.0.1', '[::1]'].includes(url.hostname)
    || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new RetestError('invalid-input');
  return url.origin;
}

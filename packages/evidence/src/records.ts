import type { Evidence, EvidenceCaptureContext, EvidenceKind } from '@agento/core';
import { EvidenceError, type StoredEvidence } from './contracts.js';
import { Redactor } from './redaction.js';
import { digest, freeze, jsonCopy, object, text } from './value.js';

export const EVIDENCE_KINDS: readonly EvidenceKind[] = Object.freeze([
  'source-location', 'static-analysis', 'http-request', 'http-response', 'header', 'cookie-security',
  'cross-origin', 'authorization', 'browser-observation', 'identity-session', 'resource-ownership',
  'scanner-output', 'screenshot', 'configuration',
]);
const fields = ['id', 'projectId', 'kind', 'producerId', 'capturedAt', 'summary', 'facts', 'source', 'endpointId', 'identityId'];

function validateBase(value: unknown): asserts value is Evidence {
  if (!object(value) || !['id', 'projectId', 'producerId'].every(key => text(value[key]))
    || !EVIDENCE_KINDS.includes(value.kind as EvidenceKind) || typeof value.summary !== 'string'
    || !text(value.capturedAt) || !Number.isFinite(Date.parse(value.capturedAt)) || !object(value.facts)
    || ['endpointId', 'identityId'].some(key => value[key] !== undefined && !text(value[key]))) throw new EvidenceError('invalid-evidence');
  if (value.source !== undefined) {
    if (!object(value.source) || !text(value.source.file) || !Number.isSafeInteger(value.source.startLine)
      || (value.source.startLine as number) < 1 || value.source.endLine !== undefined
      && (!Number.isSafeInteger(value.source.endLine) || (value.source.endLine as number) < (value.source.startLine as number))
      || value.source.symbol !== undefined && typeof value.source.symbol !== 'string') throw new EvidenceError('invalid-evidence');
  }
}
export function createRecord(input: Evidence, scope: EvidenceCaptureContext, redactor: Redactor): StoredEvidence {
  const value = jsonCopy(input);
  validateBase(value);
  if (value.projectId !== scope.project.id) throw new EvidenceError('project-mismatch');
  const project = jsonCopy(scope.project);
  if (!object(project) || !text(project.id) || !text(project.baseUrl) || !Array.isArray(scope.capabilityIds)
    || !scope.capabilityIds.length || !scope.capabilityIds.every(text)
    || scope.probeId !== undefined && !text(scope.probeId)
    || scope.environmentId !== undefined && !text(scope.environmentId)) throw new EvidenceError('invalid-evidence');
  // IDs are references. Never silently rewrite them if a host accidentally puts credentials there.
  for (const id of [value.id, value.projectId, value.producerId, value.endpointId, value.identityId].filter(text)) {
    if (redactor.text(id) !== id) throw new EvidenceError('invalid-evidence');
  }
  const baseUrl = redactor.url(project.baseUrl);
  const targetUrl = redactor.url(scope.targetUrl ?? project.baseUrl);
  if (baseUrl === '[REDACTED]' || targetUrl === '[REDACTED]') throw new EvidenceError('invalid-evidence');
  const selected = Object.fromEntries(fields.filter(key => Object.hasOwn(value, key)).map(key => [key, (value as unknown as Record<string, unknown>)[key]]));
  const safe = redactor.json(jsonCopy(selected)) as unknown as Evidence;
  validateBase(safe);
  const record = { ...safe, schemaVersion: 1 as const, provenance: {
    probeId: redactor.text(scope.probeId ?? (value.producerId.startsWith('probe:') ? value.producerId.slice(6) : value.producerId)),
    capabilityIds: [...new Set(scope.capabilityIds.map(item => redactor.text(item)))].sort(),
    environment: { id: redactor.text(scope.environmentId ?? 'default'), baseUrl, targetUrl },
  } };
  return freeze({ ...record, digest: digest(record) });
}

/** Validate stored content without reapplying a newer redaction policy or accepting provider extras. */
export function restoreRecord(input: unknown): StoredEvidence {
  const value = jsonCopy(input);
  validateBase(value);
  const record = value as unknown as StoredEvidence;
  const keys = Object.keys(record);
  const { digest: supplied, ...content } = record;
  if (keys.some(key => ![...fields, 'schemaVersion', 'provenance', 'digest'].includes(key))
    || record.schemaVersion !== 1 || !/^[a-f0-9]{64}$/.test(supplied) || digest(content) !== supplied
    || !object(record.provenance) || !text(record.provenance.probeId)
    || !Array.isArray(record.provenance.capabilityIds) || !record.provenance.capabilityIds.length
    || !record.provenance.capabilityIds.every(text) || !object(record.provenance.environment)
    || !['id', 'baseUrl', 'targetUrl'].every(key => text((record.provenance.environment as unknown as Record<string, unknown>)[key]))) {
    throw new EvidenceError('integrity-failed');
  }
  return freeze(record);
}

import { createHash } from 'node:crypto';
import { verifyEvidenceBundle } from '@agento/evidence';
import { RetestError } from './contracts.js';
export const sha256 = (text) => createHash('sha256').update(text).digest('hex');
export function canonical(value) {
    if (value === null || typeof value !== 'object')
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map(canonical).join(',')}]`;
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}
export function freeze(value) {
    if (value && typeof value === 'object') {
        for (const child of Object.values(value))
            freeze(child);
        Object.freeze(value);
    }
    return value;
}
export function checkedRecord(value) {
    const record = value;
    const content = { schemaVersion: 1, finding: { id: 'retest-check', projectId: record.projectId,
            cweId: 'CWE-639', status: 'CONFIRMED', evidenceIds: [record.id] }, evidence: [record] };
    try {
        verifyEvidenceBundle({ ...content, digest: sha256(canonical(content)) });
    }
    catch {
        throw new RetestError('integrity-failed');
    }
    return record;
}
export const safePath = (path) => typeof path === 'string' && /^(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_.-]+$/.test(path)
    && path.split('/').every(part => !part.startsWith('.'));
export function loopbackOrigin(value) {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || !['127.0.0.1', '[::1]'].includes(url.hostname)
        || url.username || url.password || url.search || url.hash || url.pathname !== '/')
        throw new RetestError('invalid-input');
    return url.origin;
}

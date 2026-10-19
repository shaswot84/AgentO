import { createHash } from 'node:crypto';
import { ScannerError } from './contracts.js';
export const hash = (value) => createHash('sha256').update(value).digest('hex');
export function record(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        throw new ScannerError('invalid-output');
    return value;
}
function parse(text) {
    try {
        return JSON.parse(text);
    }
    catch {
        throw new ScannerError('invalid-output');
    }
}
function list(value) {
    if (!Array.isArray(value) || value.length > 256)
        throw new ScannerError('invalid-output');
    return value;
}
function location(value, url) {
    if (typeof value !== 'string')
        throw new ScannerError('invalid-output');
    try {
        const actual = new URL(value), expected = new URL(url);
        if (actual.origin !== expected.origin || actual.pathname !== expected.pathname || actual.username || actual.password)
            throw new Error();
    }
    catch {
        throw new ScannerError('invalid-output');
    }
}
function claim(id, cwes, severity, confidence = 'unknown', technique = null, dbmsFingerprint = null) {
    if (typeof id !== 'string' || !id || id.length > 512)
        throw new ScannerError('invalid-output');
    const cweIds = (Array.isArray(cwes) ? cwes : [cwes]).flatMap(value => {
        const match = String(value).match(/^(?:CWE-)?(639|862|942|1004|614|79|89)$/i);
        return match ? [`CWE-${match[1]}`] : [];
    });
    return { ruleDigest: hash(id), cweIds: [...new Set(cweIds)].sort(),
        reportedSeverity: ['info', 'low', 'medium', 'high', 'critical'].includes(String(severity))
            ? severity : 'unknown',
        reportedConfidence: ['low', 'medium', 'high'].includes(String(confidence))
            ? confidence : 'unknown', technique, dbmsFingerprint };
}
export function nuclei(text, url) {
    if (!text.trim())
        return [];
    return list(text.trim().split(/\r?\n/)).map(line => {
        const value = record(parse(String(line))), info = record(value.info);
        if (value.type !== 'http' || value['matcher-status'] === false)
            throw new ScannerError('invalid-output');
        location(value['matched-at'], url);
        const classification = info.classification === undefined ? {} : record(info.classification);
        return claim(value['template-id'], classification['cwe-id'], info.severity);
    });
}
export function zap(text, url) {
    const root = record(parse(text));
    const claims = [];
    for (const item of list(root.site)) {
        const site = record(item);
        for (const item of list(site.alerts)) {
            const alert = record(item);
            const instances = list(alert.instances);
            if (!instances.length)
                throw new ScannerError('invalid-output');
            for (const instance of instances)
                location(record(instance).uri, url);
            const risk = ['info', 'low', 'medium', 'high'][Number(alert.riskcode)] ?? 'unknown';
            const confidence = ['unknown', 'low', 'medium', 'high', 'high'][Number(alert.confidence)] ?? 'unknown';
            claims.push(claim(String(alert.pluginid ?? ''), alert.cweid, risk, confidence));
            if (claims.length > 256)
                throw new ScannerError('output-limit');
        }
    }
    return claims;
}
export function dalfox(text, url) {
    const root = parse(text);
    if (!Array.isArray(root)) {
        const meta = record(record(root).meta);
        if (meta.incomplete !== false)
            throw new ScannerError('incomplete-output');
    }
    const findings = Array.isArray(root) ? root : record(root).findings;
    return list(findings).map(item => {
        const finding = record(item);
        // v3 findings carry url; v2 PoC records carry their request URL in data.
        location(finding.url ?? finding.data, url);
        const type = finding.type;
        if (!['V', 'R', 'A', 'I', 'v', 'r', 'a', 'i'].includes(String(type)))
            throw new ScannerError('invalid-output');
        return claim(`dalfox:${String(type).toUpperCase()}`, 'CWE-79', String(finding.severity).toLowerCase(), finding.confidence);
    });
}
/** Parse only structured result blocks, never arbitrary console sentences or payload text. */
export function sqlmap(text, url) {
    const failures = text.split(/\r?\n/).filter(line => /\[(?:CRITICAL|ERROR)\]/.test(line));
    if (failures.some(line => !/\[CRITICAL\] all tested parameters do not appear to be injectable\./.test(line)))
        throw new ScannerError('tool-failed');
    if (!/testing connection to the target URL|sqlmap identified the following injection point|all tested parameters do not appear to be injectable/.test(text)) {
        throw new ScannerError('invalid-output');
    }
    const block = text.match(/sqlmap identified the following injection point(?:\(s\))?[\s\S]*?---\s*\r?\n([\s\S]*?)\r?\n---/);
    if (!block)
        return [];
    // The target URL is validated by the private gateway, not copied from console prose.
    location(url, url);
    const dbms = text.match(/^back-end DBMS: (SQLite|PostgreSQL|MySQL|Microsoft SQL Server|Oracle)(?:\s|$)/m)?.[1];
    const fingerprint = dbms === 'Microsoft SQL Server' ? 'SQLServer' : dbms;
    const techniques = [...block[1].matchAll(/^\s*Type: (boolean-based blind|error-based|time-based blind)\s*$/gm)];
    if (!techniques.length)
        throw new ScannerError('invalid-output');
    return techniques.map(match => claim(`sqlmap:${match[1]}`, 'CWE-89', 'unknown', 'unknown', match[1] === 'error-based' ? 'error' : match[1] === 'boolean-based blind' ? 'boolean' : 'time', fingerprint ?? null));
}
export function freeze(value) {
    if (value && typeof value === 'object') {
        for (const child of Object.values(value))
            freeze(child);
        Object.freeze(value);
    }
    return value;
}

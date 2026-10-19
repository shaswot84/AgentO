import { freeze } from './shared.js';
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const string = (value) => typeof value === 'string' && value.length > 0;
const strings = (value) => Array.isArray(value) && value.every(item => typeof item === 'string');
const bool = (value) => typeof value === 'boolean';
const tri = (value) => value === null || bool(value);
const numeric = (value) => typeof value === 'number' && Number.isFinite(value);
const nonnegative = (value) => numeric(value) && value >= 0;
const timestamp = (value) => string(value) && Number.isFinite(Date.parse(value));
function httpUrl(value) {
    if (!string(value))
        return false;
    try {
        const parsed = new URL(value);
        return ['http:', 'https:'].includes(parsed.protocol) && !parsed.username && !parsed.password;
    }
    catch {
        return false;
    }
}
function origin(value) {
    return value === 'null' || httpUrl(value) && new URL(value).origin === value;
}
function response(value) {
    if (!object(value) || !string(value.responseId) || !string(value.url) || !string(value.method)
        || !numeric(value.status) || !Number.isInteger(value.status) || value.status < 100 || value.status > 599
        || !object(value.body) || !string(value.body.sha256) || !/^[a-f0-9]{64}$/i.test(value.body.sha256)
        || !nonnegative(value.body.byteLength) || !bool(value.body.truncated) || !object(value.timings))
        return false;
    if (!httpUrl(value.url))
        return false;
    return timestamp(value.timings.startedAt) && nonnegative(value.timings.firstByteMs) && nonnegative(value.timings.durationMs);
}
function comparison(value) {
    return object(value) && numeric(value.statusDelta) && tri(value.bodyEqual) && numeric(value.byteLengthDelta)
        && numeric(value.durationDeltaMs) && tri(value.ownerMarkersMatch);
}
function cors(value) {
    return object(value) && strings(value.allowOrigin) && Array.isArray(value.allowCredentials)
        && value.allowCredentials.every(tri) && strings(value.allowMethods) && strings(value.allowHeaders)
        && strings(value.exposeHeaders) && Array.isArray(value.maxAge) && value.maxAge.every(item => item === null || numeric(item));
}
function cookie(value) {
    return object(value) && string(value.name) && value.value === '[REDACTED]' && string(value.domain) && string(value.path)
        && bool(value.hostOnly) && bool(value.httpOnly) && bool(value.secure) && bool(value.partitioned)
        && ['Strict', 'Lax', 'None', null].includes(value.sameSite)
        && (value.expiresAt === null || timestamp(value.expiresAt)) && (value.maxAge === null || numeric(value.maxAge))
        && ['response', 'browser', 'jar'].includes(value.source)
        && (value.responseId === undefined || string(value.responseId)) && (value.sessionId === undefined || string(value.sessionId));
}
function parameter(value) {
    return object(value) && string(value.name) && ['query', 'json-body', 'form-body'].includes(value.location);
}
/** Validate at the core JSON boundary as well as at the public typed evaluator boundary. */
export function isProbeEvidence(value) {
    if (!object(value) || !string(value.id) || !string(value.projectId) || !timestamp(value.capturedAt)
        || !['COMPLETED', 'PARTIAL'].includes(value.outcome) || !Array.isArray(value.diagnostics)
        || !value.diagnostics.every(item => ['scanner-unavailable', 'scanner-failed', 'scanner-skipped', 'browser-unavailable', 'response-truncated'].includes(item))
        || value.outcome === 'COMPLETED' && value.diagnostics.length > 0)
        return false;
    switch (value.probeId) {
        case 'cookie-security': return Array.isArray(value.observations) && value.observations.every(item => object(item)
            && ['anonymous', 'authenticated'].includes(item.context)
            && (item.context === 'anonymous' ? item.identityId === null : string(item.identityId))
            && response(item.response) && Array.isArray(item.cookies) && item.cookies.every(cookie));
        case 'cross-origin': return Array.isArray(value.observations) && value.observations.every(item => object(item)
            && origin(item.requestedOrigin) && (item.identityId === null || string(item.identityId))
            && ['omit', 'session'].includes(item.credentialMode) && object(item.preflight) && object(item.actual)
            && response(item.preflight.response) && response(item.actual.response) && cors(item.preflight.cors) && cors(item.actual.cors));
        case 'authorization': return string(value.resourceId) && string(value.ownerIdentityId) && string(value.attackerIdentityId)
            && value.ownerIdentityId !== value.attackerIdentityId && response(value.owner) && response(value.attacker)
            && response(value.anonymous) && comparison(value.attackerComparison) && comparison(value.anonymousComparison);
        case 'xss': return parameter(value.parameter) && response(value.baseline) && response(value.injected) && string(value.canary)
            && tri(value.literalReflection) && Array.isArray(value.reflectionContexts)
            && value.reflectionContexts.every(item => ['html', 'attribute', 'script', 'text'].includes(item))
            && (value.browser === null || object(value.browser) && httpUrl(value.browser.url) && bool(value.browser.canaryVisible))
            && tri(value.executionConfirmed) && tri(value.domSinkReached);
        case 'sql-injection': return parameter(value.parameter) && response(value.baseline) && comparison(value.booleanComparison)
            && Array.isArray(value.observations) && value.observations.every(item => object(item)
            && ['syntax', 'boolean-true', 'boolean-false'].includes(item.variant)
            && ['error', 'boolean'].includes(item.technique) && response(item.response)
            && comparison(item.comparison) && strings(item.errorIndicators) && fingerprint(item.dbmsFingerprint))
            && (value.scanner === null || object(value.scanner) && ['error', 'boolean', 'time'].includes(value.scanner.technique)
                && fingerprint(value.scanner.dbmsFingerprint) && tri(value.scanner.observedDifference));
        default: return false;
    }
}
function fingerprint(value) { return [null, 'SQLite', 'PostgreSQL', 'MySQL', 'SQLServer', 'Oracle'].includes(value); }
/** Each nested object has its own public schema; extra adapter fields are never copied. */
function pick(value, keys) {
    const source = value;
    return Object.fromEntries(keys.filter(key => source[key] !== undefined).map(key => [key, source[key]]));
}
function publicResponse(value) {
    const item = value, parsed = new URL(item.url);
    parsed.hash = '';
    parsed.username = '';
    parsed.password = '';
    for (const name of new Set(parsed.searchParams.keys()))
        parsed.searchParams.set(name, '[REDACTED]');
    return { ...pick(item, ['responseId', 'method', 'status']), url: parsed.href,
        body: pick(item.body, ['sha256', 'byteLength', 'truncated']),
        timings: pick(item.timings, ['startedAt', 'firstByteMs', 'durationMs']) };
}
const publicComparison = (value) => pick(value, ['statusDelta', 'bodyEqual', 'byteLengthDelta', 'durationDeltaMs', 'ownerMarkersMatch']);
const publicCors = (value) => pick(value, ['allowOrigin', 'allowCredentials', 'allowMethods', 'allowHeaders', 'exposeHeaders', 'maxAge']);
function project(value) {
    const item = value;
    const common = pick(item, ['id', 'probeId', 'projectId', 'capturedAt', 'outcome', 'diagnostics']);
    if (item.probeId === 'cookie-security')
        return { ...common, observations: item.observations.map(observation => ({
                ...pick(observation, ['identityId', 'context']), response: publicResponse(observation.response),
                cookies: observation.cookies.map(cookie => pick(cookie, [
                    'name', 'value', 'domain', 'path', 'hostOnly', 'httpOnly', 'secure', 'sameSite', 'expiresAt', 'maxAge',
                    'partitioned', 'source', 'responseId', 'sessionId',
                ])),
            })) };
    if (item.probeId === 'cross-origin')
        return { ...common, observations: item.observations.map(observation => ({
                ...pick(observation, ['requestedOrigin', 'identityId', 'credentialMode']),
                ...Object.fromEntries(['preflight', 'actual'].map(key => {
                    const exchange = observation[key];
                    return [key, { response: publicResponse(exchange.response), cors: publicCors(exchange.cors) }];
                })),
            })) };
    if (item.probeId === 'authorization')
        return { ...common, ...pick(item, ['resourceId', 'ownerIdentityId', 'attackerIdentityId']),
            owner: publicResponse(item.owner), attacker: publicResponse(item.attacker), anonymous: publicResponse(item.anonymous),
            attackerComparison: publicComparison(item.attackerComparison), anonymousComparison: publicComparison(item.anonymousComparison) };
    const injection = { ...common, parameter: pick(item.parameter, ['name', 'location']), baseline: publicResponse(item.baseline) };
    if (item.probeId === 'xss') {
        const browser = item.browser;
        return { ...injection, ...pick(item, ['canary', 'literalReflection', 'reflectionContexts', 'executionConfirmed', 'domSinkReached']),
            injected: publicResponse(item.injected), browser: browser === null ? null : {
                canaryVisible: browser.canaryVisible, url: new URL(browser.url).origin + new URL(browser.url).pathname,
            } };
    }
    return { ...injection, booleanComparison: publicComparison(item.booleanComparison),
        scanner: item.scanner === null ? null : pick(item.scanner, ['technique', 'dbmsFingerprint', 'observedDifference']),
        observations: item.observations.map(observation => ({
            ...pick(observation, ['variant', 'technique', 'errorIndicators', 'dbmsFingerprint']),
            response: publicResponse(observation.response), comparison: publicComparison(observation.comparison),
        })) };
}
export function toCoreEvidence(probe, endpointId) {
    if (!isProbeEvidence(probe))
        throw new Error('Invalid normalized probe evidence');
    return freeze({ id: probe.id, projectId: probe.projectId, kind: 'configuration', producerId: `probe:${probe.probeId}`,
        capturedAt: probe.capturedAt, summary: 'Normalized security probe observations.',
        ...(endpointId ? { endpointId } : {}), facts: { observation: 'security-probe', schemaVersion: 1, probe: structuredClone(project(probe)) } });
}
export function fromCoreEvidence(item) {
    const probe = item.facts.probe;
    if (item.facts.observation !== 'security-probe' || item.facts.schemaVersion !== 1 || !isProbeEvidence(probe)
        || probe.id !== item.id || probe.projectId !== item.projectId || probe.capturedAt !== item.capturedAt
        || item.producerId !== `probe:${probe.probeId}`)
        return;
    return probe;
}

import { freeze } from './safety.js';
export function splitQuoted(value, separator) {
    const result = [];
    let start = 0, quoted = false, escaped = false;
    for (let index = 0; index < value.length; index++) {
        const char = value[index];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (quoted && char === '\\') {
            escaped = true;
            continue;
        }
        if (char === '"')
            quoted = !quoted;
        else if (!quoted && char === separator) {
            result.push(value.slice(start, index).trim());
            start = index + 1;
        }
    }
    result.push(value.slice(start).trim());
    return result.filter(Boolean);
}
export class NormalizedHeaderAnalyzer {
    async analyze(response) {
        const read = (key) => response.headers[key] ?? [];
        const tokens = (key) => read(key).flatMap(value => splitQuoted(value, ','));
        const numeric = (key) => read(key).map(value => /^\d+$/.test(value.trim()) && Number.isSafeInteger(Number(value)) ? Number(value) : null);
        const security = Object.create(null);
        for (const key of ['strict-transport-security', 'content-security-policy', 'content-security-policy-report-only',
            'x-content-type-options', 'x-frame-options', 'referrer-policy', 'permissions-policy',
            'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy']) {
            if (read(key).length)
                security[key] = [...read(key)];
        }
        return freeze({ responseId: response.id,
            cors: { allowOrigin: [...read('access-control-allow-origin')],
                allowCredentials: read('access-control-allow-credentials').map(value => value.trim() === 'true' ? true : value.trim() === 'false' ? false : null),
                allowMethods: tokens('access-control-allow-methods'), allowHeaders: tokens('access-control-allow-headers'),
                exposeHeaders: tokens('access-control-expose-headers'), maxAge: numeric('access-control-max-age') }, security,
            caching: { cacheControl: tokens('cache-control').map(directive => {
                    const index = directive.indexOf('=');
                    return { name: (index < 0 ? directive : directive.slice(0, index)).trim().toLowerCase(),
                        value: index < 0 ? null : directive.slice(index + 1).trim().replace(/^"(.*)"$/, '$1') };
                }), pragma: tokens('pragma'), vary: tokens('vary'), expires: [...read('expires')], age: numeric('age') } });
    }
}

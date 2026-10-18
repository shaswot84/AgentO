import { createHash } from 'node:crypto';
export function freeze(value) {
    if (value && typeof value === 'object') {
        for (const child of Object.values(value))
            freeze(child);
        Object.freeze(value);
    }
    return value;
}
export function identifier(...values) {
    return createHash('sha256').update(JSON.stringify(values)).digest('hex').slice(0, 24);
}
export function record(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value);
}
export function exact(value, keys) {
    return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
export function strings(value) {
    return Array.isArray(value) && value.every(item => typeof item === 'string' && item.length > 0);
}
export function cancelled(signal) {
    if (signal?.aborted)
        throw new Error('Hypothesis generation cancelled');
}

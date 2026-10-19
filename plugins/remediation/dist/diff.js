import { RemediationError } from './contracts.js';
import { safePath } from './value.js';
/** One bounded hunk per file, retaining three context lines at both ends. */
export function unifiedDiff(path, before, after) {
    if (!safePath(path) || before === after || !before.endsWith('\n') || !after.endsWith('\n'))
        throw new RemediationError('source-mismatch');
    const oldLines = before.slice(0, -1).split('\n'), newLines = after.slice(0, -1).split('\n');
    let prefix = 0, suffix = 0;
    while (prefix < Math.min(oldLines.length, newLines.length) && oldLines[prefix] === newLines[prefix])
        prefix++;
    while (suffix < Math.min(oldLines.length, newLines.length) - prefix
        && oldLines[oldLines.length - suffix - 1] === newLines[newLines.length - suffix - 1])
        suffix++;
    const start = Math.max(0, prefix - 3), endOld = oldLines.length - Math.max(0, suffix - 3), endNew = newLines.length - Math.max(0, suffix - 3);
    const lines = [`diff --git a/${path} b/${path}`, `--- a/${path}`, `+++ b/${path}`,
        `@@ -${start + 1},${endOld - start} +${start + 1},${endNew - start} @@`];
    lines.push(...oldLines.slice(start, prefix).map(line => ` ${line}`), ...oldLines.slice(prefix, oldLines.length - suffix).map(line => `-${line}`), ...newLines.slice(prefix, newLines.length - suffix).map(line => `+${line}`), ...oldLines.slice(oldLines.length - suffix, endOld).map(line => ` ${line}`));
    return `${lines.join('\n')}\n`;
}

import { constants } from 'node:fs';
import { access, stat } from 'node:fs/promises';
import { delimiter, isAbsolute, join } from 'node:path';
/** File-only check. Never interpolate a command, spawn a process or return a private path. */
export async function executableAvailable(command) {
    if (!validExecutable(command))
        return false;
    const paths = isAbsolute(command) ? [command] : (process.env.PATH ?? '').split(delimiter)
        .filter(directory => isAbsolute(directory)).map(directory => join(directory, command));
    for (const path of paths) {
        try {
            if (!(await stat(path)).isFile())
                continue;
            await access(path, constants.X_OK);
            return true;
        }
        catch { /* A missing, inaccessible or non-executable candidate does not stop PATH lookup. */ }
    }
    return false;
}
export function validExecutable(command) {
    return typeof command === 'string' && command.length > 0 && command.length <= 4_096
        && !/[\r\n\0]/.test(command)
        && (isAbsolute(command) || /^[A-Za-z0-9_.-]+$/.test(command) && command !== '.' && command !== '..');
}
export async function checkAvailability(toolId, check, timeoutMs, signal) {
    if (signal?.aborted)
        return { toolId, available: false, code: 'cancelled' };
    const controller = new AbortController();
    let timer;
    let cancel;
    const interrupted = new Promise(resolve => {
        cancel = () => { resolve('cancelled'); controller.abort(); };
        signal?.addEventListener('abort', cancel, { once: true });
        timer = setTimeout(() => { resolve('timeout'); controller.abort(); }, timeoutMs);
    });
    try {
        // Attach a rejection handler even if a late callback ignores cancellation.
        const checked = Promise.resolve().then(() => signal?.aborted ? 'cancelled' : check(controller.signal))
            .catch(() => 'check-failed');
        const code = await Promise.race([checked, interrupted]);
        return { toolId, available: code === 'available', code };
    }
    finally {
        clearTimeout(timer);
        if (cancel)
            signal?.removeEventListener('abort', cancel);
    }
}

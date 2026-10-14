import { BrowserWorkflowFailure } from '@agento/core';

export function integer(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new BrowserWorkflowFailure('invalid-workflow');
  }
  return value;
}

/** Defense in depth for application text; the browser also redacts known session secrets. */
export function redact(value: string, limit = 500): string {
  return value.replace(/\b(?:Bearer\s+)?eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/gi, '[redacted]')
    .replace(/\b(?:password|passwd|token|secret|cookie|authorization|api[_-]?key)\s*[:=]\s*[^\s,;]+/gi, '[redacted]')
    .replace(/\bhttps?:\/\/[^\s<>"']+/gi, item => safeUrl(item))
    .replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, limit);
}

export function safeUrl(value: string): string {
  if (value === 'about:blank') return value;
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol)) return '[unsupported-url]';
    url.username = ''; url.password = ''; url.search = ''; url.hash = '';
    return url.toString().slice(0, 2_000);
  } catch { return '[invalid-url]'; }
}

export function normalizedFailure(error: unknown): BrowserWorkflowFailure {
  return error instanceof BrowserWorkflowFailure ? error : new BrowserWorkflowFailure('browser-failed');
}

export function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

export async function bounded<T>(operation: (signal: AbortSignal) => Promise<T>,
  parent: AbortSignal, timeoutMs: number): Promise<T> {
  if (parent.aborted) throw new BrowserWorkflowFailure('timeout');
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let abort: (() => void) | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    abort = () => { controller.abort(); reject(new BrowserWorkflowFailure('timeout')); };
    parent.addEventListener('abort', abort, { once: true });
    timer = setTimeout(abort, timeoutMs);
  });
  try { return await Promise.race([Promise.resolve().then(() => operation(controller.signal)), deadline]); }
  finally { if (timer) clearTimeout(timer); if (abort) parent.removeEventListener('abort', abort); }
}

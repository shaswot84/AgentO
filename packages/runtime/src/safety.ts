export type RuntimeErrorCode = 'invalid-request' | 'scope-denied' | 'timeout' | 'cancelled'
  | 'transport-failed' | 'browser-failed' | 'authentication-failed' | 'session-closed'
  | 'unsupported-capability' | 'record-limit' | 'session-limit';
export class RuntimeError extends Error {
  constructor(readonly code: RuntimeErrorCode) { super(code); this.name = 'RuntimeError'; }
}
export function freeze<T>(value: T): T {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
export function limit(value: number, maximum: number): number {
  if (!Number.isInteger(value) || value < 1 || value > maximum) throw new RuntimeError('invalid-request');
  return value;
}
export class RuntimeScope {
  readonly origins: readonly string[];
  readonly baseUrl: string;
  constructor(baseUrl: string, allowedOrigins: readonly string[]) {
    this.origins = Object.freeze([...new Set(allowedOrigins.map(value => {
      const url = this.parse(value);
      if (url.pathname !== '/' || url.search || url.hash) throw new RuntimeError('scope-denied');
      return url.origin;
    }))]);
    this.baseUrl = this.assert(baseUrl);
  }
  assert(value: string): string {
    const url = this.parse(value, this.baseUrl);
    if (!this.origins.includes(url.origin)) throw new RuntimeError('scope-denied');
    url.hash = '';
    return url.href;
  }
  private parse(value: string, base?: string): URL {
    try {
      if (typeof value !== 'string' || !value || value !== value.trim() || /[\u0000-\u0020\\]/.test(value)) throw new Error();
      const url = new URL(value, base);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error();
      return url;
    } catch { throw new RuntimeError('scope-denied'); }
  }
}
/** Queries and fragments can contain credentials. Backend paths remain observational data. */
export function evidenceUrl(value: string): string {
  try {
    const url = new URL(value); url.username = ''; url.password = ''; url.hash = '';
    for (const key of [...url.searchParams.keys()]) url.searchParams.set(key, '[REDACTED]');
    return url.href;
  } catch { return '[REDACTED]'; }
}
export async function bounded<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) { void work.catch(() => undefined); throw new RuntimeError('cancelled'); }
  let abort!: () => void;
  try {
    return await Promise.race([work, new Promise<never>((_resolve, reject) => {
      abort = () => reject(new RuntimeError('cancelled'));
      signal.addEventListener('abort', abort, { once: true });
    })]);
  } finally { signal.removeEventListener('abort', abort); }
}

export type RuntimeErrorCode = 'invalid-request' | 'scope-denied' | 'timeout' | 'cancelled' | 'transport-failed' | 'browser-failed' | 'authentication-failed' | 'session-closed' | 'unsupported-capability' | 'record-limit' | 'session-limit';
export declare class RuntimeError extends Error {
    readonly code: RuntimeErrorCode;
    constructor(code: RuntimeErrorCode);
}
export declare function freeze<T>(value: T): T;
export declare function limit(value: number, maximum: number): number;
export declare class RuntimeScope {
    readonly origins: readonly string[];
    readonly baseUrl: string;
    constructor(baseUrl: string, allowedOrigins: readonly string[]);
    assert(value: string): string;
    private parse;
}
/** Queries and fragments can contain credentials. Backend paths remain observational data. */
export declare function evidenceUrl(value: string): string;
export declare function bounded<T>(work: Promise<T>, signal: AbortSignal): Promise<T>;

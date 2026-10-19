import type { SecurityScannerRequest } from '@agento/runtime';
export interface Exchange {
    readonly responseId: string;
    readonly method: string;
    readonly status: number;
    readonly requestDigest: string;
    readonly bodyDigest: string;
    readonly byteLength: number;
}
/** A local origin, never an unrestricted forward proxy or CONNECT tunnel. */
export declare function openGateway(input: SecurityScannerRequest, signal: AbortSignal, headPreflight?: boolean): Promise<{
    origin: string;
    url: string;
    signal: AbortSignal;
    exchanges: Exchange[];
    assertHealthy(): void;
    assertComplete(): void;
    close(): Promise<void>;
}>;
export declare function bounded<T>(operation: Promise<T>, signal: AbortSignal): Promise<T>;

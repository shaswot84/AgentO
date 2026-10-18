import type { AuthSession, HttpRequest, HttpResponse, TestIdentity } from '../contracts.js';
import type { InjectionContext, ProbeContext, ProbeEvidence, ProbeMetadata, ResponseComparator, ResponseComparison } from './contracts.js';
import type { CapabilityCatalog } from './registry.js';
export declare function metadata(id: string, required: readonly (keyof CapabilityCatalog)[], optional?: readonly (keyof CapabilityCatalog)[]): ProbeMetadata;
export declare function available(context: ProbeContext, required: readonly string[]): boolean;
export declare function assertActive(context: ProbeContext): void;
export declare function check(context: ProbeContext, supported: boolean): void;
export declare function sanitized<T>(execute: () => Promise<T>): Promise<T>;
export declare function base(context: ProbeContext, probeId: string, diagnostics?: ProbeEvidence['diagnostics']): ProbeEvidence;
/** Each investigation snapshots configuration before the first asynchronous boundary. */
export declare function snapshot<C extends ProbeContext>(context: C): C;
export declare function request(context: ProbeContext, input: HttpRequest, injection?: boolean): HttpRequest;
export declare function withIdentity<T>(context: ProbeContext, identity: TestIdentity, execute: (session: AuthSession) => Promise<T>): Promise<T>;
export declare function publicResponse(context: ProbeContext, response: HttpResponse): {
    responseId: string;
    url: string;
    method: string;
    status: number;
    body: {
        sha256: string;
        byteLength: number;
        truncated: boolean;
    };
    timings: {
        startedAt: string;
        firstByteMs: number;
        durationMs: number;
    };
};
export declare function publicComparison(result: ResponseComparison): ResponseComparison;
export declare function text(response: HttpResponse): string;
export declare class NormalizedResponseComparator implements ResponseComparator {
    compare(reference: HttpResponse, candidate: HttpResponse, markers?: readonly string[]): {
        statusDelta: number;
        bodyEqual: boolean | null;
        byteLengthDelta: number;
        durationDeltaMs: number;
        ownerMarkersMatch: boolean | null;
    };
}
export declare function validateInjection(context: InjectionContext): HttpRequest;
/** Mutate exactly one declared query or body parameter, preserving all other inputs. */
export declare function mutate(context: InjectionContext, input: HttpRequest, value: (original: string) => string): HttpRequest;

import type { HttpRequest, HttpResponse, HttpTransport, RequestExecutor, ResponseCollector, ResponseTimings, TransportRequest, TransportResponse } from './contracts.js';
import { RuntimeScope } from './safety.js';
export declare class NormalizedResponseCollector implements ResponseCollector {
    collect(request: {
        readonly url: string;
        readonly method: string;
    }, response: TransportResponse, timings: ResponseTimings): HttpResponse;
    evidence(response: HttpResponse): {
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
}
/** Node's single-hop client preserves separate Set-Cookie fields and never follows redirects. */
export declare class NodeHttpTransport implements HttpTransport {
    send(request: TransportRequest): Promise<TransportResponse>;
}
export interface HttpExecutorOptions {
    readonly baseUrl: string;
    readonly allowedOrigins: readonly string[];
    readonly timeoutMs?: number;
    readonly maxBodyBytes?: number;
    readonly maxRequestBytes?: number;
    readonly transport?: HttpTransport;
    readonly collector?: ResponseCollector;
}
export declare class DeterministicRequestExecutor implements RequestExecutor {
    readonly scope: RuntimeScope;
    private readonly timeoutMs;
    private readonly maxBodyBytes;
    private readonly maxRequestBytes;
    private readonly transport;
    private readonly collector;
    constructor(options: HttpExecutorOptions);
    execute(request: HttpRequest): Promise<HttpResponse>;
}

import type { HeaderAnalyzer, HttpResponse } from './contracts.js';
export declare function splitQuoted(value: string, separator: string): string[];
export declare class NormalizedHeaderAnalyzer implements HeaderAnalyzer {
    analyze(response: HttpResponse): Promise<{
        responseId: string;
        cors: {
            allowOrigin: string[];
            allowCredentials: (boolean | null)[];
            allowMethods: string[];
            allowHeaders: string[];
            exposeHeaders: string[];
            maxAge: (number | null)[];
        };
        security: Record<string, readonly string[]>;
        caching: {
            cacheControl: {
                name: string;
                value: string | null;
            }[];
            pragma: string[];
            vary: string[];
            expires: string[];
            age: (number | null)[];
        };
    }>;
}

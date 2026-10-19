import type { PolicyConfiguration, ToolPolicy } from './contracts.js';
export declare const severities: readonly ['info', 'low', 'medium', 'high', 'critical'];
export declare const risks: readonly ['passive', 'active'];
export declare function identifier(value: unknown): value is string;
export declare function parseUrl(value: string, base?: string): URL;
export declare function origins(values: readonly string[]): readonly string[];
export declare function methods(values: readonly string[]): readonly string[];
export declare function limit(value: number, maximum?: number): number;
export declare function freeze<T>(value: T): T;
export declare function configuration(input: PolicyConfiguration): {
    allowedOrigins: readonly string[];
    allowedMethods: readonly string[];
    tools: Record<string, ToolPolicy>;
    maxRisk: "active" | "passive";
    rateLimit: {
        maxRequests: number;
        windowMs: number;
    };
    maxRequestsPerExecution: number;
    executionTtlMs: number;
    approval: {
        risks: any[];
        severities: any[];
        ttlMs: number;
    };
    maxAuditRecords: number;
};

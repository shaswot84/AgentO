export declare function freeze<T>(value: T): T;
export declare function identifier(...values: unknown[]): string;
export declare function record(value: unknown): value is Record<string, unknown>;
export declare function exact(value: Record<string, unknown>, keys: readonly string[]): boolean;
export declare function strings(value: unknown): value is string[];
export declare function cancelled(signal?: AbortSignal): void;

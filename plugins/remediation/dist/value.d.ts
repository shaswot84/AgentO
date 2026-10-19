export declare const sha256: (value: string) => string;
export declare function canonical(value: unknown): string;
/** Reject executable objects, accessors, cycles, and oversized host input. */
export declare function copy<T>(value: T, depth?: number, seen?: Set<object>, budget?: {
    nodes: number;
}): T;
export declare function freeze<T>(value: T): T;
export declare function safePath(value: unknown): value is string;
export declare function strings(value: unknown): asserts value is readonly string[];

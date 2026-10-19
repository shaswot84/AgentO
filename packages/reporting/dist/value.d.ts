import type { Evidence } from '@agento/core';
import { type StoredEvidence } from '@agento/evidence';
/** Copy plain JSON without invoking getters, retaining provider instances, or accepting cycles. */
export declare function copy<T>(value: T, depth?: number, seen?: Set<object>, budget?: {
    nodes: number;
}): T;
export declare function freeze<T>(value: T): T;
export declare function canonical(value: unknown): string;
export declare const digest: (value: unknown) => string;
export declare const text: (value: unknown) => value is string;
export declare const sorted: (ids: readonly string[]) => string[];
export declare function strings(value: unknown): asserts value is readonly string[];
export declare function index<T extends {
    readonly id: string;
}>(values: readonly T[]): Map<string, T>;
export declare function checkedRecord(value: Evidence): StoredEvidence;
export declare function limit(value: number, max: number): number;

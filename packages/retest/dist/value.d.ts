import type { Evidence } from '@agento/core';
import { type StoredEvidence } from '@agento/evidence';
export declare const sha256: (text: string) => string;
export declare function canonical(value: unknown): string;
export declare function freeze<T>(value: T): T;
export declare function checkedRecord(value: Evidence): StoredEvidence;
export declare const safePath: (path: string) => boolean;
export declare function loopbackOrigin(value: string): string;

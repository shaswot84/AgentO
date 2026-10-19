import type { ScannerObservation } from './contracts.js';
export declare const hash: (value: string) => string;
export declare function record(value: unknown): Record<string, unknown>;
export declare function nuclei(text: string, url: string): ScannerObservation[];
export declare function zap(text: string, url: string): ScannerObservation[];
export declare function dalfox(text: string, url: string): ScannerObservation[];
/** Parse only structured result blocks, never arbitrary console sentences or payload text. */
export declare function sqlmap(text: string, url: string): ScannerObservation[];
export declare function freeze<T>(value: T): T;

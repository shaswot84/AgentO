import { type A02ScanOptions, type A02ScanReport } from './contracts.js';
/** Bounded host composition for three rules. No vulnerability logic is implemented here. */
export declare function runA02Scan(options: A02ScanOptions): Promise<A02ScanReport>;

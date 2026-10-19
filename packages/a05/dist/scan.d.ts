import { type A05ScanOptions, type A05ScanReport } from './contracts.js';
/** Bounded host composition. Rules retain responsibility for every security verdict. */
export declare function runA05Scan(options: A05ScanOptions): Promise<A05ScanReport>;

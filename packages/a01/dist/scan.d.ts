import { type A01ScanOptions, type A01ScanReport } from './contracts.js';
/** Host composition only. The probe collects comparisons; the CWE rules decide verdicts. */
export declare function runA01Scan(options: A01ScanOptions): Promise<A01ScanReport>;

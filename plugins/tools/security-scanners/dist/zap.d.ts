import type { SecurityScannerRequest } from '@agento/runtime';
import { ScannerAdapter } from './adapter.js';
import type { ScannerOptions } from './contracts.js';
/** Dedicated command-mode instance; passive scanning of the explicitly requested exchange. */
export declare class ZapAdapter extends ScannerAdapter {
    readonly id = "zap-adapter";
    constructor(options?: ScannerOptions);
    protected prepare(input: SecurityScannerRequest, url: string, directory: string): Promise<{
        args: string[];
        reportFile: string;
    }>;
    protected normalize(text: string, url: string): import("./contracts.js").ScannerObservation[];
}

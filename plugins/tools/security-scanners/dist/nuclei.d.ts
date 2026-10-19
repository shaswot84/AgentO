import type { SecurityScannerRequest } from '@agento/runtime';
import { ScannerAdapter } from './adapter.js';
import type { NucleiOptions } from './contracts.js';
export declare class NucleiAdapter extends ScannerAdapter {
    readonly id = "nuclei-adapter";
    private readonly templates;
    constructor(options?: NucleiOptions);
    protected prepare(input: SecurityScannerRequest, url: string, directory: string): Promise<{
        args: string[];
    }>;
    protected normalize(text: string, url: string): import("./contracts.js").ScannerObservation[];
}

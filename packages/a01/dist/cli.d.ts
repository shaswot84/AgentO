#!/usr/bin/env node
/** Credentials are read only during a guarded login, never copied into the report. */
export declare function scanFile(configPath: string): Promise<import("./contracts.js").A01ScanReport>;

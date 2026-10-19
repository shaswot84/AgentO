#!/usr/bin/env node
/** JSON contains environment variable names, never passwords. Config paths resolve beside the config file. */
export declare function scanFile(configPath: string): Promise<import("./contracts.js").A02ScanReport>;

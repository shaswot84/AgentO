import type { RetestResult } from '@agento/core';
import { type NormalizedProbeEvidence } from '@agento/cwe';
import { type RetestInput, type RetestOptions } from './contracts.js';
/** No execution occurs until the original finding, retained proof, plan and patch bindings pass. */
export declare class RetestEngine {
    #private;
    constructor(options: RetestOptions);
    run(input: RetestInput, signal?: AbortSignal): Promise<RetestResult>;
}
export declare function probeTargets(probe: NormalizedProbeEvidence): string[];

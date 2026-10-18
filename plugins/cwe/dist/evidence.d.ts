import type { Evidence } from '@agento/core';
import type { NormalizedProbeEvidence } from './contracts.js';
/** Validate at the core JSON boundary as well as at the public typed evaluator boundary. */
export declare function isProbeEvidence(value: unknown): value is NormalizedProbeEvidence;
export declare function toCoreEvidence(probe: NormalizedProbeEvidence, endpointId?: string): Evidence;
export declare function fromCoreEvidence(item: Evidence): NormalizedProbeEvidence | undefined;

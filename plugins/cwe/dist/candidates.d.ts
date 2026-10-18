import type { AnalysisContext, Endpoint, Evidence, Resource } from '@agento/core';
import type { ModelFact } from '@agento/security-model';
import type { CWEMetadata, CWEHypothesis, RuleOptions } from './contracts.js';
export interface CandidateContext {
    readonly endpoint: Endpoint;
    readonly hasSignal: boolean;
    readonly facts: readonly ModelFact[];
    readonly resources: readonly Resource[];
    readonly parameters: Endpoint['parameters'];
}
export declare function detect(metadata: CWEMetadata, context: AnalysisContext, options: RuleOptions, accepts: (candidate: CandidateContext) => boolean): readonly CWEHypothesis[];
export declare function referencesMatch(item: Evidence, endpointId: string | undefined, context: AnalysisContext): boolean;

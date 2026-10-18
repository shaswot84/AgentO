import type { CrossOriginEvidence } from '@agento/runtime';
import { EvidenceCWEPlugin } from './base.js';
import type { EvaluationScope, RuleOptions } from './contracts.js';
export declare class CWE942Plugin extends EvidenceCWEPlugin<'cross-origin'> {
    constructor(options?: RuleOptions);
    protected isCandidate(): boolean;
    protected interpret(evidence: CrossOriginEvidence, scope: EvaluationScope): import("./shared.js").Decision;
}

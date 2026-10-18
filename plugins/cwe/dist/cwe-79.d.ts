import type { XSSEvidence } from '@agento/runtime';
import { EvidenceCWEPlugin } from './base.js';
import type { EvaluationScope, RuleOptions } from './contracts.js';
import type { CandidateContext } from './candidates.js';
export declare class CWE79Plugin extends EvidenceCWEPlugin<'xss'> {
    constructor(options?: RuleOptions);
    protected isCandidate(candidate: CandidateContext): boolean;
    protected interpret(evidence: XSSEvidence, scope: EvaluationScope): import("./shared.js").Decision;
}

import type { AuthorizationEvidence } from '@agento/runtime';
import { EvidenceCWEPlugin } from './base.js';
import type { EvaluationScope, RuleOptions } from './contracts.js';
import type { CandidateContext } from './candidates.js';
export declare class CWE639Plugin extends EvidenceCWEPlugin<'authorization'> {
    constructor(options?: RuleOptions);
    protected isCandidate(candidate: CandidateContext): boolean;
    protected interpret(evidence: AuthorizationEvidence, scope: EvaluationScope): import("./shared.js").Decision;
}

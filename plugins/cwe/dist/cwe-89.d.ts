import type { SQLInjectionEvidence } from '@agento/runtime';
import { EvidenceCWEPlugin } from './base.js';
import type { EvaluationScope, RuleOptions } from './contracts.js';
import type { CandidateContext } from './candidates.js';
export declare class CWE89Plugin extends EvidenceCWEPlugin<'sql-injection'> {
    constructor(options?: RuleOptions);
    protected isCandidate(candidate: CandidateContext): boolean;
    protected interpret(evidence: SQLInjectionEvidence, scope: EvaluationScope): import("./shared.js").Decision;
}

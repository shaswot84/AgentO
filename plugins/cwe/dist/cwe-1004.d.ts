import { EvidenceCWEPlugin } from './base.js';
import type { CandidateContext } from './candidates.js';
import type { EvaluationScope, RuleOptions } from './contracts.js';
import type { CookieSecurityEvidence } from '@agento/runtime';
export declare class CWE1004Plugin extends EvidenceCWEPlugin<'cookie-security'> {
    constructor(options?: RuleOptions);
    protected interpret(evidence: CookieSecurityEvidence, scope: EvaluationScope): import("./shared.js").Decision;
    protected isCandidate(candidate: CandidateContext): boolean;
}

import type { CookieSecurityEvidence } from '@agento/runtime';
import type { EvaluationScope } from './contracts.js';
import type { CandidateContext } from './candidates.js';
import { type Decision } from './shared.js';
export declare function cookieCandidate(candidate: CandidateContext): boolean;
export declare function cookieDecision(evidence: CookieSecurityEvidence, scope: EvaluationScope, attribute: 'httpOnly' | 'secure'): Decision;

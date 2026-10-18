import type { HypothesisContextRule } from './contracts.js';
/** Candidate strength is about investigation priority, never proof or finding confidence. */
export declare function createDefaultHypothesisRules(options?: {
    readonly sensitiveCookieNames?: readonly string[];
    readonly untrustedOrigins?: readonly string[];
}): readonly HypothesisContextRule[];

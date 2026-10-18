import type { AnalysisContext, ReasoningModel, SecurityHypothesis } from '@agento/core';
import type { GroundedHypothesis, HypothesisEngineOptions, HypothesisResult } from './contracts.js';
/** Generates hypotheses only. It never creates plans, dispatches probes, or interprets vulnerability proof. */
export declare class SecurityHypothesisEngine implements ReasoningModel {
    readonly id = "agento-hypothesis-engine";
    readonly capabilities: readonly string[];
    private readonly rules;
    private readonly plugins;
    private readonly provider;
    private readonly limits;
    constructor(options: HypothesisEngineOptions);
    generate(context: AnalysisContext, options?: {
        readonly signal?: AbortSignal;
    }): Promise<HypothesisResult>;
    /** Existing core reasoning port: keeps registered candidate IDs so plugins can rebind their own plans. */
    reviewHypotheses(context: AnalysisContext, hypotheses: readonly SecurityHypothesis[]): Promise<readonly GroundedHypothesis[]>;
    private process;
}

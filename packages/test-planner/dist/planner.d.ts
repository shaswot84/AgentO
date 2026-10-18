import type { AnalysisContext, SecurityHypothesis, TestPlanner } from '@agento/core';
import type { PlanningBindings, PlanningResult, StructuredTestPlan, TestPlannerOptions } from './contracts.js';
/** Pure planning: no sessions, transport, capability selection, evidence collection, or verdicts. */
export declare class SecurityTestPlanner implements TestPlanner {
    private readonly plugins;
    private readonly maxPlans;
    constructor(options: TestPlannerOptions);
    /** The core port exposes only plans with satisfied planning prerequisites. Inspect plan() for blocked drafts. */
    generateTests(context: AnalysisContext, hypothesis: SecurityHypothesis): Promise<readonly StructuredTestPlan[]>;
    plan(input: AnalysisContext, supplied: SecurityHypothesis, suppliedBindings?: PlanningBindings): Promise<PlanningResult>;
}

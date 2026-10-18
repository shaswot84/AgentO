import type { AnalysisContext, SecurityHypothesis } from '@agento/core';
import type { ApplicationSecurityModel } from '@agento/security-model';
import type { HypothesisContext, HypothesisSupport } from './contracts.js';
export declare function applicationModel(context: AnalysisContext): ApplicationSecurityModel;
export declare function gatherContext(model: ApplicationSecurityModel, candidate: SecurityHypothesis): HypothesisContext | undefined;
/** Membership in the endpoint's context is required; an arbitrary known project ID is insufficient. */
export declare function validateSupports(context: HypothesisContext, supports: readonly HypothesisSupport[]): readonly HypothesisSupport[];

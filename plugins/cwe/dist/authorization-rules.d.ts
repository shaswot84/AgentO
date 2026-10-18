import type { AuthorizationEvidence } from '@agento/runtime';
import type { EvaluationScope } from './contracts.js';
import { type Decision } from './shared.js';
export declare function authorizationContext(evidence: AuthorizationEvidence, scope: EvaluationScope): Decision | undefined;
export declare function leaked(evidence: AuthorizationEvidence, anonymous: boolean): boolean;
export declare function denied(status: number): boolean;
export declare const accessConfirmed: () => Decision;

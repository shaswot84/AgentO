import type { PlannedStep, PlanScope, ProbeId, VerificationCriteria } from './contracts.js';
export declare function steps(probe: ProbeId, scope: PlanScope): readonly PlannedStep[];
export declare function verification(probe: ProbeId, cweId: string, scope: PlanScope): VerificationCriteria;

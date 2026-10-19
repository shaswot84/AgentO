import type { CapabilityResolution, SelectionReport } from '@agento/capability-registry';
import type { PolicyAuditRecord, PolicyConfiguration, PolicyDecision, PolicyExecution, PolicyOptions, PolicyRequest } from './contracts.js';
/** Local policy authority. Approval methods and adapter registrations belong to the trusted host. */
export declare class PolicyEngine {
    private readonly options;
    private readonly config;
    private readonly records;
    private readonly pending;
    private readonly approvals;
    private readonly requests;
    private readonly toolContext;
    private lastTime;
    constructor(config: PolicyConfiguration, options?: PolicyOptions);
    audit(): readonly PolicyAuditRecord[];
    review(request: PolicyRequest, selection: SelectionReport): PolicyDecision;
    /** Call only after a human accepts the reviewed plan. No target-supplied approval data is accepted. */
    approve(decisionId: string, approverId: string): string;
    revokeApproval(approvalId: string): void;
    run<T>(request: PolicyRequest, resolution: CapabilityResolution, execute: (execution: PolicyExecution) => Promise<T>, options?: {
        readonly approvalId?: string;
        readonly signal?: AbortSignal;
    }): Promise<T>;
    private check;
    private needsApproval;
    private deny;
    private record;
    private time;
    private prune;
}

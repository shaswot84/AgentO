import type { NormalizedProbeEvidence, ProbeTestPlan } from '@agento/cwe';
import { type RegressionResult, type RetestEnvironment, type RetestInput, type RetestSession } from './contracts.js';
export interface LocalTarget {
    readonly baseUrl: string;
    dispose(): Promise<void>;
}
/** Explicit host ports. Never infer shell commands, credentials or private probe inputs from patch prose. */
export interface LocalPatchOptions {
    readonly sourceDirectory: string;
    /** Only these source trees/files are copied. No symlinks, Git metadata or node_modules. */
    readonly include: readonly string[];
    /** Optional installed development dependencies linked into the temporary copy. */
    readonly dependencyDirectory?: string;
    start(directory: string, signal: AbortSignal): Promise<LocalTarget>;
    regression(directory: string, input: RetestInput, signal: AbortSignal): Promise<RegressionResult>;
    replay(target: LocalTarget, plan: ProbeTestPlan, targetUrl: string, signal: AbortSignal): Promise<NormalizedProbeEvidence>;
}
/** Copies source, checks every reviewed hash, applies only ordinary unified hunks, then starts the host. */
export declare class LocalPatchEnvironment implements RetestEnvironment {
    #private;
    constructor(options: LocalPatchOptions);
    create(input: RetestInput, signal: AbortSignal): Promise<RetestSession>;
}

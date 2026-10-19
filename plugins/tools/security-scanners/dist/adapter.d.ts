import type { AnalysisContext, CWEId, Evidence, SecurityScanner, SecurityTestPlan, SecurityTestResult } from '@agento/core';
import type { CapabilityCatalog, SecurityScannerPort, SecurityScannerRequest } from '@agento/runtime';
import { ScannerError } from './contracts.js';
import type { ScannerObservation, ScannerOptions } from './contracts.js';
export interface Invocation {
    readonly args: readonly string[];
    readonly reportFile?: string;
    readonly acceptedExits?: readonly number[];
}
export declare abstract class ScannerAdapter implements SecurityScanner, SecurityScannerPort {
    protected readonly options: ScannerOptions;
    private readonly command;
    abstract readonly id: string;
    readonly capabilities: readonly string[];
    protected readonly timeoutMs: number;
    protected readonly maxOutputBytes: number;
    protected readonly headPreflight: boolean;
    constructor(options: ScannerOptions, command: string);
    protected abstract prepare(input: SecurityScannerRequest, url: string, directory: string): Promise<Invocation>;
    protected abstract normalize(text: string, url: string): readonly ScannerObservation[];
    registration(): {
        metadata: {
            id: string;
            capabilities: readonly (keyof CapabilityCatalog)[];
            supportedCwes: 'all' | readonly CWEId[];
            protocols: readonly ('http' | 'https')[];
            risk: 'active';
        };
        capabilities: Partial<CapabilityCatalog>;
        executable: string;
        checkAvailability(signal: AbortSignal): Promise<boolean>;
    };
    execute(context: AnalysisContext, plan: SecurityTestPlan): Promise<SecurityTestResult>;
    run(input: SecurityScannerRequest): Promise<SecurityTestResult>;
    private environment;
    protected result(planId: string, evidence: readonly Evidence[], code?: ScannerError['code']): SecurityTestResult;
}

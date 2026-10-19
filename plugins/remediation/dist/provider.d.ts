import type { AnalysisContext, Finding, RemediationProvider } from '@agento/core';
import { type ExpressRemediationOptions, type PreparedRemediation } from './contracts.js';
/** Pure suggestion provider. Reviewed recipes are deliberately narrower than arbitrary Express code. */
export declare class ExpressRemediationProvider implements RemediationProvider {
    #private;
    readonly id = "express-remediation";
    readonly capabilities: readonly string[];
    constructor(options: ExpressRemediationOptions);
    suggest(context: AnalysisContext, finding: Finding): Promise<PreparedRemediation>;
}

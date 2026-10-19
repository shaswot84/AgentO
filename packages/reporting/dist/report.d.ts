import type { FindingStatus, Severity } from '@agento/core';
import { type StoredEvidence } from '@agento/evidence';
import { type ReportInput, type ReportingOptions, type SecurityReport } from './contracts.js';
export declare const FINDING_STATUSES: readonly FindingStatus[];
export declare const SEVERITIES: readonly Severity[];
export declare function evidenceClass(record: StoredEvidence): 'static' | 'runtime' | 'other';
/** Presentation only: consumes a trusted assessment and never executes tests or chooses a verdict. */
export declare function buildSecurityReport(input: ReportInput, options: ReportingOptions): SecurityReport;

import type { HttpResponseEvidence } from '@agento/runtime';
import type { CWEVerdict, EvaluationScope } from './contracts.js';
export declare function freeze<T>(value: T): T;
export declare function identifier(...parts: unknown[]): string;
export declare function url(value: string): URL;
/** Query values are private inputs, not endpoint identity. Parameter binding is checked separately. */
export declare function sameTarget(response: HttpResponseEvidence, scope: EvaluationScope): boolean;
export declare function sameExchangeTarget(a: HttpResponseEvidence, b: HttpResponseEvidence): boolean;
export declare function successful(response: HttpResponseEvidence): boolean;
export declare function complete(response: HttpResponseEvidence): boolean;
export type Decision = Pick<CWEVerdict, 'status' | 'summary'> & {
    readonly limitations?: readonly string[];
};
export declare const unknown: (summary: string, ...limitations: string[]) => Decision;
export declare const confirmed: (summary: string) => Decision;
export declare const rejected: (summary: string) => Decision;

import type { InjectionContext, SecurityProbe, SQLInjectionEvidence } from './contracts.js';
export declare class SQLInjectionProbe implements SecurityProbe<InjectionContext, SQLInjectionEvidence> {
    metadata(): import("./contracts.js").ProbeMetadata;
    supports(context: InjectionContext): boolean;
    execute(input: InjectionContext): Promise<SQLInjectionEvidence>;
}

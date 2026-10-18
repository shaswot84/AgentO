import type { InjectionContext, SecurityProbe, XSSEvidence } from './contracts.js';
export declare class XSSProbe implements SecurityProbe<InjectionContext, XSSEvidence> {
    metadata(): import("./contracts.js").ProbeMetadata;
    supports(context: InjectionContext): boolean;
    execute(input: InjectionContext): Promise<XSSEvidence>;
}

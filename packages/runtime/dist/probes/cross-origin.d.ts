import type { CrossOriginContext, CrossOriginEvidence, SecurityProbe } from './contracts.js';
export declare class CrossOriginProbe implements SecurityProbe<CrossOriginContext, CrossOriginEvidence> {
    metadata(): import("./contracts.js").ProbeMetadata;
    supports(context: CrossOriginContext): boolean;
    execute(input: CrossOriginContext): Promise<CrossOriginEvidence>;
}

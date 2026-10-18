import type { AuthorizationContext, AuthorizationEvidence, SecurityProbe } from './contracts.js';
export declare class AuthorizationProbe implements SecurityProbe<AuthorizationContext, AuthorizationEvidence> {
    metadata(): import("./contracts.js").ProbeMetadata;
    supports(context: AuthorizationContext): boolean;
    execute(input: AuthorizationContext): Promise<AuthorizationEvidence>;
}

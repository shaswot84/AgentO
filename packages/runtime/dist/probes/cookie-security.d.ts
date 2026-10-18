import type { CookieSecurityContext, CookieSecurityEvidence, SecurityProbe } from './contracts.js';
export declare class CookieSecurityProbe implements SecurityProbe<CookieSecurityContext, CookieSecurityEvidence> {
    metadata(): import("./contracts.js").ProbeMetadata;
    supports(context: CookieSecurityContext): boolean;
    execute(input: CookieSecurityContext): Promise<CookieSecurityEvidence>;
}

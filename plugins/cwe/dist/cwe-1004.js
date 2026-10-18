import { EvidenceCWEPlugin } from './base.js';
import { cookieCandidate, cookieDecision } from './cookie-rules.js';
export class CWE1004Plugin extends EvidenceCWEPlugin {
    constructor(options = {}) {
        super({ cweId: 'CWE-1004', title: 'Sensitive cookie without HttpOnly',
            owaspCategory: 'A02:2025', severity: 'medium', probeId: 'cookie-security',
            requiredCapabilities: ['request-executor', 'response-collector', 'cookie-analyzer'],
            optionalCapabilities: ['authentication-manager', 'cookie-inspector', 'browser-controller'] }, options);
    }
    interpret(evidence, scope) { return cookieDecision(evidence, scope, 'httpOnly'); }
    isCandidate(candidate) { return cookieCandidate(candidate); }
}

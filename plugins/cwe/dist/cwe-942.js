import { EvidenceCWEPlugin } from './base.js';
import { confirmed, rejected, sameTarget, successful, unknown } from './shared.js';
export class CWE942Plugin extends EvidenceCWEPlugin {
    constructor(options = {}) {
        super({ cweId: 'CWE-942', title: 'Permissive cross-origin policy',
            owaspCategory: 'A02:2025', severity: 'medium', probeId: 'cross-origin',
            requiredCapabilities: ['request-executor', 'response-collector', 'header-analyzer'],
            optionalCapabilities: ['authentication-manager'] }, options);
    }
    isCandidate() { return true; }
    interpret(evidence, scope) {
        const untrusted = new Set(scope.untrustedOrigins ?? []);
        const observations = evidence.observations.filter(item => untrusted.has(item.requestedOrigin)
            && item.requestedOrigin !== new URL(scope.targetUrl).origin && sameTarget(item.actual.response, scope));
        if (!observations.length)
            return unknown('No matching observation of an explicitly untrusted origin is available.');
        for (const item of observations) {
            const cors = item.actual.cors;
            if (!successful(item.actual.response) || cors.allowOrigin.length !== 1 || cors.allowCredentials.length !== 1 || cors.allowCredentials[0] !== true)
                continue;
            if (cors.allowOrigin[0] === '*')
                return { ...confirmed('The response declares a wildcard cross-origin policy together with credentials.'),
                    limitations: ['This confirms a policy configuration issue; browsers reject credentialed wildcard reads, so data disclosure is not proven.'] };
            if (cors.allowOrigin[0] === item.requestedOrigin && item.credentialMode === 'session' && item.identityId !== null) {
                return confirmed('An authenticated response permits an explicitly untrusted origin with credentials.');
            }
        }
        if (evidence.outcome === 'COMPLETED' && observations.every(item => successful(item.actual.response)
            && item.actual.cors.allowOrigin.length <= 1 && !item.actual.cors.allowOrigin.includes(item.requestedOrigin)
            && !item.actual.cors.allowOrigin.includes('*')))
            return rejected('Observed responses do not grant the declared untrusted origins access.');
        return unknown('A permissive credentialed cross-origin response policy was not established.', 'Preflight headers alone do not prove an actual response permits access.');
    }
}

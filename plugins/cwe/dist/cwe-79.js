import { EvidenceCWEPlugin } from './base.js';
import { complete, confirmed, rejected, sameExchangeTarget, sameTarget, unknown } from './shared.js';
export class CWE79Plugin extends EvidenceCWEPlugin {
    constructor(options = {}) {
        super({ cweId: 'CWE-79', title: 'Cross-site scripting',
            owaspCategory: 'A05:2025', severity: 'high', probeId: 'xss',
            requiredCapabilities: ['request-executor', 'response-collector'],
            optionalCapabilities: ['authentication-manager', 'browser-controller', 'xss-scanner'] }, options);
    }
    isCandidate(candidate) { return candidate.hasSignal || candidate.parameters.length > 0; }
    interpret(evidence, scope) {
        const location = evidence.parameter.location === 'query' ? 'query' : 'body';
        if (!scope.parameter || evidence.parameter.name !== scope.parameter.name || location !== scope.parameter.location
            || ![evidence.baseline, evidence.injected].every(response => sameTarget(response, scope))
            || !sameExchangeTarget(evidence.baseline, evidence.injected))
            return unknown('XSS evidence is not bound to this target parameter.');
        if (evidence.executionConfirmed === true)
            return confirmed('The probe observed script execution attributable to the tested injection point.');
        if (evidence.outcome === 'COMPLETED' && complete(evidence.injected) && complete(evidence.baseline)
            && evidence.executionConfirmed === false && evidence.domSinkReached === false)
            return rejected('The completed investigation observed neither execution nor a DOM sink.');
        return unknown('Script execution was not established.', 'Reflection, lexical HTML contexts and visible canaries alone do not prove XSS.');
    }
}

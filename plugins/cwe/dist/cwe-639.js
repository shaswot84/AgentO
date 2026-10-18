import { EvidenceCWEPlugin } from './base.js';
import { accessConfirmed, authorizationContext, denied, leaked } from './authorization-rules.js';
import { rejected, unknown } from './shared.js';
export class CWE639Plugin extends EvidenceCWEPlugin {
    constructor(options = {}) {
        super({ cweId: 'CWE-639', title: 'Authorization bypass through a user-controlled key',
            owaspCategory: 'A01:2025', severity: 'high', probeId: 'authorization',
            requiredCapabilities: ['request-executor', 'response-collector', 'authentication-manager', 'response-comparator'],
            optionalCapabilities: ['browser-controller'] }, options);
    }
    isCandidate(candidate) {
        return candidate.hasSignal || candidate.resources.some(resource => !!resource.ownerIdentityId)
            || candidate.facts.some(fact => fact.kind === 'ownership');
    }
    interpret(evidence, scope) {
        const unavailable = authorizationContext(evidence, scope);
        if (unavailable)
            return unavailable;
        if (!scope.authorization.attackerIsUnauthorized)
            return unknown('The second identity is not declared unauthorized for this resource.');
        if (leaked(evidence, false))
            return accessConfirmed();
        if (evidence.outcome === 'COMPLETED' && denied(evidence.attacker.status))
            return rejected('The forbidden identity was denied resource access.');
        return unknown('Cross-identity resource disclosure was not established.', 'Status or body equality alone does not prove owner-specific disclosure.');
    }
}

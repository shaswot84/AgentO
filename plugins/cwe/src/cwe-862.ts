import type { AuthorizationEvidence } from '@agento/runtime';
import { EvidenceCWEPlugin } from './base.js';
import type { EvaluationScope, RuleOptions } from './contracts.js';
import { accessConfirmed, authorizationContext, denied, leaked } from './authorization-rules.js';
import { rejected, unknown } from './shared.js';
import type { CandidateContext } from './candidates.js';

export class CWE862Plugin extends EvidenceCWEPlugin<'authorization'> {
  constructor(options: RuleOptions = {}) { super({ cweId: 'CWE-862', title: 'Missing authorization on a protected resource',
    owaspCategory: 'A01:2025', severity: 'high', probeId: 'authorization',
    requiredCapabilities: ['request-executor', 'response-collector', 'authentication-manager', 'response-comparator'],
    optionalCapabilities: ['browser-controller'] }, options); }
  protected isCandidate(candidate: CandidateContext) {
    return candidate.hasSignal || candidate.endpoint.authentication === 'required' || candidate.endpoint.roles.length > 0;
  }
  protected interpret(evidence: AuthorizationEvidence, scope: EvaluationScope) {
    const unavailable = authorizationContext(evidence, scope);
    if (unavailable) return unavailable;
    const policy = scope.authorization!;
    if (policy.anonymousIsUnauthorized && leaked(evidence, true)
      || policy.attackerIsUnauthorized && leaked(evidence, false)) return accessConfirmed();
    const tested = [policy.anonymousIsUnauthorized ? evidence.anonymous : null,
      policy.attackerIsUnauthorized ? evidence.attacker : null].filter(response => response !== null);
    if (tested.length && evidence.outcome === 'COMPLETED' && tested.every(response => denied(response.status))) {
      return rejected('All identities declared unauthorized were denied access to the protected resource.');
    }
    return unknown('Protected resource access by an unauthorized identity was not established.');
  }
}

import type { XSSEvidence } from '@agento/runtime';
import { EvidenceCWEPlugin } from './base.js';
import type { EvaluationScope, RuleOptions } from './contracts.js';
import { complete, confirmed, rejected, sameExchangeTarget, sameTarget, unknown } from './shared.js';
import type { CandidateContext } from './candidates.js';

export class CWE79Plugin extends EvidenceCWEPlugin<'xss'> {
  constructor(options: RuleOptions = {}) { super({ cweId: 'CWE-79', title: 'Cross-site scripting',
    owaspCategory: 'A05:2025', severity: 'high', probeId: 'xss',
    requiredCapabilities: ['request-executor', 'response-collector'],
    optionalCapabilities: ['authentication-manager', 'browser-controller', 'xss-scanner'] }, options); }
  protected isCandidate(candidate: CandidateContext) { return candidate.hasSignal || candidate.parameters.length > 0; }
  protected interpret(evidence: XSSEvidence, scope: EvaluationScope) {
    const location = evidence.parameter.location === 'query' ? 'query' : 'body';
    if (!scope.parameter || evidence.parameter.name !== scope.parameter.name || location !== scope.parameter.location
      || ![evidence.baseline, evidence.injected].every(response => sameTarget(response, scope))
      || !sameExchangeTarget(evidence.baseline, evidence.injected)) return unknown('XSS evidence is not bound to this target parameter.');
    if (evidence.executionConfirmed === true) return confirmed('The probe observed script execution attributable to the tested injection point.');
    if (evidence.outcome === 'COMPLETED' && complete(evidence.injected) && complete(evidence.baseline)
      && evidence.executionConfirmed === false && evidence.domSinkReached === false) return rejected('The completed investigation observed neither execution nor a DOM sink.');
    return unknown('Script execution was not established.', 'Reflection, lexical HTML contexts and visible canaries alone do not prove XSS.');
  }
}

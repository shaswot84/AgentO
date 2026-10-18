import { EvidenceCWEPlugin } from './base.js';
import { cookieCandidate, cookieDecision } from './cookie-rules.js';
import type { CandidateContext } from './candidates.js';
import type { EvaluationScope, RuleOptions } from './contracts.js';
import type { CookieSecurityEvidence } from '@agento/runtime';

export class CWE1004Plugin extends EvidenceCWEPlugin<'cookie-security'> {
  constructor(options: RuleOptions = {}) { super({ cweId: 'CWE-1004', title: 'Sensitive cookie without HttpOnly',
    owaspCategory: 'A02:2025', severity: 'medium', probeId: 'cookie-security',
    requiredCapabilities: ['request-executor', 'response-collector', 'cookie-analyzer'],
    optionalCapabilities: ['authentication-manager', 'cookie-inspector', 'browser-controller'] }, options); }
  protected interpret(evidence: CookieSecurityEvidence, scope: EvaluationScope) { return cookieDecision(evidence, scope, 'httpOnly'); }
  protected isCandidate(candidate: CandidateContext) { return cookieCandidate(candidate); }
}

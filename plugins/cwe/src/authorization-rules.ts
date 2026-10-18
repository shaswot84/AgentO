import type { AuthorizationEvidence } from '@agento/runtime';
import type { EvaluationScope } from './contracts.js';
import { complete, confirmed, sameExchangeTarget, sameTarget, successful, unknown, type Decision } from './shared.js';

export function authorizationContext(evidence: AuthorizationEvidence, scope: EvaluationScope): Decision | undefined {
  const policy = scope.authorization;
  if (!policy || policy.resourceId !== evidence.resourceId || policy.ownerIdentityId !== evidence.ownerIdentityId
    || policy.attackerIdentityId !== evidence.attackerIdentityId) return unknown('An explicit matching resource and identity access policy is required.');
  if (![evidence.owner, evidence.attacker, evidence.anonymous].every(response => sameTarget(response, scope)
    && sameExchangeTarget(evidence.owner, response))) return unknown('Authorization responses do not describe the same resource request.');
  if (!successful(evidence.owner) || !complete(evidence.owner)) return unknown('The authorized owner baseline was not established.');
  return;
}
export function leaked(evidence: AuthorizationEvidence, anonymous: boolean): boolean {
  const response = anonymous ? evidence.anonymous : evidence.attacker;
  const comparison = anonymous ? evidence.anonymousComparison : evidence.attackerComparison;
  return successful(response) && complete(response) && comparison.ownerMarkersMatch === true;
}
export function denied(status: number): boolean { return [401, 403, 404].includes(status); }
export const accessConfirmed = () => confirmed('A forbidden identity received content matching the authorized owner resource.');

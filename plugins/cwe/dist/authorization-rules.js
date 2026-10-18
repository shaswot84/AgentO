import { complete, confirmed, sameExchangeTarget, sameTarget, successful, unknown } from './shared.js';
export function authorizationContext(evidence, scope) {
    const policy = scope.authorization;
    if (!policy || policy.resourceId !== evidence.resourceId || policy.ownerIdentityId !== evidence.ownerIdentityId
        || policy.attackerIdentityId !== evidence.attackerIdentityId)
        return unknown('An explicit matching resource and identity access policy is required.');
    if (![evidence.owner, evidence.attacker, evidence.anonymous].every(response => sameTarget(response, scope)
        && sameExchangeTarget(evidence.owner, response)))
        return unknown('Authorization responses do not describe the same resource request.');
    if (!successful(evidence.owner) || !complete(evidence.owner))
        return unknown('The authorized owner baseline was not established.');
    return;
}
export function leaked(evidence, anonymous) {
    const response = anonymous ? evidence.anonymous : evidence.attacker;
    const comparison = anonymous ? evidence.anonymousComparison : evidence.attackerComparison;
    return successful(response) && complete(response) && comparison.ownerMarkersMatch === true;
}
export function denied(status) { return [401, 403, 404].includes(status); }
export const accessConfirmed = () => confirmed('A forbidden identity received content matching the authorized owner resource.');

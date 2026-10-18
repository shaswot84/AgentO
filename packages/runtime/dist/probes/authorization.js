import { freeze, RuntimeError } from '../safety.js';
import { assertActive, available, base, check, metadata, publicComparison, publicResponse, request, sanitized, snapshot, withIdentity } from './shared.js';
export class AuthorizationProbe {
    metadata() { return metadata('authorization', ['request-executor', 'response-collector', 'authentication-manager', 'response-comparator']); }
    supports(context) {
        return available(context, this.metadata().requiredCapabilities) && Boolean(context.resource || context.discoverResource);
    }
    execute(input) {
        return sanitized(async () => {
            const context = snapshot(input), owner = structuredClone(input.owner), attacker = structuredClone(input.attacker);
            const initial = input.resource ? copyResource(input.resource) : undefined;
            check(context, this.supports(context));
            if (!owner.id || !attacker.id || owner.id === attacker.id || owner.authentication === 'anonymous'
                || attacker.authentication === 'anonymous' || Boolean(initial) === Boolean(input.discoverResource))
                throw new RuntimeError('invalid-request');
            // Known targets are validated before authentication or any outbound operation.
            if (initial)
                validateResource(context, initial, owner.id);
            return withIdentity(context, owner, async (ownerSession) => {
                const resource = initial ?? copyResource(await context.discoverResource(ownerSession));
                const prepared = validateResource(context, resource, owner.id);
                const ownerResponse = await ownerSession.http.execute(prepared);
                assertActive(context);
                return withIdentity(context, attacker, async (attackerSession) => {
                    if (attackerSession.id === ownerSession.id)
                        throw new RuntimeError('authentication-failed');
                    const attackerResponse = await attackerSession.http.execute(prepared);
                    assertActive(context);
                    const anonymous = await context.capabilities.get('request-executor').execute(prepared);
                    const comparator = context.capabilities.get('response-comparator');
                    const diagnostics = [ownerResponse, attackerResponse, anonymous].some(response => response.body.truncated)
                        ? ['response-truncated'] : [];
                    return freeze({ ...base(context, this.metadata().id, diagnostics), resourceId: resource.id,
                        ownerIdentityId: owner.id, attackerIdentityId: attacker.id,
                        owner: publicResponse(context, ownerResponse), attacker: publicResponse(context, attackerResponse),
                        anonymous: publicResponse(context, anonymous),
                        attackerComparison: publicComparison(comparator.compare(ownerResponse, attackerResponse, resource.ownerMarkers)),
                        anonymousComparison: publicComparison(comparator.compare(ownerResponse, anonymous, resource.ownerMarkers)) });
                });
            });
        });
    }
}
function copyResource(resource) {
    return { ...resource, request: { ...resource.request, headers: { ...resource.request.headers } },
        ...(resource.ownerMarkers ? { ownerMarkers: [...resource.ownerMarkers] } : {}) };
}
function validateResource(context, resource, ownerId) {
    if (!resource.id || resource.ownerIdentityId !== ownerId || (resource.ownerMarkers?.length ?? 0) > 16
        || resource.ownerMarkers?.some(marker => !marker || marker.length > 4096))
        throw new RuntimeError('invalid-request');
    return request(context, resource.request);
}

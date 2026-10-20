import { isEndpointTestable } from '@agento/core';
import { freeze, identifier, url } from './shared.js';
export function detect(metadata, context, options, accepts) {
    const model = context;
    const hypotheses = [];
    const evidence = new Set(context.evidence.filter(item => item.projectId === context.project.id).map(item => item.id));
    for (const endpoint of context.endpoints) {
        if (!isEndpointTestable(endpoint))
            continue;
        const target = targetUrl(context, endpoint);
        if (!target)
            continue;
        const matches = (id) => id === endpoint.id || !!id && model.endpointAliases?.[id] === endpoint.id;
        const signals = context.signals.filter(signal => signal.projectId === context.project.id
            && signal.cweIds.includes(metadata.cweId) && matches(signal.endpointId));
        const facts = [...(model.cookies ?? []), ...(model.corsConfigurations ?? []), ...(model.dataFlows ?? []),
            ...(model.databaseOperations ?? []), ...(model.observedOwnership ?? [])]
            .filter(fact => fact.endpointIds.some(matches) || fact.endpointIds.length === 0);
        const resources = context.resources.filter(resource => resource.projectId === context.project.id && matches(resource.endpointId));
        const protectedEndpoint = endpoint.authentication === 'required' || endpoint.roles.length > 0;
        const parameters = endpoint.parameters.filter(parameter => parameter.location === 'query' || parameter.location === 'body');
        if (!accepts({ endpoint, hasSignal: signals.length > 0, facts, resources, parameters }))
            continue;
        const injection = metadata.probeId === 'xss' || metadata.probeId === 'sql-injection';
        const identities = context.identities.filter(identity => identity.authentication !== 'anonymous');
        const eligible = identities.filter(identity => endpoint.roles.every(role => identity.roles.includes(role)));
        const identityIds = metadata.probeId === 'cookie-security' ? identities.slice(0, 10).map(identity => identity.id)
            : metadata.probeId === 'cross-origin' || injection && protectedEndpoint ? eligible.slice(0, 1).map(identity => identity.id) : [];
        const points = injection && parameters.length ? parameters : [undefined];
        const policies = metadata.probeId === 'authorization'
            ? (options.authorizationPolicies ?? []).filter(policy => resources.some(resource => resource.id === policy.resourceId)
                || facts.some(fact => fact.kind === 'ownership' && fact.details.resourceId === policy.resourceId)) : [];
        for (const point of points)
            for (const policy of policies.length ? policies : [undefined]) {
                const sensitive = [...new Set([...(options.sensitiveCookieNames ?? []), ...sensitiveNames(facts)])];
                const scope = {
                    projectId: context.project.id, targetUrl: target, method: endpoint.method,
                    identityIds: policy ? [policy.ownerIdentityId, policy.attackerIdentityId] : identityIds,
                    ...(point ? { parameter: { name: point.name, location: point.location } } : {}),
                    ...(metadata.probeId === 'cookie-security' ? { sensitiveCookieNames: sensitive } : {}),
                    ...(metadata.probeId === 'cross-origin' ? { untrustedOrigins: [...(options.untrustedOrigins ?? [])] } : {}),
                    ...(policy ? { authorization: structuredClone(policy) } : {}),
                };
                const refs = [...endpoint.evidenceIds, ...signals.flatMap(signal => signal.evidenceIds),
                    ...facts.flatMap(fact => fact.evidenceIds), ...resources.flatMap(resource => resource.evidenceIds)];
                hypotheses.push({ id: `hypothesis:${identifier(metadata.cweId, context.project.id, endpoint.id, point?.name, point?.location, policy ? [policy.resourceId, policy.ownerIdentityId, policy.attackerIdentityId, policy.attackerIsUnauthorized, policy.anonymousIsUnauthorized] : null)}`,
                    projectId: context.project.id, cweId: metadata.cweId, status: 'HYPOTHESIS',
                    reason: `Application observations warrant ${metadata.title.toLowerCase()} investigation; runtime proof is required.`,
                    endpointId: endpoint.id, ...(endpoint.handler ? { source: structuredClone(endpoint.handler) } : {}),
                    evidenceIds: [...new Set(refs.filter(id => evidence.has(id)))].sort(), scope });
            }
    }
    return freeze([...new Map(hypotheses.map(hypothesis => [hypothesis.id, hypothesis])).values()].sort((a, b) => a.id.localeCompare(b.id)));
}
function sensitiveNames(facts) {
    return facts.filter(fact => fact.kind === 'cookie' && fact.details.sensitive === true && typeof fact.details.name === 'string')
        .map(fact => fact.details.name);
}
function targetUrl(context, endpoint) {
    try {
        const origin = 'origin' in endpoint && typeof endpoint.origin === 'string' ? endpoint.origin : context.project.baseUrl;
        const target = url(new URL(endpoint.path, origin).href);
        if (!context.project.allowedOrigins.includes(target.origin))
            return;
        // Do not turn framework-specific regex, wildcard or optional syntax into an executable target.
        if (/[()*?{}]/.test(endpoint.path.split('?')[0]))
            return;
        target.search = '';
        return target.href;
    }
    catch {
        return;
    }
}
export function referencesMatch(item, endpointId, context) {
    if (!item.endpointId || !endpointId)
        return false;
    const aliases = context.endpointAliases ?? {};
    return (aliases[item.endpointId] ?? item.endpointId) === (aliases[endpointId] ?? endpointId);
}

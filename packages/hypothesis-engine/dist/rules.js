import { identifier, record } from './shared.js';
function support(kind, statement, evidenceIds, strength = 'candidate') {
    const refs = [...new Set(evidenceIds)].sort();
    return { id: `support:${identifier(kind, refs)}`, kind, statement, evidenceIds: refs, strength };
}
function signalSupports(context) {
    return context.signals.map(signal => support('cwe-signal', `An evidence-linked signal associates this endpoint with ${context.candidate.cweId}; runtime verification is required.`, signal.evidenceIds));
}
function input(context) {
    return context.endpoint.parameters.some(parameter => ['path', 'query', 'body'].includes(parameter.location));
}
function options(fact) {
    return record(fact.details.options) ? fact.details.options : fact.details;
}
function conditional(fact) {
    return Array.isArray(fact.details.conditions) && fact.details.conditions.length > 0;
}
function binding(context, fact) {
    if (typeof fact.details.origin === 'string' && fact.details.origin !== context.endpoint.origin)
        return false;
    if (fact.endpointIds.length)
        return true;
    // Global source configuration applies to the application. Unbound runtime facts cannot be assigned to a route.
    return fact.source === 'source' || fact.source === 'declared';
}
function cweRule(cweId, gather) {
    return { cweId, gather: context => [...signalSupports(context), ...gather(context)] };
}
function cookieRule(cweId, attribute, names) {
    return cweRule(cweId, context => context.facts.filter(fact => fact.kind === 'cookie' && binding(context, fact)).flatMap(fact => {
        const config = options(fact);
        const session = fact.details.observation === 'session';
        const cookie = session && record(config.cookie) ? config.cookie : config;
        const name = typeof fact.details.name === 'string' ? fact.details.name : typeof config.name === 'string' ? config.name : undefined;
        const sensitive = session || fact.details.sensitive === true || name !== undefined && names.includes(name);
        if (!sensitive || cookie[attribute] === true)
            return [];
        if (cookie[attribute] === false)
            return [support(`cookie-${attribute}`, conditional(fact)
                    ? `A conditional session or declared sensitive cookie configuration disables ${attribute}; the active configuration requires verification.`
                    : `A session or declared sensitive cookie observation explicitly disables ${attribute}; its runtime scope requires verification.`, fact.evidenceIds)];
        return [support(`cookie-${attribute}-unknown`, `A session or declared sensitive cookie is observed, but its ${attribute} setting is unresolved.`, fact.evidenceIds, 'context')];
    }));
}
function corsRule(untrusted) {
    return cweRule('CWE-942', context => context.facts.filter(fact => fact.kind === 'cors' && binding(context, fact)).flatMap(fact => {
        const config = options(fact), origins = config.allowOrigin;
        const broad = config.origin === true || config.origin === '*' || Array.isArray(origins)
            && origins.some(origin => origin === '*' || typeof origin === 'string' && untrusted.includes(origin))
            || fact.details.header === 'access-control-allow-origin'
                && (fact.details.value === '*' || fact.details.requestInput === 'headers.origin');
        if (!broad)
            return [];
        return [support('broad-cors', 'CORS observations allow a wildcard, reflected request origin or explicitly untrusted origin; response sensitivity and browser access require verification.', fact.evidenceIds)];
    }));
}
function ownership(context) {
    if (!input(context))
        return [];
    // Do not infer an absent ownership check from an extractor's silence.
    return context.facts.filter(fact => fact.kind === 'ownership' && fact.endpointIds.length > 0).map(fact => support('owner-key', 'Evidence links an owner-bound resource and request input to this endpoint; their relationship is unresolved and ownership enforcement remains unverified.', [...fact.evidenceIds, ...context.endpoint.evidenceIds]));
}
function authorization(context) {
    const guards = context.evidence.filter(item => item.facts.observation === 'authorization-guard');
    const conditional = guards.filter(item => item.facts.enforcement === 'conditional');
    if (conditional.length)
        return [support('conditional-authorization', 'An observed role rejection guard is conditional; enforcement across runtime paths requires verification.', conditional.map(item => item.id))];
    if (guards.some(item => item.facts.enforcement === 'observed'))
        return [];
    if (context.endpoint.authentication !== 'required' && !context.endpoint.roles.length)
        return [];
    return [support('protected-endpoint', 'The endpoint has authentication or role requirements; these declarations alone do not establish authorization enforcement.', context.endpoint.evidenceIds, 'context')];
}
function injection(context) {
    if (!input(context))
        return [];
    const flows = context.facts.filter(fact => fact.kind === 'data-flow'
        && (fact.details.cweId === context.candidate.cweId || Array.isArray(fact.details.cweIds) && fact.details.cweIds.includes(context.candidate.cweId)));
    const supported = flows.map(fact => support('source-sink', 'A static source/sink candidate is associated with request input; runtime reachability and exploitability remain unverified.', fact.evidenceIds));
    if (context.candidate.cweId === 'CWE-89') {
        for (const fact of context.facts.filter(fact => fact.kind === 'database-operation')) {
            if (fact.details.interpolated === true)
                supported.push(support('interpolated-query', 'An interpolated database operation and request input occur at this endpoint; lexical co-location does not prove runtime data flow.', [...fact.evidenceIds, ...context.endpoint.evidenceIds]));
            else if (record(fact.details.sql) && fact.details.sql.kind === 'dynamic')
                supported.push(support('dynamic-query', 'A dynamic database operation and request input were observed; their runtime relationship remains unverified.', fact.evidenceIds, 'context'));
        }
    }
    else
        supported.push(support('request-input', 'Request input is declared at this endpoint; whether it reaches executable page content remains unverified.', context.endpoint.evidenceIds, 'context'));
    return supported;
}
/** Candidate strength is about investigation priority, never proof or finding confidence. */
export function createDefaultHypothesisRules(options = {}) {
    const names = [...(options.sensitiveCookieNames ?? [])], origins = [...(options.untrustedOrigins ?? [])];
    return [cweRule('CWE-639', ownership), cweRule('CWE-862', authorization), corsRule(origins),
        cookieRule('CWE-1004', 'httpOnly', names), cookieRule('CWE-614', 'secure', names),
        cweRule('CWE-79', injection), cweRule('CWE-89', injection)];
}

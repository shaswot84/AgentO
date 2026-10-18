import { confirmed, rejected, sameTarget, unknown, url } from './shared.js';
export function cookieCandidate(candidate) {
    return candidate.endpoint.authentication === 'required' || candidate.endpoint.roles.length > 0
        || candidate.hasSignal || candidate.facts.some(fact => fact.kind === 'cookie');
}
export function cookieDecision(evidence, scope, attribute) {
    const target = url(scope.targetUrl);
    if (attribute === 'secure' && target.protocol !== 'https:')
        return unknown('HTTPS cookie context is required to assess the Secure attribute.');
    const names = new Set(scope.sensitiveCookieNames ?? []);
    if (!names.size)
        return unknown('Sensitive cookie identities have not been declared.');
    const observations = evidence.observations.filter(item => sameTarget(item.response, scope));
    const cookies = observations.flatMap(item => item.cookies).filter(cookie => {
        const domain = cookie.domain.replace(/^\./, '').toLowerCase();
        const host = target.hostname.toLowerCase();
        return names.has(cookie.name) && (cookie.hostOnly ? host === domain : host === domain || host.endsWith(`.${domain}`))
            && (target.pathname === cookie.path || target.pathname.startsWith(cookie.path.endsWith('/') ? cookie.path : `${cookie.path}/`))
            && (cookie.maxAge === null || cookie.maxAge > 0)
            && (cookie.maxAge !== null || cookie.expiresAt === null || Date.parse(cookie.expiresAt) > Date.parse(evidence.capturedAt));
    });
    if (cookies.some(cookie => cookie[attribute] === false))
        return confirmed(`A declared sensitive cookie lacks the ${attribute === 'httpOnly' ? 'HttpOnly' : 'Secure'} attribute.`);
    if (!cookies.length || evidence.outcome !== 'COMPLETED')
        return unknown('No complete observation of a declared sensitive cookie is available.');
    return rejected(`Observed sensitive cookies carry the ${attribute === 'httpOnly' ? 'HttpOnly' : 'Secure'} attribute.`);
}

import type { CookieEvidence } from '../contracts.js';
import { freeze, limit, RuntimeError } from '../safety.js';
import type { CookieSecurityContext, CookieSecurityEvidence, SecurityProbe } from './contracts.js';
import { available, base, check, metadata, publicResponse, request, sanitized, snapshot, withIdentity } from './shared.js';

export class CookieSecurityProbe implements SecurityProbe<CookieSecurityContext, CookieSecurityEvidence> {
  metadata() { return metadata('cookie-security', ['request-executor', 'response-collector', 'cookie-analyzer'],
    ['authentication-manager', 'cookie-inspector', 'browser-controller']); }
  supports(context: CookieSecurityContext): boolean {
    return available(context, this.metadata().requiredCapabilities)
      && (!(context.identities?.length) || available(context, ['authentication-manager', 'cookie-inspector']));
  }
  execute(input: CookieSecurityContext): Promise<CookieSecurityEvidence> {
    return sanitized(async () => {
      const context = snapshot(input), identities = structuredClone(input.identities ?? []);
      check(context, this.supports(context));
      limit(identities.length + 1, 11);
      if (new Set(identities.map(identity => identity.id)).size !== identities.length
        || identities.some(identity => identity.authentication === 'anonymous')) throw new RuntimeError('invalid-request');
      const prepared = request(context, context.request);
      const analyzer = context.capabilities.get('cookie-analyzer');
      const observations: CookieSecurityEvidence['observations'][number][] = [];
      // Both parser and inspector outputs are projected to the public cookie shape below.
      const anonymous = await context.capabilities.get('request-executor').execute(prepared);
      observations.push({ identityId: null, context: 'anonymous', response: publicResponse(context, anonymous),
        cookies: publicCookies(await analyzer.analyze(anonymous)) });
      for (const identity of identities) {
        await withIdentity(context, identity, async session => {
          const response = await session.http.execute(prepared);
          const inspector = context.capabilities.get('cookie-inspector');
          const cookies = [...await analyzer.analyze(response), ...await inspector.inspect(session)];
          // A browser may retain cookies that the narrower backend HTTP jar cannot transfer.
          if (context.capabilities.has('browser-controller')) {
            cookies.push(...await context.capabilities.get('browser-controller').withSession(identity, page => inspector.inspect(page)));
          }
          observations.push({ identityId: identity.id, context: 'authenticated', response: publicResponse(context, response),
            cookies: publicCookies(cookies) });
        });
      }
      return freeze({ ...base(context, this.metadata().id), observations });
    });
  }
}
function publicCookies(cookies: readonly CookieEvidence[]): CookieEvidence[] {
  return cookies.map(cookie => ({ name: cookie.name, value: '[REDACTED]', domain: cookie.domain, path: cookie.path,
    hostOnly: cookie.hostOnly, httpOnly: cookie.httpOnly, secure: cookie.secure, sameSite: cookie.sameSite,
    expiresAt: cookie.expiresAt, maxAge: cookie.maxAge, partitioned: cookie.partitioned, source: cookie.source,
    ...(cookie.responseId ? { responseId: cookie.responseId } : {}), ...(cookie.sessionId ? { sessionId: cookie.sessionId } : {}) }));
}

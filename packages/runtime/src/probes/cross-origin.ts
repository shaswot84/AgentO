import { freeze, limit, RuntimeError } from '../safety.js';
import type { HeaderEvidence, RequestExecutor } from '../contracts.js';
import type { CrossOriginContext, CrossOriginEvidence, SecurityProbe } from './contracts.js';
import { assertActive, available, base, check, metadata, publicResponse, request, sanitized, snapshot, withIdentity } from './shared.js';

export class CrossOriginProbe implements SecurityProbe<CrossOriginContext, CrossOriginEvidence> {
  metadata() { return metadata('cross-origin', ['request-executor', 'response-collector', 'header-analyzer'], ['authentication-manager']); }
  supports(context: CrossOriginContext): boolean {
    return available(context, this.metadata().requiredCapabilities)
      && (!context.identity || context.capabilities.has('authentication-manager'));
  }
  execute(input: CrossOriginContext): Promise<CrossOriginEvidence> {
    return sanitized(async () => {
      const context = snapshot(input), identity = input.identity ? structuredClone(input.identity) : undefined;
      check(context, this.supports(context));
      const prepared = request(context, context.request);
      const origins = [...(input.origins ?? ['null', 'https://unapproved.invalid', 'https://reflected.invalid'])];
      const requestedHeaders = [...(input.requestedHeaders ?? ['x-agento-probe'])];
      limit(origins.length, 8);
      if (requestedHeaders.length > 16 || requestedHeaders.some(header => !/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/.test(header))
        || new Set(origins).size !== origins.length || identity?.authentication === 'anonymous') throw new RuntimeError('invalid-request');
      for (const origin of origins) {
        if (origin === 'null') continue;
        let parsed: URL;
        try { parsed = new URL(origin); } catch { throw new RuntimeError('invalid-request'); }
        if (!['http:', 'https:'].includes(parsed.protocol) || parsed.origin !== origin) throw new RuntimeError('invalid-request');
      }
      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(prepared.headers ?? {})) {
        if (!['origin', 'access-control-request-method', 'access-control-request-headers'].includes(key.toLowerCase())) headers[key] = value;
      }
      const executor = context.capabilities.get('request-executor'), analyzer = context.capabilities.get('header-analyzer');
      const collect = async (actualExecutor: RequestExecutor): Promise<CrossOriginEvidence> => {
        const observations: CrossOriginEvidence['observations'][number][] = [];
        for (const origin of origins) {
          assertActive(context);
          // Browser preflights omit credentials even when the actual request uses a session.
          const preflight = await executor.execute({ ...prepared, method: 'OPTIONS', headers: { ...headers, Origin: origin,
            'Access-Control-Request-Method': prepared.method!,
            ...(requestedHeaders.length ? { 'Access-Control-Request-Headers': requestedHeaders.join(', ') } : {}) } });
          assertActive(context);
          const actual = await actualExecutor.execute({ ...prepared, headers: { ...headers, Origin: origin } });
          observations.push({ requestedOrigin: origin, identityId: identity?.id ?? null,
            credentialMode: identity ? 'session' : 'omit',
            preflight: { response: publicResponse(context, preflight), cors: publicCors((await analyzer.analyze(preflight)).cors) },
            actual: { response: publicResponse(context, actual), cors: publicCors((await analyzer.analyze(actual)).cors) } });
        }
        return freeze({ ...base(context, this.metadata().id), observations });
      };
      return identity ? withIdentity(context, identity, session => collect(session.http)) : collect(executor);
    });
  }
}
function publicCors(cors: HeaderEvidence['cors']): HeaderEvidence['cors'] {
  return { allowOrigin: [...cors.allowOrigin], allowCredentials: [...cors.allowCredentials], allowMethods: [...cors.allowMethods],
    allowHeaders: [...cors.allowHeaders], exposeHeaders: [...cors.exposeHeaders], maxAge: [...cors.maxAge] };
}

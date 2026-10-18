import { randomUUID } from 'node:crypto';
import { evidenceUrl, freeze, RuntimeError } from '../safety.js';
import type { InjectionContext, SecurityProbe, XSSEvidence } from './contracts.js';
import { available, base, check, metadata, mutate, publicResponse, sanitized, snapshot, text, validateInjection } from './shared.js';
import { scan, withInjectionExecutor } from './injection.js';

export class XSSProbe implements SecurityProbe<InjectionContext, XSSEvidence> {
  metadata() { return metadata('xss', ['request-executor', 'response-collector'],
    ['authentication-manager', 'browser-controller', 'xss-scanner']); }
  supports(context: InjectionContext): boolean {
    return available(context, this.metadata().requiredCapabilities)
      && (!context.identity || context.capabilities.has('authentication-manager'));
  }
  execute(input: InjectionContext): Promise<XSSEvidence> {
    return sanitized(async () => {
      const context = { ...snapshot(input), parameter: { ...input.parameter },
        ...(input.identity ? { identity: structuredClone(input.identity) } : {}),
        ...(input.anonymousIdentity ? { anonymousIdentity: structuredClone(input.anonymousIdentity) } : {}) };
      check(context, this.supports(context));
      if (context.anonymousIdentity && context.anonymousIdentity.authentication !== 'anonymous') throw new RuntimeError('invalid-request');
      const prepared = validateInjection(context);
      const normalized = { ...context, request: prepared };
      const canary = `agento-${randomUUID().replaceAll('-', '')}`;
      const payload = `${canary}<agento-canary data-marker="${canary}"></agento-canary>`;
      const injectedRequest = mutate(context, prepared, () => payload);
      return withInjectionExecutor(context, async (executor, session) => {
        const baseline = await executor.execute(prepared), injected = await executor.execute(injectedRequest);
        const body = text(injected), diagnostics: XSSEvidence['diagnostics'][number][] = [];
        if (baseline.body.truncated || injected.body.truncated) diagnostics.push('response-truncated');
        let browser: XSSEvidence['browser'] = null;
        if (context.parameter.location === 'query' && prepared.method === 'GET') {
          const observe = async (page: import('../contracts.js').BrowserSession) => {
            await page.perform({ action: 'navigate', url: injectedRequest.url });
            const result = await page.inspect();
            return { url: evidenceUrl(result.url), canaryVisible: (result.visibleTextSummary ?? '').includes(canary) };
          };
          if (session) browser = await session.withBrowser(observe);
          else if (context.anonymousIdentity && context.capabilities.has('browser-controller')) {
            browser = await context.capabilities.get('browser-controller').withSession(
              context.anonymousIdentity, observe);
          } else diagnostics.push('browser-unavailable');
        } else diagnostics.push('browser-unavailable');
        let executionConfirmed: boolean | null = null, domSinkReached: boolean | null = null;
        if (context.capabilities.has('xss-scanner')) {
          const result = await scan(normalized, executor, canary, value => context.capabilities.get('xss-scanner').scan(value));
          if (![true, false, null].includes(result.executionConfirmed) || ![true, false, null].includes(result.domSinkReached)) {
            throw new RuntimeError('invalid-request');
          }
          executionConfirmed = result.executionConfirmed; domSinkReached = result.domSinkReached;
        } else diagnostics.push('scanner-unavailable');
        const reflected = body.includes(payload);
        return freeze({ ...base(context, this.metadata().id, diagnostics), parameter: { ...context.parameter },
          baseline: publicResponse(context, baseline), injected: publicResponse(context, injected), canary,
          literalReflection: reflected ? true : injected.body.truncated ? null : false,
          reflectionContexts: contexts(body, canary, injected.headers['content-type'] ?? []),
          browser, executionConfirmed, domSinkReached });
      });
    });
  }
}
/** Lexical hints only: these are not a browser parser or proof of an executable sink. */
function contexts(body: string, canary: string, contentTypes: readonly string[]): XSSEvidence['reflectionContexts'] {
  const result = new Set<XSSEvidence['reflectionContexts'][number]>();
  let offset = body.indexOf(canary), count = 0;
  while (offset >= 0 && count++ < 32) {
    const prefix = body.slice(0, offset).toLowerCase();
    result.add(!contentTypes.some(type => /text\/html|application\/xhtml\+xml/i.test(type)) ? 'text'
      : prefix.lastIndexOf('<script') > prefix.lastIndexOf('</script') ? 'script'
      : prefix.lastIndexOf('<') > prefix.lastIndexOf('>') ? 'attribute' : 'html');
    offset = body.indexOf(canary, offset + canary.length);
  }
  return [...result];
}

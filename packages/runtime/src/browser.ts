import { randomUUID } from 'node:crypto';
import type { AnalysisContext, BrowserContextCookie, BrowserWorkflowRuntimeDriver, TargetApplicationProfile } from '@agento/core';
import type { BrowserController, BrowserSession, CookieInspector, NetworkEvidence, NetworkObserver, RuntimeCookie, TestIdentity } from './contracts.js';
import { cookieEvidence } from './cookies.js';
import { evidenceUrl, freeze, limit, RuntimeError, RuntimeScope } from './safety.js';

export interface WorkflowBrowserOptions {
  readonly driver: BrowserWorkflowRuntimeDriver;
  readonly context: AnalysisContext;
  readonly target?: TargetApplicationProfile;
  readonly maxNetworkRecords?: number;
}
/** Adapts a workflow driver's guarded lifecycle to reusable runtime capabilities. */
export class WorkflowBrowserController implements BrowserController {
  private readonly context: AnalysisContext;
  private readonly target: TargetApplicationProfile | undefined;
  private readonly maximum: number;
  private readonly scope: RuntimeScope;
  constructor(private readonly options: WorkflowBrowserOptions) {
    this.context = freeze(structuredClone(options.context));
    // Strategies are trusted configuration objects with methods, not serializable data.
    const target = options.target;
    this.target = target ? { ...target, baseOrigins: [...target.baseOrigins],
      ...(target.personas ? { personas: structuredClone(target.personas) } : {}),
      ...(target.scope ? { scope: { allowedOrigins: [...target.scope.allowedOrigins] } } : {}) } : undefined;
    const declared = new RuntimeScope(this.context.project.baseUrl, this.context.project.allowedOrigins);
    const configured = target ? new RuntimeScope(this.context.project.baseUrl, target.baseOrigins) : declared;
    const narrowed = target?.scope ? new RuntimeScope(this.context.project.baseUrl, target.scope.allowedOrigins) : configured;
    const origins = declared.origins.filter(origin => configured.origins.includes(origin) && narrowed.origins.includes(origin));
    this.scope = new RuntimeScope(this.context.project.baseUrl, origins);
    this.maximum = limit(options.maxNetworkRecords ?? 500, 10_000);
  }
  async withSession<T>(identity: TestIdentity, execute: (session: BrowserSession) => Promise<T>): Promise<T> {
    const registered = this.context.identities.find(item => item.id === identity.id);
    if (!registered || registered.authentication !== identity.authentication
      || JSON.stringify([...registered.roles].sort()) !== JSON.stringify([...identity.roles].sort())) throw new RuntimeError('authentication-failed');
    const id = `runtime-browser:${randomUUID()}`;
    let value: T | undefined, finished = false, callbackError: unknown;
    try {
      const result = await this.options.driver.runWorkflow(this.context,
        { id, identityId: identity.id, goal: 'runtime-session' }, async port => {
          let active = true;
          const assertActive = () => { if (!active || port.signal.aborted) throw new RuntimeError('session-closed'); };
          const read = async (): Promise<readonly RuntimeCookie[]> => {
            assertActive();
            if (!port.readCookies) throw new RuntimeError('unsupported-capability');
            const cookies = await port.readCookies(); assertActive();
            return freeze(cookies.map(cookie => fromBrowser(cookie, this.scope)));
          };
          const session: BrowserSession = Object.freeze<BrowserSession>({ id, identityId: identity.id,
            inspect: async () => { assertActive(); const page = await port.inspect(); assertActive(); return page; },
            perform: async action => {
              assertActive(); if (action.action === 'navigate' || action.action === 'wait-url') this.scope.assert(action.url);
              if ('response' in action && action.response) this.scope.assert(action.response.url);
              await port.perform(action); assertActive();
            },
            network: () => {
              assertActive(); const records = port.network();
              if (records.length > this.maximum) throw new RuntimeError('record-limit');
              return freeze(records.map(record => ({ sessionId: id, identityId: identity.id, source: 'browser' as const,
                url: evidenceUrl(record.url), method: record.method, status: record.status, blocked: record.blocked })));
            },
            cookies: async () => freeze((await read()).map(cookie => cookieEvidence(cookie, 'browser', { sessionId: id }))),
            transferCookies: read,
            importCookies: async cookies => {
              assertActive();
              if (!port.replaceCookies) throw new RuntimeError('unsupported-capability');
              const converted = cookies.map(cookie => {
                if (cookie.partitioned) throw new RuntimeError('unsupported-capability');
                const origin = this.scope.origins.find(item => new URL(item).hostname === cookie.domain);
                if (!origin || !cookie.path.startsWith('/')) throw new RuntimeError('authentication-failed');
                return { name: cookie.name, value: cookie.value,
                  domain: cookie.hostOnly ? cookie.domain : `.${cookie.domain}`, path: cookie.path,
                  expires: cookie.expiresAt === null ? -1 : Date.parse(cookie.expiresAt) / 1000,
                  httpOnly: cookie.httpOnly, secure: cookie.secure, sameSite: cookie.sameSite ?? 'Lax' };
              });
              await port.replaceCookies(converted); assertActive();
            },
          });
          try { value = await execute(session); assertActive(); finished = true; }
          catch (error) { callbackError = error; throw error; }
          finally { active = false; }
        }, this.target);
      if (callbackError) throw callbackError;
      if (result.outcome !== 'COMPLETED' || !finished) {
        const code = result.diagnostics[0]?.code;
        throw new RuntimeError(code === 'scope-denied' ? 'scope-denied' : code === 'authentication-failed'
          ? 'authentication-failed' : code === 'timeout' ? 'timeout' : 'browser-failed');
      }
      return value as T;
    } catch (error) { throw error instanceof RuntimeError ? error : new RuntimeError('browser-failed'); }
  }
}
export function fromBrowser(cookie: BrowserContextCookie, scope: RuntimeScope): RuntimeCookie {
  const domain = cookie.domain.replace(/^\./, '');
  if (!scope.origins.some(origin => new URL(origin).hostname === domain)
    || !Number.isFinite(cookie.expires) || cookie.expires < -1) throw new RuntimeError('authentication-failed');
  return { name: cookie.name, value: cookie.value, domain, path: cookie.path,
    hostOnly: !cookie.domain.startsWith('.'), httpOnly: cookie.httpOnly, secure: cookie.secure, sameSite: cookie.sameSite,
    expiresAt: cookie.expires === -1 ? null : new Date(cookie.expires * 1000).toISOString(), maxAge: null,
    partitioned: cookie.partitionKey !== undefined };
}
export class SessionNetworkObserver implements NetworkObserver {
  async observe(session: Parameters<NetworkObserver['observe']>[0]): Promise<readonly NetworkEvidence[]> { return session.network(); }
}
export class SessionCookieInspector implements CookieInspector {
  inspect(session: Parameters<CookieInspector['inspect']>[0]) { return session.cookies(); }
}

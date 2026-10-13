import { randomUUID } from 'node:crypto';
import type { AnalysisContext, BrowserWorkflow, BrowserWorkflowDriver, Endpoint, Evidence, Identity, JsonValue,
  Project, SecurityTestPlan, SecurityTestResult } from '@agento/core';
import { BrowserError, BrowserScope, redactUrl } from './policy.js';
import { E2EWebRuntime } from './runtime.js';
import { isStoredSession, MemorySessionStore } from './sessions.js';
import type { BrowserAction, BrowserDiagnostic, BrowserSession, BrowserSnapshot, NetworkRecord,
  SessionStore, TesterArmyE2EOptions, WorkflowObservation } from './types.js';

const messages: Record<BrowserDiagnostic['code'], string> = {
  'invalid-workflow': 'The workflow must use a registered goal or supported structured browser actions.',
  'scope-denied': 'An action or browser request was refused by the browser scope policy.',
  'authentication-failed': 'Authentication could not be verified for the requested identity.',
  'browser-failed': 'The browser workflow failed; raw tool errors are withheld.',
  'timeout': 'The browser workflow exceeded its execution budget.',
  'network-limit': 'Network evidence reached its record limit; observations are incomplete.',
  'session-store-failed': 'The private authentication store could not be read or written.',
};

export class TesterArmyE2EAdapter implements BrowserWorkflowDriver {
  readonly id = 'tester-army-e2e-adapter';
  readonly capabilities = ['browser-workflow', 'authenticated-browser', 'multi-identity', 'session-reuse',
    'network-observation', 'browser-evidence', 'origin-scope'] as const;
  private readonly store: SessionStore;
  private readonly timeoutMs: number;
  private readonly sessionTtlMs: number;
  private readonly maxNetworkRecords: number;
  private tail: Promise<unknown> = Promise.resolve();

  constructor(private readonly options: TesterArmyE2EOptions = {}) {
    this.store = options.sessionStore ?? new MemorySessionStore();
    this.timeoutMs = limit(options.timeoutMs ?? 60_000, 600_000);
    this.sessionTtlMs = limit(options.sessionTtlMs ?? 1_800_000, 86_400_000);
    this.maxNetworkRecords = limit(options.maxNetworkRecords ?? 500, 10_000);
  }

  observe(context: AnalysisContext, workflow: BrowserWorkflow): Promise<WorkflowObservation> {
    return this.serial(async () => {
      let actions: readonly BrowserAction[] | undefined;
      try { actions = this.options.resolveGoal?.(context, workflow); }
      catch { /* Resolver messages may include goal text or secrets. */ }
      return this.run(context, workflow.identityId, actions);
    });
  }

  execute(context: AnalysisContext, plan: SecurityTestPlan): Promise<SecurityTestResult> {
    return this.serial(async () => {
      const evidence: Evidence[] = [];
      let outcome: SecurityTestResult['outcome'] = 'COMPLETED';
      let code: BrowserDiagnostic['code'] | undefined;
      try {
        const scope = new BrowserScope(context.project);
        scope.assert(plan.targetUrl);
        if (plan.executor !== 'browser' || !plan.identityIds.length || !plan.steps.length
          || plan.steps.length > 100 || plan.requiredCapabilities.some(value => !this.capabilities.includes(value as typeof this.capabilities[number]))
          || plan.identityIds.some(id => !context.identities.some(identity => identity.id === id))) throw new BrowserError('invalid-workflow');
        const groups: { identityId: string; actions: BrowserAction[] }[] = [];
        // Validate the entire plan before the first identity can touch a target.
        for (const step of plan.steps) {
          const identityId = step.parameters.identityId ?? (plan.identityIds.length === 1 ? plan.identityIds[0] : undefined);
          if (typeof identityId !== 'string' || !plan.identityIds.includes(identityId)) throw new BrowserError('invalid-workflow');
          const action = parseAction(step.action, step.parameters);
          scope.validateActions([action]);
          const previous = groups.at(-1);
          if (previous?.identityId === identityId) previous.actions.push(action);
          else groups.push({ identityId, actions: [action] });
        }
        for (const group of groups) {
          const observation = await this.run(context, group.identityId, group.actions);
          evidence.push(...observation.evidence);
          if (observation.outcome !== 'COMPLETED') {
            outcome = observation.outcome; code = observation.diagnostics[0]?.code; break;
          }
        }
      } catch (error) { code = error instanceof BrowserError ? error.code : 'browser-failed'; outcome = 'SKIPPED'; }
      return freeze({ id: `browser-result:${randomUUID()}`, planId: plan.id, producerId: this.id, outcome,
        summary: outcome === 'COMPLETED' ? 'Structured browser actions completed; no vulnerability verdict is inferred.' : messages[code ?? 'browser-failed'],
        evidence, ...(code ? { error: { code, message: messages[code] } } : {}) });
    });
  }

  /** Explicit invalidation also removes an opt-in persistent snapshot. */
  forgetSession(project: Project, identity: Identity): Promise<void> {
    return this.serial(() => this.store.delete(new BrowserScope(project).binding(project, identity)));
  }

  private serial<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.tail.then(operation);
    this.tail = result.catch(() => undefined);
    return result;
  }

  private async run(context: AnalysisContext, identityId: string, actions: readonly BrowserAction[] | undefined): Promise<WorkflowObservation> {
    const runId = randomUUID(), capturedAt = new Date().toISOString();
    const diagnostics: BrowserDiagnostic[] = [], records: NetworkRecord[] = [], secrets: string[] = [];
    const controller = new AbortController();
    let session: BrowserSession | undefined, scope: BrowserScope | undefined, snapshot: BrowserSnapshot | undefined;
    let outcome: WorkflowObservation['outcome'] = 'COMPLETED', started = false, reused = false, authenticated = false;
    let sessionRef: string | undefined, blockedCount = 0, droppedCount = 0, executedActions = 0;
    const diagnose = (code: BrowserDiagnostic['code']) => {
      if (!diagnostics.some(item => item.code === code)) diagnostics.push({ code, message: messages[code] });
    };
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const aborted = new Promise<never>((_, reject) => controller.signal.addEventListener('abort', () => reject(new BrowserError('timeout')), { once: true }));
    const bounded = <T>(work: Promise<T>) => Promise.race([work, aborted]);
    try {
      scope = new BrowserScope(context.project);
      const identity = context.identities.find(item => item.id === identityId);
      if (!identity || !actions) throw new BrowserError('invalid-workflow');
      // Clone trusted recipes so a caller cannot mutate them after preflight.
      actions = structuredClone(actions);
      scope.validateActions(actions);
      const auth = this.options.authentication;
      const needsAuth = identity.authentication !== 'anonymous';
      const verification = needsAuth ? auth?.verification(identity) : undefined;
      if (needsAuth && (!auth || !this.options.credentials || !verification)) throw new BrowserError('authentication-failed');
      if (verification) {
        scope.assert(verification.url);
        if (auth!.successUrl) scope.assert(auth!.successUrl);
        if (!verification.identityPath.length || !verification.expectedIdentity) throw new BrowserError('authentication-failed');
        scope.validateActions([{ action: 'navigate', url: auth!.loginUrl, response: auth!.response },
          { action: 'fill', selector: auth!.usernameSelector, value: '' },
          { action: 'fill', selector: auth!.passwordSelector, value: '' },
          { action: 'click', selector: auth!.submitSelector }]);
      }
      timeout = setTimeout(() => controller.abort(), this.timeoutMs);
      const binding = scope.binding(context.project, identity);
      let cached = needsAuth ? await bounded(this.store.load(binding)) : undefined;
      if (cached) {
        if (!isStoredSession(cached) || cached.binding !== binding || cached.expiresAt <= Date.now()) {
          await bounded(this.store.delete(binding)); cached = undefined;
        } else {
          scope.validateState(cached.state);
          collectStateSecrets(cached.state.data, secrets);
        }
      }
      const runtime = this.options.runtime ?? new E2EWebRuntime();
      const start = async (state?: typeof cached) => {
        if (controller.signal.aborted) throw new BrowserError('timeout');
        started = true;
        const live = await runtime.start({ project: context.project, signal: controller.signal, timeoutMs: this.timeoutMs,
          assertUrl: url => scope!.assert(url), onNetwork: record => {
            if (record.blocked) blockedCount++;
            if (records.length < this.maxNetworkRecords) records.push(record); else droppedCount++;
          }, ...(state ? { state: state.state } : {}), ...(this.options.screenshot ? { screenshot: this.options.screenshot } : {}) });
        if (controller.signal.aborted) { await live.close(); throw new BrowserError('timeout'); }
        session = live;
        return session;
      };
      await bounded(start(cached));
      if (cached && verification) {
        if (await bounded(session!.verify(verification))) {
          reused = true; authenticated = true; sessionRef = cached.sessionRef;
        } else {
          await bounded(this.store.delete(binding)); await bounded(session!.close());
          session = undefined; await bounded(start());
        }
      }
      if (needsAuth && !authenticated) {
        try {
          const credentials = await bounded(this.options.credentials!(identity, context.project));
          if (typeof credentials.username !== 'string' || typeof credentials.password !== 'string'
            || !credentials.username || !credentials.password) throw new BrowserError('authentication-failed');
          secrets.push(credentials.password);
          await bounded(session!.perform({ action: 'navigate', url: auth!.loginUrl }));
          await bounded(session!.perform({ action: 'fill', selector: auth!.usernameSelector, value: credentials.username }));
          await bounded(session!.perform({ action: 'fill', selector: auth!.passwordSelector, value: credentials.password }));
          await bounded(session!.perform({ action: 'click', selector: auth!.submitSelector, response: auth!.response }));
          if (auth!.successUrl) await bounded(session!.perform({ action: 'wait-url', url: auth!.successUrl }));
          if (!await bounded(session!.verify(verification!))) throw new BrowserError('authentication-failed');
        } catch (error) {
          if (error instanceof BrowserError && ['scope-denied', 'timeout'].includes(error.code)) throw error;
          throw new BrowserError('authentication-failed');
        }
        authenticated = true; sessionRef = `browser-session:${randomUUID()}`;
      }
      for (const action of actions) {
        await bounded(session!.perform(action)); executedActions++;
      }
      snapshot = await bounded(session!.snapshot());
      if (blockedCount) throw new BrowserError('scope-denied');
      if (needsAuth) {
        // Verify again: a workflow may log out or switch accounts. Never cache that as this identity.
        if (!await bounded(session!.verify(verification!))) {
          await bounded(this.store.delete(binding)); throw new BrowserError('authentication-failed');
        }
        const state = await bounded(session!.captureState());
        scope.validateState(state); collectStateSecrets(state.data, secrets);
        await bounded(this.store.save({ binding, sessionRef: sessionRef!, expiresAt: Date.now() + this.sessionTtlMs, state }));
      }
      if (blockedCount) throw new BrowserError('scope-denied');
    } catch (error) {
      const code = controller.signal.aborted ? 'timeout' : error instanceof BrowserError ? error.code : 'browser-failed';
      diagnose(code); outcome = started ? 'FAILED' : 'SKIPPED';
    } finally {
      if (timeout) clearTimeout(timeout);
      await session?.close().catch(() => { diagnose('browser-failed'); outcome = 'FAILED'; });
    }
    if (blockedCount) { diagnose('scope-denied'); outcome = 'FAILED'; }
    if (droppedCount) { diagnose('network-limit'); outcome = 'FAILED'; }
    const evidence: Evidence[] = [];
    const endpoints = new Map<string, Endpoint>();
    const makeEvidence = (kind: Evidence['kind'], summary: string, facts: Record<string, JsonValue>, endpointId?: string, artifactRef?: string): Evidence => {
      const item: Evidence = { id: `browser-evidence:${randomUUID()}`, projectId: context.project.id, producerId: this.id,
        capturedAt, kind, identityId, summary, facts, ...(endpointId ? { endpointId } : {}), ...(artifactRef ? { artifactRef } : {}) };
      evidence.push(item); return item;
    };
    for (const record of records) {
      const url = redactUrl(record.url, secrets);
      let endpoint: Endpoint | undefined;
      const parsed = URL.canParse(url) ? new URL(url) : undefined;
      if (!record.blocked && record.status !== null && parsed && isMethod(record.method)) {
        endpoint = (parsed.origin === new URL(context.project.baseUrl).origin
          ? context.endpoints.find(item => item.method === record.method && pathMatches(item.path, parsed.pathname)) : undefined)
          ?? endpoints.get(`${parsed.origin}:${record.method}:${parsed.pathname}`);
        if (!endpoint) {
          endpoint = { id: `browser-endpoint:${runId}:${endpoints.size}`, componentId: context.components[0]?.id ?? `${context.project.id}:browser`,
            method: record.method, path: parsed.pathname, parameters: [...new Set(parsed.searchParams.keys())].map(name => ({ name, location: 'query', required: false })),
            authentication: 'unknown', roles: [], evidenceIds: [] };
          endpoints.set(`${parsed.origin}:${record.method}:${parsed.pathname}`, endpoint);
        }
      }
      const requestEvidence = makeEvidence('http-request', record.blocked ? 'Browser request refused by scope policy.' : 'Observed browser request.',
        { url, method: record.method, resourceType: record.resourceType, blocked: record.blocked,
          ...(record.blockedReason ? { blockedReason: record.blockedReason } : {}) }, endpoint?.id);
      const references = [requestEvidence.id];
      if (record.status !== null) references.push(makeEvidence('http-response', 'Observed browser response status.',
        { url, method: record.method, status: record.status, requestEvidenceId: requestEvidence.id }, endpoint?.id).id);
      if (endpoint && endpoints.has(`${parsed!.origin}:${record.method}:${parsed!.pathname}`)) {
        endpoints.set(`${parsed!.origin}:${record.method}:${parsed!.pathname}`, { ...endpoint, evidenceIds: [...endpoint.evidenceIds, ...references] });
      }
    }
    if (authenticated) makeEvidence('identity-session', 'Verified isolated browser identity session.',
      { authenticated: true, reused, sessionRef: sessionRef!, rawStateIncluded: false });
    if (snapshot?.screenshotPath) makeEvidence('screenshot', 'Opt-in masked browser screenshot.',
      { url: redactUrl(snapshot.url, secrets), inputsMasked: true }, undefined, snapshot.screenshotPath);
    makeEvidence('browser-observation', `Browser workflow ${outcome.toLowerCase()}; observations carry no vulnerability verdict.`,
      { outcome, executedActions, networkRecordCount: records.length, blockedCount, droppedCount,
        diagnosticCodes: diagnostics.map(item => item.code), ...(snapshot ? { url: redactUrl(snapshot.url, secrets) } : {}) });
    return freeze({ outcome, diagnostics, endpoints: [...endpoints.values()], resources: [], signals: [], evidence });
  }
}

function limit(value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new Error('Browser execution limits are invalid.');
  return value;
}
function isMethod(value: string): value is Endpoint['method'] {
  return ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(value);
}
function pathMatches(pattern: string, path: string): boolean {
  const parts = pattern.split('/'), candidate = path.split('/');
  return parts.length === candidate.length && parts.every((part, index) => part.startsWith(':') || part === candidate[index]);
}
function parseAction(action: string, parameters: Readonly<Record<string, JsonValue>>): BrowserAction {
  const string = (name: string) => {
    if (typeof parameters[name] !== 'string') throw new BrowserError('invalid-workflow');
    return parameters[name] as string;
  };
  const responseValue = parameters.response;
  let response: { url: string; method?: string; status?: number } | undefined;
  if (responseValue !== undefined) {
    if (!responseValue || typeof responseValue !== 'object' || Array.isArray(responseValue)) throw new BrowserError('invalid-workflow');
    const item = responseValue as Record<string, JsonValue>;
    if (typeof item.url !== 'string' || item.method !== undefined && typeof item.method !== 'string'
      || item.status !== undefined && typeof item.status !== 'number') throw new BrowserError('invalid-workflow');
    response = { url: item.url, ...(typeof item.method === 'string' ? { method: item.method } : {}),
      ...(typeof item.status === 'number' ? { status: item.status } : {}) };
  }
  switch (action) {
    case 'navigate': return { action, url: string('url'), ...(response ? { response } : {}) };
    case 'wait-url': return { action, url: string('url') };
    case 'fill': return { action, selector: string('selector'), value: string('value') };
    case 'click': return { action, selector: string('selector'), ...(response ? { response } : {}) };
    case 'wait-visible': return { action, selector: string('selector') };
    default: throw new BrowserError('invalid-workflow');
  }
}
function collectStateSecrets(data: unknown, secrets: string[]): void {
  if (!data || typeof data !== 'object') return;
  const cookies = (data as { cookies?: unknown }).cookies;
  if (Array.isArray(cookies)) for (const cookie of cookies) if (typeof cookie?.value === 'string') secrets.push(cookie.value);
  const origins = (data as { origins?: unknown }).origins;
  if (Array.isArray(origins)) for (const origin of origins) if (Array.isArray(origin?.localStorage)) {
    for (const entry of origin.localStorage) if (typeof entry?.value === 'string') secrets.push(entry.value);
  }
}
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value); for (const child of Object.values(value)) freeze(child);
  }
  return value;
}

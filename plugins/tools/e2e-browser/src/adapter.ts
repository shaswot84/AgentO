import { createHash, randomUUID } from 'node:crypto';
import { BrowserWorkflowFailure, type AnalysisContext, type BrowserPageInspection, type BrowserWorkflow,
  type BrowserWorkflowRuntimeDriver, type BrowserWorkflowSession, type Endpoint, type Evidence, type Identity, type JsonValue,
  type Persona, type Project, type SecurityTestPlan, type SecurityTestResult, type TargetApplicationProfile } from '@agento/core';
import { BrowserError, BrowserScope, redactUrl } from './policy.js';
import { E2EWebRuntime } from './runtime.js';
import { isStoredSession, MemorySessionStore } from './sessions.js';
import { FormLoginStrategy } from './authentication.js';
import { authenticationActions, targetPersona, targetScope, validateVerification } from './target.js';
import { legacyWorkflowExecutor } from './legacy-workflow.js';
import { privateStorageValues } from './private-values.js';
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
  'unable-to-proceed': 'The workflow planner could not safely advance the requested goal.',
  'model-budget': 'The optional semantic planner exhausted its configured execution budget.',
};

export class TesterArmyE2EAdapter implements BrowserWorkflowRuntimeDriver {
  readonly id = 'tester-army-e2e-adapter';
  readonly capabilities = ['browser-workflow', 'authenticated-browser', 'multi-identity', 'session-reuse',
    'network-observation', 'browser-evidence', 'origin-scope'] as const;
  private readonly store: SessionStore;
  private readonly timeoutMs: number;
  private readonly sessionTtlMs: number;
  private readonly maxNetworkRecords: number;
  private readonly maxWorkflowActions: number;
  private tail: Promise<unknown> = Promise.resolve();

  constructor(private readonly options: TesterArmyE2EOptions = {}) {
    const target = options.target;
    this.options = { ...options, ...(target ? { target: { ...target, baseOrigins: [...target.baseOrigins],
      ...(target.personas ? { personas: freeze(structuredClone(target.personas)) } : {}),
      ...(target.authentication ? { authentication: [...target.authentication] } : {}),
      ...(target.scope ? { scope: { allowedOrigins: [...target.scope.allowedOrigins] } } : {}),
      ...(target.workflowHints ? { workflowHints: freeze(structuredClone(target.workflowHints)) } : {}),
    } } : {}) };
    this.store = options.sessionStore ?? new MemorySessionStore();
    this.timeoutMs = limit(options.timeoutMs ?? 60_000, 600_000);
    this.sessionTtlMs = limit(options.sessionTtlMs ?? 1_800_000, 86_400_000);
    this.maxNetworkRecords = limit(options.maxNetworkRecords ?? 500, 10_000);
    this.maxWorkflowActions = limit(options.maxWorkflowActions ?? 100, 100);
  }

  observe(context: AnalysisContext, workflow: BrowserWorkflow): Promise<WorkflowObservation> {
    return this.serial(async () => {
      let actions: readonly BrowserAction[] | undefined;
      try { actions = this.options.resolveGoal?.(context, workflow); }
      catch { /* Resolver messages may include goal text or secrets. */ }
      const execute = !actions && this.options.workflowPlanner && this.options.target
        ? legacyWorkflowExecutor(this.options.workflowPlanner, this.options.target, workflow) : undefined;
      return this.run(context, workflow.identityId, actions, execute);
    });
  }

  /** Trusted workflow orchestration uses a guarded capability port, never raw browser objects. */
  runWorkflow(context: AnalysisContext, workflow: BrowserWorkflow,
    execute: (session: BrowserWorkflowSession) => Promise<void>, target?: TargetApplicationProfile): Promise<WorkflowObservation> {
    return this.serial(() => this.run(context, workflow.identityId, undefined, execute, target));
  }

  execute(context: AnalysisContext, plan: SecurityTestPlan): Promise<SecurityTestResult> {
    return this.serial(async () => {
      const evidence: Evidence[] = [];
      let outcome: SecurityTestResult['outcome'] = 'COMPLETED';
      let code: BrowserDiagnostic['code'] | undefined;
      try {
        const scope = targetScope(context.project, this.options.target);
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
  forgetSession(project: Project, identity: Identity, target = this.options.target): Promise<void> {
    return this.serial(() => {
      const persona = targetPersona(identity, identity.id, target);
      const configured = targetScope(project, this.options.target);
      const scope = targetScope({ ...project, allowedOrigins: configured.origins }, target);
      return this.store.delete(this.binding(scope, project, persona, target));
    });
  }

  private binding(scope: BrowserScope, project: Project, persona: Persona, target = this.options.target): string {
    return scope.binding(project, persona, target ? [target.id, persona.credentialsRef,
      persona.authenticationStrategyId ?? target.defaultAuthenticationStrategyId
        ?? (target.authentication?.length === 1 ? target.authentication[0]!.id : undefined), persona.expectedRole] : undefined);
  }

  private serial<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.tail.then(operation);
    this.tail = result.catch(() => undefined);
    return result;
  }

  private async run(context: AnalysisContext, identityId: string, actions: readonly BrowserAction[] | undefined,
    execute?: (session: BrowserWorkflowSession) => Promise<void>, requestedTarget?: TargetApplicationProfile): Promise<WorkflowObservation> {
    const target = requestedTarget ?? this.options.target;
    const runId = randomUUID(), capturedAt = new Date().toISOString();
    const diagnostics: BrowserDiagnostic[] = [], records: NetworkRecord[] = [], secrets: string[] = [];
    const controller = new AbortController();
    let session: BrowserSession | undefined, scope: BrowserScope | undefined, snapshot: BrowserSnapshot | undefined;
    let outcome: WorkflowObservation['outcome'] = 'COMPLETED', started = false, reused = false, authenticated = false, portActive = true;
    let sessionRef: string | undefined, blockedCount = 0, droppedCount = 0, executedActions = 0;
    const diagnose = (code: BrowserDiagnostic['code']) => {
      if (!diagnostics.some(item => item.code === code)) diagnostics.push({ code, message: messages[code] });
    };
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const aborted = new Promise<never>((_, reject) => controller.signal.addEventListener('abort', () => reject(new BrowserError('timeout')), { once: true }));
    const bounded = <T>(work: Promise<T>) => Promise.race([work, aborted]);
    try {
      const configuredScope = targetScope(context.project, this.options.target);
      scope = targetScope({ ...context.project, allowedOrigins: configuredScope.origins }, target);
      const identity = targetPersona(context.identities.find(item => item.id === identityId), identityId, target);
      if (!actions && !execute) throw new BrowserError('invalid-workflow');
      // Clone trusted recipes so a caller cannot mutate them after preflight.
      if (actions) { actions = structuredClone(actions); scope.validateActions(actions); }
      const strategies = target?.authentication;
      const strategyId = identity.authenticationStrategyId ?? target?.defaultAuthenticationStrategyId;
      if (strategies && new Set(strategies.map(item => item.id)).size !== strategies.length) throw new BrowserError('authentication-failed');
      const strategy = strategies?.find(item => item.id === strategyId)
        ?? (!strategyId && strategies?.length === 1 ? strategies[0] : undefined)
        ?? (!target && this.options.authentication ? new FormLoginStrategy(this.options.authentication) : undefined);
      const needsAuth = identity.authentication !== 'anonymous';
      const preparation = needsAuth ? strategy?.prepare(identity) : undefined;
      const verification = preparation ? structuredClone(preparation.verification) : undefined;
      const loginActions = preparation?.actions ? structuredClone(preparation.actions) : undefined;
      const needsCredentials = loginActions?.some(action => action.action === 'fill-credential');
      if (needsAuth && (!strategy || !verification)) throw new BrowserError('authentication-failed');
      if (verification) {
        validateVerification(scope, verification);
        if (loginActions) scope.validateActions(authenticationActions(loginActions));
      }
      timeout = setTimeout(() => controller.abort(), this.timeoutMs);
      const binding = this.binding(scope, context.project, identity, target);
      let cached = needsAuth ? await bounded(this.store.load(binding)) : undefined;
      if (cached) {
        if (!isStoredSession(cached) || cached.binding !== binding || cached.expiresAt <= Date.now()) {
          await bounded(this.store.delete(binding)); cached = undefined;
        } else {
          scope.validateState(cached.state);
          collectStateSecrets(cached.state.data, secrets);
        }
      }
      const canLogin = !!loginActions && (!needsCredentials || !!this.options.credentials);
      if (needsAuth && !cached && !canLogin) throw new BrowserError('authentication-failed');
      const runtime = this.options.runtime ?? new E2EWebRuntime();
      const start = async (state?: typeof cached) => {
        if (controller.signal.aborted) throw new BrowserError('timeout');
        started = true;
        const live = await runtime.start({ project: context.project, signal: controller.signal, timeoutMs: this.timeoutMs,
          assertUrl: url => scope!.assert(url), onNetwork: record => {
            if (record.blocked) blockedCount++;
            if (records.length < this.maxNetworkRecords) records.push({ ...record, timestamp: record.timestamp ?? new Date().toISOString() }); else droppedCount++;
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
          session = undefined;
          if (!canLogin) throw new BrowserError('authentication-failed');
          await bounded(start());
        }
      }
      if (needsAuth && !authenticated) {
        try {
          if (!loginActions) throw new BrowserError('authentication-failed');
          const credentials = needsCredentials ? await bounded(this.options.credentials!(identity, context.project)) : undefined;
          if (credentials && (typeof credentials.username !== 'string' || typeof credentials.password !== 'string'
            || !credentials.username || !credentials.password)) throw new BrowserError('authentication-failed');
          if (credentials) secrets.push(credentials.username, credentials.password);
          const login = authenticationActions(loginActions, credentials);
          scope.validateActions(login);
          for (const action of login) await bounded(session!.perform(action));
          if (!await bounded(session!.verify(verification!))) throw new BrowserError('authentication-failed');
        } catch (error) {
          if (error instanceof BrowserError && ['scope-denied', 'timeout'].includes(error.code)) throw error;
          throw new BrowserError('authentication-failed');
        }
        authenticated = true; sessionRef = `browser-session:${randomUUID()}`;
      }
      if (execute) {
        const assertActive = () => {
          if (!portActive || controller.signal.aborted) throw new BrowserError('timeout');
          if (blockedCount) throw new BrowserError('scope-denied');
          if (droppedCount) throw new BrowserError('network-limit');
        };
        const perform = async (action: BrowserAction) => {
          assertActive();
          if (executedActions >= this.maxWorkflowActions) throw new BrowserError('invalid-workflow');
          const checked = structuredClone(action);
          scope!.validateActions([checked]);
          if (checked.action === 'fill') secrets.push(checked.value);
          try { await bounded(session!.perform(checked)); }
          catch (error) { throw error instanceof BrowserWorkflowFailure ? error : new BrowserError('browser-failed'); }
          executedActions++; assertActive();
        };
        const inspect = async () => {
          assertActive();
          collectStateSecrets((await bounded(session!.captureState())).data, secrets);
          const raw = await bounded(session!.inspect()), page = sanitizeInspection(raw, secrets);
          const stateId = createHash('sha256').update(JSON.stringify([runId, raw.stateId, page])).digest('hex');
          assertActive(); return freeze({ ...page, stateId });
        };
        const port: BrowserWorkflowSession = Object.freeze<BrowserWorkflowSession>({ signal: controller.signal,
          persona: freeze(structuredClone(identity)), inspect, perform,
          fillCredential: async (selector: string, field: 'username' | 'password', guard?: { readonly stateId: string }) => {
            assertActive();
            if (!['username', 'password'].includes(field) || !this.options.credentials) throw new BrowserError('authentication-failed');
            scope!.validateActions([{ action: 'fill', selector, value: '' }]);
            const before = await inspect();
            if (guard && guard.stateId !== before.stateId) throw new BrowserError('authentication-failed');
            const credentials = await bounded(this.options.credentials(identity, context.project));
            if (!credentials || typeof credentials[field] !== 'string' || !credentials[field]) throw new BrowserError('authentication-failed');
            const after = await inspect();
            if (after.stateId !== before.stateId) throw new BrowserError('authentication-failed');
            secrets.push(credentials[field]);
            await perform({ action: 'fill', selector, value: credentials[field] });
          },
          assertUrl: (url: string) => { assertActive(); return scope!.assert(url); },
          network: () => {
            assertActive(); return freeze(records.map(record => ({ url: redactUrl(record.url, secrets),
              method: record.method, status: record.status, blocked: record.blocked })));
          },
          readCookies: async () => {
            assertActive();
            if (!session!.readCookies) throw new BrowserError('browser-failed');
            const cookies = await bounded(session!.readCookies());
            scope!.validateState({ format: 'playwright-storage-state', version: 1, data: { cookies, origins: [] } });
            secrets.push(...cookies.map(cookie => cookie.value));
            assertActive(); return freeze(structuredClone(cookies));
          },
          replaceCookies: async cookies => {
            assertActive();
            if (!session!.replaceCookies) throw new BrowserError('browser-failed');
            const copy = structuredClone(cookies);
            scope!.validateState({ format: 'playwright-storage-state', version: 1, data: { cookies: copy, origins: [] } });
            secrets.push(...copy.map(cookie => cookie.value));
            await bounded(session!.replaceCookies(copy)); assertActive();
          },
        });
        try { await bounded(execute(port)); } finally { portActive = false; }
      } else for (const action of actions!) {
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
      const code = controller.signal.aborted ? 'timeout' : error instanceof BrowserWorkflowFailure ? error.code : 'browser-failed';
      diagnose(code); outcome = started ? 'FAILED' : 'SKIPPED';
    } finally {
      portActive = false;
      if (session && !controller.signal.aborted) await bounded(session.captureState()).then(state => collectStateSecrets(state.data, secrets)).catch(() => undefined);
      if (controller.signal.aborted) { diagnose('timeout'); outcome = started ? 'FAILED' : 'SKIPPED'; }
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
      const common = { url, origin: parsed?.origin ?? null, personaId: identityId,
        timestamp: record.timestamp ?? capturedAt,
        ...(sessionRef ? { sessionRef } : {}),
        ...(target ? { targetId: target.id } : {}),
        ...(record.initiatingPage ? { initiatingPage: redactUrl(record.initiatingPage, secrets) } : {}) };
      const requestEvidence = makeEvidence('http-request', record.blocked ? 'Browser request refused by scope policy.' : 'Observed browser request.',
        { ...common, method: record.method, resourceType: record.resourceType, blocked: record.blocked,
          ...(record.blockedReason ? { blockedReason: record.blockedReason } : {}) }, endpoint?.id);
      const references = [requestEvidence.id];
      if (record.status !== null) references.push(makeEvidence('http-response', 'Observed browser response status.',
        { ...common, method: record.method, status: record.status, headers: safeHeaders(record.headers, secrets), requestEvidenceId: requestEvidence.id }, endpoint?.id).id);
      if (endpoint && endpoints.has(`${parsed!.origin}:${record.method}:${parsed!.pathname}`)) {
        endpoints.set(`${parsed!.origin}:${record.method}:${parsed!.pathname}`, { ...endpoint, evidenceIds: [...endpoint.evidenceIds, ...references] });
      }
    }
    if (authenticated) makeEvidence('identity-session', 'Verified isolated browser identity session.',
      { authenticated: true, reused, sessionRef: sessionRef!, rawStateIncluded: false,
        ...(target ? { targetId: target.id } : {}) });
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
    case 'click': case 'submit': return { action, selector: string('selector'), ...(response ? { response } : {}) };
    case 'wait-visible': return { action, selector: string('selector') };
    default: throw new BrowserError('invalid-workflow');
  }
}
function collectStateSecrets(data: unknown, secrets: string[]): void {
  if (!data || typeof data !== 'object') return;
  const cookies = (data as { cookies?: unknown }).cookies;
  if (Array.isArray(cookies)) for (const cookie of cookies) if (typeof cookie?.value === 'string') secrets.push(...privateStorageValues(cookie.value));
  const origins = (data as { origins?: unknown }).origins;
  if (Array.isArray(origins)) for (const origin of origins) if (Array.isArray(origin?.localStorage)) {
    for (const entry of origin.localStorage) if (typeof entry?.value === 'string') secrets.push(...privateStorageValues(entry.value));
  }
}
function safeHeaders(headers: Readonly<Record<string, string>> | undefined, secrets: readonly string[]): Record<string, JsonValue> {
  const result: Record<string, JsonValue> = {};
  const mime = headers?.['content-type']?.split(';')[0]?.trim().toLowerCase();
  if (mime && /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(mime) && mime.length <= 128
    && !secrets.filter(Boolean).some(secret => [secret, encodeURIComponent(secret)].some(form => mime.includes(form.toLowerCase())))) result['content-type'] = mime;
  if (headers?.['x-content-type-options']?.toLowerCase() === 'nosniff') result['x-content-type-options'] = 'nosniff';
  return result;
}
function sanitizeInspection(page: BrowserPageInspection, secrets: readonly string[]): BrowserPageInspection {
  const text = (value: string, maximum: number) => {
    for (const secret of secrets.filter(Boolean)) value = value.split(secret).join('[REDACTED]');
    return value.replace(/\beyJ[A-Za-z0-9_.-]+/g, '[REDACTED]')
      .replace(/[A-Za-z0-9_.~%+=-]{40,}/g, '[REDACTED]').slice(0, maximum);
  };
  return { url: page.url === 'about:blank' ? page.url : redactUrl(page.url, secrets),
    ...(page.title !== undefined ? { title: text(page.title, 256) } : {}),
    ...(page.headings ? { headings: page.headings.slice(0, 20).map(value => text(value, 256)) } : {}),
    ...(page.visibleTextSummary !== undefined ? { visibleTextSummary: text(page.visibleTextSummary, 4096) } : {}),
    controls: page.controls.slice(0, 100).map(control => ({ kind: control.kind,
      selector: text(control.selector, 2048), label: text(control.label, 256),
      ...(control.enabled !== undefined ? { enabled: control.enabled } : {}),
      ...(control.inputType ? { inputType: text(control.inputType, 32) } : {}),
      ...(control.formSelector ? { formSelector: text(control.formSelector, 2048) } : {}),
      ...(control.href ? { href: redactUrl(control.href, secrets) } : {}) })) };
}
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value); for (const child of Object.values(value)) freeze(child);
  }
  return value;
}

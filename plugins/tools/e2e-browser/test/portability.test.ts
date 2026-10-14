import { readFile } from 'node:fs/promises';
import { describe, expect, it, vi } from 'vitest';
import type { AuthenticationStrategy, BrowserAction, Persona, TargetApplicationProfile, WorkflowPlanner } from '@agento/core';
import { TesterArmyE2EAdapter, FormLoginStrategy, StoredSessionStrategy, MemorySessionStore } from '../src/index.js';
import { anonymous, context, fakeRuntime, state, workflow } from './helpers.js';

const persona: Persona = { id: 'support', label: 'Support', roles: ['support'], authentication: 'session-cookie', credentialsRef: 'vault:support' };
const auth = new FormLoginStrategy({ loginUrl: '/sign-in', usernameSelector: '[name=handle]', passwordSelector: '[name=passphrase]',
  submitSelector: '[data-auth] button', response: { url: '/sessions', status: 200 },
  verification: actor => ({ url: '/whoami', identityPath: ['account', 'handle'], expectedIdentity: actor.id }) }, 'login');
const target: TargetApplicationProfile = { id: 'support-app', baseOrigins: [context.project.baseUrl], personas: [persona], authentication: [auth] };
const configuredContext = { ...context, identities: [persona] };
const configuredWorkflow = { ...workflow, identityId: persona.id };
const credentials = vi.fn(async (actor: Persona) => {
  expect(actor.credentialsRef).toBe('vault:support');
  return { username: 'support', password: 'private-password' };
});
const recipe = () => [{ action: 'navigate' as const, url: '/account' }];

describe('target profiles and authentication boundaries', () => {
  it('uses arbitrary personas, routes and selectors from target configuration', async () => {
    const runtime = fakeRuntime();
    const result = await new TesterArmyE2EAdapter({ target, credentials, runtime, resolveGoal: recipe }).observe(configuredContext, configuredWorkflow);
    expect(result.outcome).toBe('COMPLETED');
    expect(runtime.sessions[0]!.perform.mock.calls.map(([action]) => action)).toContainEqual({ action: 'fill', selector: '[name=handle]', value: 'support' });
    expect(result.evidence.find(item => item.kind === 'identity-session')?.facts.targetId).toBe(target.id);
    expect(JSON.stringify(result)).not.toMatch(/private-password|private-session-cookie/);
  });

  it('discovers personas from context when the profile does not declare them', async () => {
    const { personas: _personas, ...profile } = target;
    const result = await new TesterArmyE2EAdapter({ target: profile, credentials, runtime: fakeRuntime(), resolveGoal: recipe }).observe(configuredContext, configuredWorkflow);
    expect(result.outcome).toBe('COMPLETED');
  });

  it('allows an anonymous profile without authentication or other optional fields', async () => {
    const result = await new TesterArmyE2EAdapter({ target: { id: 'public', baseOrigins: target.baseOrigins },
      runtime: fakeRuntime(), resolveGoal: recipe }).observe(context, { ...workflow, identityId: anonymous.id });
    expect(result.outcome).toBe('COMPLETED');
  });

  it('refuses missing, duplicate or conflicting personas before target access', async () => {
    const runtime = fakeRuntime();
    for (const profile of [{ ...target, personas: [] }, { ...target, personas: [persona, persona] },
      { ...target, personas: [{ ...persona, roles: ['owner'] }] }]) {
      expect((await new TesterArmyE2EAdapter({ target: profile, runtime, credentials, resolveGoal: recipe })
        .observe(configuredContext, configuredWorkflow)).outcome).toBe('SKIPPED');
    }
    expect(runtime.start).not.toHaveBeenCalled();
  });

  it('requires explicit origins and never broadens declared project scope', async () => {
    const runtime = fakeRuntime();
    for (const profile of [{ ...target, baseOrigins: [] }, { ...target, baseOrigins: ['https://127.0.0.1:3000'] },
      { ...target, scope: { allowedOrigins: ['http://127.0.0.1:3001'] } }]) {
      const result = await new TesterArmyE2EAdapter({ target: profile, runtime, credentials, resolveGoal: recipe }).observe(configuredContext, configuredWorkflow);
      expect(result.diagnostics[0]?.code).toBe('scope-denied');
    }
    const wider = { ...configuredContext, project: { ...context.project, allowedOrigins: [...target.baseOrigins, 'http://external.example'] } };
    expect((await new TesterArmyE2EAdapter({ target, runtime, credentials,
      resolveGoal: () => [{ action: 'navigate', url: 'http://external.example' }] }).observe(wider, configuredWorkflow)).diagnostics[0]?.code).toBe('scope-denied');
    expect(runtime.start).not.toHaveBeenCalled();
  });

  it('rejects unknown strategies and external authentication or verification paths before launch', async () => {
    const runtime = fakeRuntime();
    const invalid = new StoredSessionStrategy(() => ({ url: 'http://external.example', identityPath: ['id'], expectedIdentity: 'support' }));
    for (const profile of [{ ...target, defaultAuthenticationStrategyId: 'unknown' }, { ...target, authentication: [invalid] },
      { ...target, authentication: [auth, auth] }]) {
      expect((await new TesterArmyE2EAdapter({ target: profile, runtime, credentials, resolveGoal: recipe }).observe(configuredContext, configuredWorkflow)).outcome).toBe('SKIPPED');
    }
    expect(runtime.start).not.toHaveBeenCalled();
  });

  it('supports a per-persona strategy and a custom declarative login without credentials', async () => {
    const strategy: AuthenticationStrategy = { id: 'custom', prepare: actor => ({
      verification: { url: '/whoami', identityPath: ['id'], expectedIdentity: actor.id },
      actions: [{ action: 'navigate', url: '/bootstrap' }, { action: 'submit', selector: 'form[data-bootstrap]' }],
    }) };
    const runtime = fakeRuntime();
    const profile = { ...target, personas: [{ ...persona, authenticationStrategyId: 'custom' }], authentication: [auth, strategy] };
    expect((await new TesterArmyE2EAdapter({ target: profile, runtime, resolveGoal: recipe }).observe(configuredContext, configuredWorkflow)).outcome).toBe('COMPLETED');
    expect(runtime.sessions[0]!.perform.mock.calls[1]?.[0]).toEqual({ action: 'submit', selector: 'form[data-bootstrap]' });
  });

  it('isolates saved state by target, persona, credential reference and strategy in a shared store', async () => {
    const store = new MemorySessionStore(), runtime = fakeRuntime();
    const run = (profile: TargetApplicationProfile, actor = persona) => new TesterArmyE2EAdapter({ target: profile, runtime, credentials,
      sessionStore: store, resolveGoal: recipe }).observe({ ...configuredContext, identities: [actor] }, { ...configuredWorkflow, identityId: actor.id });
    await run(target); await run(target);
    await run({ ...target, id: 'another-target' });
    const alternate = { ...persona, id: 'another-persona' };
    await run({ ...target, personas: [alternate] }, alternate);
    const changedRef = { ...persona, credentialsRef: 'vault:support' + ':rotated' };
    await new TesterArmyE2EAdapter({ target: { ...target, personas: [changedRef] }, runtime,
      credentials: async () => ({ username: 'support', password: 'private-password' }), sessionStore: store, resolveGoal: recipe }).observe(configuredContext, configuredWorkflow);
    await run({ ...target, authentication: [new FormLoginStrategy({ loginUrl: '/new', usernameSelector: 'input', passwordSelector: 'input[type=password]',
      submitSelector: 'button', response: { url: '/sessions' }, verification: actor => ({ url: '/whoami', identityPath: ['id'], expectedIdentity: actor.id }) }, 'other-strategy')] });
    expect(runtime.start.mock.calls.map(([request]) => !!request.state)).toEqual([false, true, false, false, false, false]);
  });

  it('reuses independently provisioned state through StoredSessionStrategy and refuses missing state', async () => {
    const store = new MemorySessionStore(), runtime = fakeRuntime();
    await new TesterArmyE2EAdapter({ target, runtime, credentials, sessionStore: store, resolveGoal: recipe }).observe(configuredContext, configuredWorkflow);
    const profile = { ...target, authentication: [new StoredSessionStrategy(actor => ({ url: '/whoami', identityPath: ['id'], expectedIdentity: actor.id }), 'login')] };
    const adapter = new TesterArmyE2EAdapter({ target: profile, runtime, sessionStore: store, resolveGoal: recipe });
    expect((await adapter.observe(configuredContext, configuredWorkflow)).outcome).toBe('COMPLETED');
    expect(runtime.start.mock.calls.at(-1)![0].state).toEqual(state);
    await adapter.forgetSession(context.project, persona);
    expect((await adapter.observe(configuredContext, configuredWorkflow)).outcome).toBe('SKIPPED');
    expect(runtime.start).toHaveBeenCalledTimes(2);
  });

  it('reuses a form session without a credentials resolver and refuses fresh or stale state without one', async () => {
    const sessionStore = new MemorySessionStore(), runtime = fakeRuntime();
    await new TesterArmyE2EAdapter({ target, runtime, credentials, sessionStore, resolveGoal: recipe }).observe(configuredContext, configuredWorkflow);
    const adapter = new TesterArmyE2EAdapter({ target, runtime, sessionStore, resolveGoal: recipe });
    expect((await adapter.observe(configuredContext, configuredWorkflow)).outcome).toBe('COMPLETED');
    const invalid = fakeRuntime({ verify: () => false });
    const stale = await new TesterArmyE2EAdapter({ target, runtime: invalid, sessionStore, resolveGoal: recipe }).observe(configuredContext, configuredWorkflow);
    expect(stale.diagnostics[0]?.code).toBe('authentication-failed');
    expect(invalid.start).toHaveBeenCalledOnce(); expect(invalid.sessions[0]!.close).toHaveBeenCalledOnce();
    expect((await adapter.observe(configuredContext, configuredWorkflow)).outcome).toBe('SKIPPED');
    expect(runtime.start).toHaveBeenCalledTimes(2);
  });

  it('snapshots target personas, workflow hints and approved origins against caller mutations', async () => {
    const profile = { ...target, baseOrigins: [...target.baseOrigins], personas: [{ ...persona }], workflowHints: { start: '/account' } };
    const adapter = new TesterArmyE2EAdapter({ target: profile, runtime: fakeRuntime(), credentials, resolveGoal: recipe });
    profile.baseOrigins[0] = 'http://external.example'; profile.personas[0]!.id = 'other'; profile.workflowHints.start = 'http://external.example';
    expect((await adapter.observe(configuredContext, configuredWorkflow)).outcome).toBe('COMPLETED');
  });

  it('normalizes generic origin, initiating page, timestamps and only safe headers', async () => {
    const runtime = fakeRuntime({ perform: async (_action, request) => request.onNetwork({ url: `${context.project.baseUrl}/graphql?secret=private`,
      method: 'POST', status: 200, resourceType: 'fetch', blocked: false, initiatingPage: `${context.project.baseUrl}/dashboard?token=private`,
      headers: { 'content-type': 'application/json; boundary=private', 'x-content-type-options': 'nosniff', authorization: 'private', 'set-cookie': 'private' } }) });
    const result = await new TesterArmyE2EAdapter({ runtime, resolveGoal: recipe }).observe(context, { ...workflow, identityId: 'anonymous' });
    const response = result.evidence.find(item => item.kind === 'http-response')!;
    expect(response.facts).toMatchObject({ origin: context.project.baseUrl, personaId: 'anonymous',
      headers: { 'content-type': 'application/json', 'x-content-type-options': 'nosniff' } });
    expect(response.facts.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(JSON.stringify(result)).not.toMatch(/private|authorization|set-cookie/);
  });

  it('withholds a content-type value that reflects a private storage secret', async () => {
    const runtime = fakeRuntime({ perform: async (_action, request) => request.onNetwork({ url: `${context.project.baseUrl}/data`,
      method: 'GET', status: 200, resourceType: 'fetch', blocked: false, headers: { 'content-type': 'application/private-session-cookie' } }) });
    const result = await new TesterArmyE2EAdapter({ runtime, resolveGoal: recipe }).observe(context, { ...workflow, identityId: 'anonymous' });
    expect(result.outcome).toBe('COMPLETED');
    expect(result.evidence.find(item => item.kind === 'http-response')?.facts.headers).toEqual({});
    expect(JSON.stringify(result)).not.toContain('private-session-cookie');
  });
});

describe('iterative workflow planning', () => {
  const publicTarget: TargetApplicationProfile = { id: 'public', baseOrigins: target.baseOrigins, personas: [anonymous] };
  const publicWorkflow = { ...workflow, identityId: 'anonymous' };
  it('inspects after each action and passes immutable, normalized inputs with secrets removed', async () => {
    const runtime = fakeRuntime();
    const original = runtime.start.getMockImplementation()!;
    runtime.start.mockImplementation(async request => ({ ...await original(request), inspect: async () => ({ url: `${request.project.baseUrl}/?token=private`,
      controls: [{ selector: 'button', kind: 'button', label: 'private-session-cookie', href: `${request.project.baseUrl}/secret/private-session-cookie` }] }) }));
    const next = vi.fn(async (input: Parameters<WorkflowPlanner['next']>[0]) => {
      expect(Object.isFrozen(input.page.controls)).toBe(true);
      expect(JSON.stringify(input)).not.toMatch(/private-session-cookie|\?token=private/);
      return input.executedActions === 2 ? { outcome: 'complete' as const } : { outcome: 'action' as const, action: { action: 'navigate' as const, url: '/next' } };
    });
    const result = await new TesterArmyE2EAdapter({ target: publicTarget, runtime, workflowPlanner: { next } }).observe(context, publicWorkflow);
    expect(result.outcome).toBe('COMPLETED');
    expect(next.mock.calls.map(([input]) => input.executedActions)).toEqual([0, 1, 2]);
  });

  it('rejects external and unsupported planner actions before performing them', async () => {
    for (const action of [{ action: 'navigate', url: 'http://external.example' }, { action: 'eval', script: 'secret' }]) {
      const runtime = fakeRuntime();
      const result = await new TesterArmyE2EAdapter({ target: publicTarget, runtime, workflowPlanner: {
        next: async () => ({ outcome: 'action', action: action as BrowserAction }),
      } }).observe(context, publicWorkflow);
      expect(result.outcome).toBe('FAILED');
      expect(runtime.sessions[0]!.perform).not.toHaveBeenCalled();
      expect(JSON.stringify(result)).not.toContain('secret');
    }
  });

  it('bounds nonterminating action loops and planner time', async () => {
    const runtime = fakeRuntime();
    const loop = await new TesterArmyE2EAdapter({ target: publicTarget, runtime, maxWorkflowActions: 2,
      workflowPlanner: { next: async () => ({ outcome: 'action', action: { action: 'navigate', url: '/' } }) } }).observe(context, publicWorkflow);
    expect(loop.diagnostics[0]?.code).toBe('invalid-workflow');
    expect(runtime.sessions[0]!.perform).toHaveBeenCalledTimes(2);
    const waiting = await new TesterArmyE2EAdapter({ target: publicTarget, runtime, timeoutMs: 25,
      workflowPlanner: { next: async () => new Promise(() => undefined) } }).observe(context, publicWorkflow);
    expect(waiting.diagnostics[0]?.code).toBe('timeout');
    expect(runtime.sessions.every(session => session.close.mock.calls.length === 1)).toBe(true);
  });

  it('reports a timeout when final private-state collection exceeds the budget', async () => {
    const runtime = fakeRuntime();
    const original = runtime.start.getMockImplementation()!;
    runtime.start.mockImplementation(async request => ({ ...await original(request), captureState: async () => new Promise(() => undefined) }));
    const result = await new TesterArmyE2EAdapter({ target: publicTarget, runtime, timeoutMs: 25, resolveGoal: recipe }).observe(context, publicWorkflow);
    expect(result.outcome).toBe('FAILED'); expect(result.diagnostics[0]?.code).toBe('timeout');
    expect(runtime.sessions[0]!.close).toHaveBeenCalledOnce();
  });

  it('retains deterministic recipe priority and safe structured-plan support', async () => {
    const next = vi.fn(async () => ({ outcome: 'unsupported' as const })), runtime = fakeRuntime();
    expect((await new TesterArmyE2EAdapter({ target: publicTarget, runtime, resolveGoal: recipe, workflowPlanner: { next } })
      .observe(context, publicWorkflow)).outcome).toBe('COMPLETED');
    expect(next).not.toHaveBeenCalled();
  });
});

it('keeps fixture names, selectors and routes out of generic runtime and core sources', async () => {
  for (const file of ['adapter.ts', 'runtime.ts', 'policy.ts', 'target.ts', 'authentication.ts', 'sessions.ts', 'types.ts']) {
    expect(await readFile(new URL(`../src/${file}`, import.meta.url), 'utf8')).not.toMatch(/alice|bob|admin|\/login|\/orders|\/api\/orders|orders-table|idor-result|\/sign-in|\/purchases|buyer-one|data-account/i);
  }
  expect(await readFile(new URL('../../../../packages/core/src/browser.ts', import.meta.url), 'utf8')).not.toMatch(/playwright|tester-army|alice|\/orders|\/purchases/i);
});

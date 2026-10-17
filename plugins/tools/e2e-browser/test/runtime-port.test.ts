import { describe, expect, it, vi } from 'vitest';
import type { BrowserContextCookie, BrowserPageInspection, BrowserWorkflowSession } from '@agento/core';
import { TesterArmyE2EAdapter, demoBrowserOptions } from '../src/index.js';
import { context, fakeRuntime, workflow } from './helpers.js';

describe('guarded browser workflow capability port', () => {
  it('returns bounded immutable page data with credentials, raw values and provider fields excluded', async () => {
    const runtime = fakeRuntime(), original = runtime.start.getMockImplementation()!;
    runtime.start.mockImplementation(async request => ({ ...await original(request), inspect: async (): Promise<BrowserPageInspection> => ({
      url: `${request.project.baseUrl}/dashboard?token=private-session-cookie`, title: 'alice123 private-session-cookie',
      headings: ['alice123'], visibleTextSummary: 'alice private-session-cookie visible page data',
      controls: [{ selector: 'form > input', kind: 'input', label: 'alice123 private-session-cookie', enabled: true,
        inputType: 'password', formSelector: 'form', href: `${request.project.baseUrl}/?password=alice123`,
        ...{ value: 'plaintext-input', rawSdk: 'private' } }],
    }) }));
    let inspection: BrowserPageInspection | undefined;
    const result = await new TesterArmyE2EAdapter({ ...demoBrowserOptions(), runtime }).runWorkflow(context, workflow, async port => {
      inspection = await port.inspect();
      expect(Object.isFrozen(inspection.controls)).toBe(true);
      expect(Object.isFrozen(port.persona)).toBe(true);
      expect(inspection.controls[0]).toMatchObject({ enabled: true, inputType: 'password', formSelector: 'form' });
      expect(JSON.stringify(inspection)).not.toMatch(/\balice\b|alice123|private-session-cookie|plaintext-input|rawSdk/);
      await port.perform({ action: 'navigate', url: '/account' });
    });
    expect(result.outcome).toBe('COMPLETED'); expect(inspection?.visibleTextSummary).toContain('visible page data');
    expect(result.evidence.find(item => item.kind === 'browser-observation')?.facts.executedActions).toBe(1);
  });

  it('refuses an external action independently of the workflow planner', async () => {
    const runtime = fakeRuntime();
    const result = await new TesterArmyE2EAdapter({ runtime }).runWorkflow(context, { ...workflow, identityId: 'anonymous' }, async port => {
      await port.perform({ action: 'navigate', url: 'http://external.example' });
    });
    expect(result.outcome).toBe('FAILED'); expect(result.diagnostics[0]?.code).toBe('scope-denied');
    expect(runtime.sessions[0]!.perform).not.toHaveBeenCalled();
  });

  it('revokes escaped capabilities after workflow completion and timeout', async () => {
    const runtime = fakeRuntime();
    let completed: BrowserWorkflowSession | undefined, timedOut: BrowserWorkflowSession | undefined;
    const actor = { ...workflow, identityId: 'anonymous' };
    const adapter = new TesterArmyE2EAdapter({ runtime, timeoutMs: 25 });
    expect((await adapter.runWorkflow(context, actor, async port => { completed = port; })).outcome).toBe('COMPLETED');
    await expect(completed!.perform({ action: 'navigate', url: '/' })).rejects.toMatchObject({ code: 'timeout' });
    const expired = await adapter.runWorkflow(context, actor, async port => { timedOut = port; await new Promise(() => undefined); });
    expect(expired.diagnostics[0]?.code).toBe('timeout');
    await expect(timedOut!.inspect()).rejects.toMatchObject({ code: 'timeout' });
    expect(runtime.sessions.every(session => session.close.mock.calls.length === 1)).toBe(true);
    expect(runtime.sessions.every(session => session.perform.mock.calls.length === 0)).toBe(true);
  });

  it('revokes the port before slow snapshot and session finalization', async () => {
    const runtime = fakeRuntime(), original = runtime.start.getMockImplementation()!;
    let revoked: boolean | undefined;
    runtime.start.mockImplementation(async request => ({ ...await original(request), snapshot: async () => {
      await new Promise(resolve => setTimeout(resolve, 50)); return { url: request.project.baseUrl };
    } }));
    const result = await new TesterArmyE2EAdapter({ runtime }).runWorkflow(context, { ...workflow, identityId: 'anonymous' }, async port => {
      setTimeout(() => { void port.perform({ action: 'navigate', url: '/late' }).then(() => { revoked = false; }, () => { revoked = true; }); }, 10);
    });
    expect(result.outcome).toBe('COMPLETED'); expect(revoked).toBe(true);
    expect(runtime.sessions[0]!.perform).not.toHaveBeenCalled();
  });

  it('refuses changed credential targets after a slow backend resolver', async () => {
    const runtime = fakeRuntime(), original = runtime.start.getMockImplementation()!;
    let path = '/sign-in';
    runtime.start.mockImplementation(async request => ({ ...await original(request), inspect: async () => ({
      url: `${request.project.baseUrl}${path}`, controls: [{ selector: 'input[type=password]', kind: 'input' as const,
        label: 'Password', inputType: 'password' }],
    }) }));
    const credentials = vi.fn(async () => { path = '/unapproved-form'; return { username: 'backend-handle', password: 'backend-password' }; });
    const result = await new TesterArmyE2EAdapter({ runtime, credentials }).runWorkflow(context, { ...workflow, identityId: 'anonymous' }, async port => {
      const page = await port.inspect();
      await port.fillCredential('input[type=password]', 'password', { stateId: page.stateId! });
    });
    expect(result.outcome).toBe('FAILED'); expect(result.diagnostics[0]?.code).toBe('authentication-failed');
    expect(credentials).toHaveBeenCalledOnce(); expect(runtime.sessions[0]!.perform).not.toHaveBeenCalled();
  });

  it('redacts bounded nested JSON storage string leaves', async () => {
    const runtime = fakeRuntime(), original = runtime.start.getMockImplementation()!;
    runtime.start.mockImplementation(async request => ({ ...await original(request), captureState: async () => ({
      format: 'playwright-storage-state', version: 1, data: { cookies: [], origins: [{ origin: request.project.baseUrl,
        localStorage: [{ name: 'nested-session', value: JSON.stringify({ account: { token: 'shortsecret42' } }) }] }] },
    }), inspect: async () => ({ url: request.project.baseUrl, title: 'Account shortsecret42',
      visibleTextSummary: 'Account shortsecret42', controls: [] }) }));
    const result = await new TesterArmyE2EAdapter({ runtime }).runWorkflow(context, { ...workflow, identityId: 'anonymous' }, async port => {
      expect(JSON.stringify(await port.inspect())).not.toContain('shortsecret42');
    });
    expect(result.outcome).toBe('COMPLETED');
  });

  it('bounds controller actions and stops after the native record limit', async () => {
    const runtime = fakeRuntime();
    const result = await new TesterArmyE2EAdapter({ runtime, maxWorkflowActions: 2 }).runWorkflow(context, { ...workflow, identityId: 'anonymous' }, async port => {
      for (let index = 0; index < 3; index++) await port.perform({ action: 'navigate', url: '/' });
    });
    expect(result.diagnostics[0]?.code).toBe('invalid-workflow');
    expect(runtime.sessions[0]!.perform).toHaveBeenCalledTimes(2);
  });

  it('resolves only supported credential references at execution time and redacts reflected values', async () => {
    const credentials = vi.fn(async () => ({ username: 'backend-handle', password: 'backend-password' }));
    const runtime = fakeRuntime({ perform: async (_action, request) => request.onNetwork({
      url: `${request.project.baseUrl}/backend-password`, method: 'GET', status: 200, resourceType: 'fetch', blocked: false,
    }) });
    const result = await new TesterArmyE2EAdapter({ runtime, credentials }).runWorkflow(context, { ...workflow, identityId: 'anonymous' }, async port => {
      expect(credentials).not.toHaveBeenCalled();
      await port.fillCredential('input[type=password]', 'password');
    });
    expect(result.outcome).toBe('COMPLETED'); expect(credentials).toHaveBeenCalledOnce();
    expect(JSON.stringify(result)).not.toContain('backend-password');
    const invalid = await new TesterArmyE2EAdapter({ runtime, credentials }).runWorkflow(context, { ...workflow, identityId: 'anonymous' }, async port => {
      await port.fillCredential('input', 'token' as 'password');
    });
    expect(invalid.diagnostics[0]?.code).toBe('authentication-failed'); expect(credentials).toHaveBeenCalledOnce();
  });
});

describe('private runtime cookie transfer', () => {
  const cookie = { name: 'runtime_sid', value: 'private-runtime-transfer', domain: '127.0.0.1', path: '/',
    expires: -1, httpOnly: true, secure: false, sameSite: 'Lax' as const };
  it('reads and replaces active context cookies without putting raw values in observations', async () => {
    const runtime = fakeRuntime(), original = runtime.start.getMockImplementation()!;
    let current: BrowserContextCookie[] = [cookie];
    runtime.start.mockImplementation(async request => ({ ...await original(request),
      readCookies: async () => current,
      replaceCookies: async (incoming: readonly BrowserContextCookie[]) => { current = [...incoming]; },
    }));
    let escaped: BrowserWorkflowSession | undefined;
    const result = await new TesterArmyE2EAdapter({ runtime }).runWorkflow(context, { ...workflow, identityId: 'anonymous' }, async port => {
      escaped = port;
      const exported = await port.readCookies!();
      expect(exported[0]?.value).toBe('private-runtime-transfer'); expect(Object.isFrozen(exported[0])).toBe(true);
      await port.replaceCookies!([{ ...cookie, value: 'rotated-private-runtime-transfer' }]);
      expect((await port.readCookies!())[0]?.value).toBe('rotated-private-runtime-transfer');
    });
    expect(result.outcome).toBe('COMPLETED');
    expect(JSON.stringify(result)).not.toContain('private-runtime-transfer');
    await expect(escaped!.readCookies!()).rejects.toMatchObject({ code: 'timeout' });
    await expect(escaped!.replaceCookies!([cookie])).rejects.toMatchObject({ code: 'timeout' });
  });
  it('rejects imported cookies outside the configured hosts before changing the context', async () => {
    const runtime = fakeRuntime(), original = runtime.start.getMockImplementation()!;
    let writes = 0;
    runtime.start.mockImplementation(async request => ({ ...await original(request), replaceCookies: async () => { writes++; } }));
    const result = await new TesterArmyE2EAdapter({ runtime }).runWorkflow(context, { ...workflow, identityId: 'anonymous' }, async port => {
      await port.replaceCookies!([{ ...cookie, domain: 'external.example' }]);
    });
    expect(result.outcome).toBe('FAILED'); expect(writes).toBe(0);
  });
});

import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import type { BrowserAction, BrowserPageInspection, JsonValue, PageModel, Project } from '@agento/core';
import * as browser from '../../../plugins/tools/e2e-browser/src/index.ts';
import type { BrowserRuntime, BrowserRuntimeRequest, TesterArmyE2EOptions } from '../../../plugins/tools/e2e-browser/src/types.ts';
import * as workflow from '../../../packages/workflow/src/index.ts';
import { observeBrowserWorkflow } from '../server/workflows.ts';
import { LocalService } from '../server/service.ts';
import { Workspace } from '../server/workspace.ts';
import { workflowNotification, workflowProfiles } from '../src/workflow-catalog.ts';

const origin = 'http://127.0.0.1:3000';
const project: Project = { id: 'live-project', name: 'Storefront', mode: 'black-box', baseUrl: origin,
  allowedOrigins: [origin], languages: [] };
const goal = 'Log in as Alice, explore order history, and verify authorization guards of Bob';

function setup() {
  const actions: BrowserAction[] = [];
  const start = vi.fn(async (request: BrowserRuntimeRequest) => {
    let page: BrowserPageInspection = { url: `${origin}/`, title: 'Storefront', controls: [
      { kind: 'link', selector: '#orders-link', label: 'My order history', href: '/orders.html' },
      { kind: 'link', selector: '#external-link', label: 'External', href: 'https://outside.test/' },
    ] };
    return {
      async perform(action: BrowserAction) {
        actions.push(action);
        if (action.action === 'navigate') {
          request.assertUrl(action.url);
          page = { ...page, url: new URL(action.url, origin).href };
        }
        if (action.action === 'click' && action.selector === '#orders-link') {
          page = { url: `${origin}/orders.html`, title: 'Order history', headings: ['Your orders'], controls: [] };
          request.onNetwork({ url: `${origin}/api/orders`, method: 'GET', status: 200, resourceType: 'fetch', blocked: false });
        }
      },
      inspect: async () => page,
      verify: async () => true,
      captureState: async () => ({ format: 'playwright-storage-state', version: 1, data: { cookies: [], origins: [] } }),
      snapshot: async () => ({ url: page.url }),
      close: vi.fn(async () => undefined),
    };
  });
  const runtime: BrowserRuntime = { start };
  class Driver extends browser.TesterArmyE2EAdapter {
    constructor(options: TesterArmyE2EOptions) { super({ ...options, runtime }); }
  }
  const provider = new workflow.FakeModelProvider(request => {
    const page = (request.input as unknown as { pageModel: PageModel }).pageModel;
    const link = page.navigationCandidates.find(item => item.label === 'My order history');
    return { status: 'completed', value: { pageId: page.id, actionType: link ? 'navigate-within-scope' : 'goal-complete',
      elementId: null, navigationId: link?.id ?? null, inputRef: null, confidence: .9,
      explanation: null, expectedOutcome: 'Order history visible' } as JsonValue, usage: { inputTokens: 50, outputTokens: 30 } };
  });
  const createModelProvider = vi.fn(async () => provider);
  return { actions, start, provider, modules: { browser: { ...browser, TesterArmyE2EAdapter: Driver }, workflow, createModelProvider } };
}

describe('frontend browser workflow execution', () => {
  it('routes the original rejected goal through semantic planning and retains provenance', async () => {
    const { modules, provider, start } = setup();
    const result = await observeBrowserWorkflow(project, { goal, identityId: 'alice' }, modules);
    expect(result).toMatchObject({ outcome: 'COMPLETED', completionType: 'planner-assessed', modelCalls: 2, modelTokens: 160,
      finalUrl: `${origin}/orders.html`, pageModelSummary: { title: 'Order history', headings: ['Your orders'] },
      session: { personaId: 'alice', authenticated: true } });
    expect(start).toHaveBeenCalledOnce();
    expect(result.steps).toEqual(expect.arrayContaining([expect.objectContaining({ actionType: 'navigate-within-scope', outcome: 'completed' })]));
    expect(result.network).toEqual(expect.arrayContaining([expect.objectContaining({ method: 'GET', url: `${origin}/api/orders`, status: 200 })]));
    expect(result.endpoints.some(item => item.path === '/api/orders')).toBe(true);
    expect(result.evidence.some(item => item.facts.completion === 'planner-assessed')).toBe(true);
    const requests = JSON.stringify(provider.requests);
    expect(requests).not.toMatch(/alice123|credentialsRef|#orders-link|OPENAI_API_KEY/);
    expect(requests).toContain('untrusted-application-data');
  });

  it('runs a recognized recipe without loading a model', async () => {
    const { modules } = setup();
    modules.createModelProvider.mockRejectedValue(new Error('must never load'));
    const result = await observeBrowserWorkflow(project, { goal: 'login as alice and open newest order' }, modules);
    expect(result).toMatchObject({ outcome: 'COMPLETED', completionType: 'recipe-completed', modelCalls: 0, modelTokens: 0 });
    expect(modules.createModelProvider).not.toHaveBeenCalled();
  });

  it('reports missing model settings before starting a browser', async () => {
    const { modules, start } = setup();
    const result = await observeBrowserWorkflow(project, { goal }, { ...modules, createModelProvider: async () => undefined });
    expect(result).toMatchObject({ outcome: 'SKIPPED', actionsCount: 0, diagnostics: [{ code: 'planner-unavailable', message: expect.stringContaining('OPENAI_API_KEY') }] });
    expect(start).not.toHaveBeenCalled();
    expect(workflowNotification(result)).toContain('Workflow skipped:');
    expect(workflowNotification(result)).toContain('backend model API key');
  });

  it('honors recipes-only mode and rejects unsupported personas and profiles before execution', async () => {
    const { modules, start } = setup();
    for (const [input, code] of [
      [{ goal, planningMode: 'recipes' as const }, 'unsupported-goal'],
      [{ goal, targetName: 'portal', identityId: 'alice' }, 'invalid-persona'],
      [{ goal, targetName: 'unknown' }, 'invalid-profile'],
    ] as const) {
      expect(await observeBrowserWorkflow(project, input, modules)).toMatchObject({ outcome: 'SKIPPED', diagnostics: [{ code }] });
    }
    expect(modules.createModelProvider).not.toHaveBeenCalled(); expect(start).not.toHaveBeenCalled();
  });

  it('blocks seeded credentials for nonlocal destinations, including extra approved origins', async () => {
    const { modules, start } = setup();
    for (const scoped of [{ ...project, baseUrl: 'https://example.test', allowedOrigins: ['https://example.test'] },
      { ...project, allowedOrigins: [origin, 'https://example.test'] }]) {
      expect(await observeBrowserWorkflow(scoped, { goal: 'open orders' }, modules)).toMatchObject({ outcome: 'SKIPPED', diagnostics: [{ code: 'scope-denied' }] });
    }
    expect(start).not.toHaveBeenCalled(); expect(modules.createModelProvider).not.toHaveBeenCalled();
  });

  it('preserves scope and model failure diagnostics without claiming completion', async () => {
    for (const failure of ['external', 'provider'] as const) {
      const { modules, provider } = setup();
      provider.generateStructured = async request => {
        if (failure === 'provider') throw new Error('api-key=private-provider-secret');
        const page = (request.input as unknown as { pageModel: PageModel }).pageModel;
        return { status: 'completed', value: { pageId: page.id, actionType: 'navigate-within-scope', elementId: null,
          navigationId: page.navigationCandidates.find(item => item.label === 'External')!.id,
          inputRef: null, confidence: .9, explanation: null, expectedOutcome: 'External page' }, usage: { inputTokens: 20, outputTokens: 20 } };
      };
      const result = await observeBrowserWorkflow(project, { goal }, modules);
      expect(result).toMatchObject({ outcome: 'FAILED', completionType: 'unconfirmed', diagnostics: [{ code: failure === 'external' ? 'scope-denied' : 'unable-to-proceed' }] });
      expect(JSON.stringify(result)).not.toContain('private-provider-secret');
    }
  });

  it('uses real profile personas in the public catalog', () => {
    const resolvers = [browser.storefrontBrowserOptions, browser.purchasesBrowserOptions, browser.portalBrowserOptions,
      browser.edgeSpaBrowserOptions, browser.opsConsoleBrowserOptions];
    workflowProfiles.forEach((profile, index) => {
      expect(profile.personas.map(persona => persona.id)).toEqual(resolvers[index]!([origin]).target!.personas!.map(persona => persona.id));
    });
  });

  it('persists semantic results and validates browser request fields at the service boundary', async () => {
    const folder = await mkdtemp(join(tmpdir(), 'agento-semantic-workspace-'));
    const { modules } = setup();
    const execution = { discover: vi.fn(), analyze: vi.fn(),
      observeWorkflow: (project: Project, input: Parameters<typeof observeBrowserWorkflow>[1]) => observeBrowserWorkflow(project, input, modules) };
    try {
      const file = join(folder, 'workspace.json');
      const service = new LocalService(await Workspace.open(file), execution);
      const saved = await service.createProject({ name: 'Local shop', repositoryPath: '/work/shop', baseUrl: origin, allowedOrigins: [origin] });
      for (const invalid of [{ goal: 'x'.repeat(2001) }, { goal, identityId: {} }, { goal, targetName: [] }, { goal, planningMode: 'unsafe' }]) {
        await expect(service.runWorkflow(saved.id, invalid as never)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
      }
      const result = await service.runWorkflow(saved.id, { goal, planningMode: 'automatic' });
      const reopened = new LocalService(await Workspace.open(file), execution);
      expect(await reopened.getWorkflow(saved.id, result.id)).toEqual(result);
      expect(result.modelCalls).toBe(2);
    } finally { await rm(folder, { recursive: true, force: true }); }
  });
});

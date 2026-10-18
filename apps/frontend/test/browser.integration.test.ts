import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { BrowserWorkflowInput, ProjectInput } from '../src/client/types.ts';
import type { JsonValue, PageModel } from '@agento/core';
import * as browser from '../../../plugins/tools/e2e-browser/src/index.ts';
import * as workflow from '../../../packages/workflow/src/index.ts';
import { observeBrowserWorkflow } from '../server/workflows.ts';
import { createLocalApi } from '../server/api.ts';
import { createHttpClient } from '../src/client/http-client.ts';
import { Workspace } from '../server/workspace.ts';
import { fileURLToPath } from 'node:url';

describe.skipIf(process.env.AGENTO_FRONTEND_BROWSER_INTEGRATION !== '1')('natural-language workflows over HTTP and Chromium', () => {
  let target: Server, api: Server, origin: string, apiOrigin: string, folder: string;
  let closeApi: () => Promise<void>;
  const providers: workflow.FakeModelProvider[] = [];

  beforeAll(async () => {
    folder = await mkdtemp(join(tmpdir(), 'agento-frontend-browser-'));
    const { createApp } = await import(new URL('../../../demo-apps/demo-app-03/src/app.ts', import.meta.url).pathname);
    target = createServer(createApp()); origin = await listen(target);
    const middleware = createLocalApi({ root: fileURLToPath(new URL('../../..', import.meta.url)), file: join(folder, 'workspace.json'),
      execution: { discover: async () => { throw new Error('Unused'); }, analyze: async () => { throw new Error('Unused'); },
        observeWorkflow: (project, input: BrowserWorkflowInput) => observeBrowserWorkflow(project, input, { browser, workflow,
          createModelProvider: async () => {
            const provider = new workflow.FakeModelProvider(request => {
              const page = (request.input as unknown as { pageModel: PageModel }).pageModel;
              const candidate = page.navigationCandidates.find(item => item.label === 'Open latest report')
                ?? page.navigationCandidates.find(item => item.label === 'Audit Reports');
              return { status: 'completed', value: { pageId: page.id,
                actionType: candidate ? 'navigate-within-scope' : 'goal-complete', elementId: null,
                navigationId: candidate?.id ?? null, inputRef: null, confidence: .95, explanation: null,
                expectedOutcome: 'Latest audit report visible' } as JsonValue, usage: { inputTokens: 80, outputTokens: 30 } };
            });
            providers.push(provider); return provider;
          },
        }),
      } });
    closeApi = middleware.close;
    api = createServer((request, response) => { void middleware(request, response, () => { response.statusCode = 404; response.end(); }); });
    apiOrigin = await listen(api);
  }, 30_000);

  afterAll(async () => {
    await Promise.all([target, api].filter(Boolean).map(server => new Promise<void>(resolve => server.close(() => resolve()))));
    await closeApi?.();
    if (folder) await rm(folder, { recursive: true, force: true });
  });

  it('authenticates the selected persona, explores live controls, and saves semantic provenance', async () => {
    const client = createHttpClient((path, options) => fetch(`${apiOrigin}${path}`, options));
    const input: ProjectInput = { name: 'Audit portal', repositoryPath: '/work/portal', baseUrl: `${origin}/dashboard`, allowedOrigins: [origin] };
    const project = await client.createProject(input);
    const result = await client.runWorkflow(project.id, { targetName: 'portal', identityId: 'analyst',
      planningMode: 'automatic', goal: 'Explore the portal and inspect the most recent audit report.' });
    expect(result).toMatchObject({ outcome: 'COMPLETED', completionType: 'planner-assessed', modelCalls: 3,
      finalUrl: `${origin}/reports/REP-501`, session: { authenticated: true, personaId: 'analyst' } });
    expect(result.diagnostics).toEqual([]);
    expect(result.steps).toHaveLength(2);
    expect(result.endpoints.some(endpoint => endpoint.path === '/reports/REP-501')).toBe(true);
    expect(result.network.some(request => request.url === `${origin}/reports/REP-501` && request.status === 200)).toBe(true);
    expect(JSON.stringify(providers[0]!.requests)).not.toMatch(/Analyst!123|credentialsRef|#link-reports|#open-report-btn/);
    expect(await client.getWorkflow(project.id, result.id)).toEqual(result);
    const restored = await Workspace.open(join(folder, 'workspace.json'));
    expect(restored.read()[0]!.workflows?.[0]).toEqual(result);
    expect(result.pageModelSummary?.title).toContain('REP-501');
    const model = await client.getSecurityModel(project.id);
    expect(model.model.endpoints.some(endpoint => endpoint.path === '/reports/REP-501')).toBe(true);
    expect(model.model.identities).toContainEqual(expect.objectContaining({ id: 'analyst', label: 'Analyst' }));
    expect(model.inputs[0]).toMatchObject({ runId: result.id, source: 'browser', included: true });
    expect(JSON.stringify(model)).not.toMatch(/Analyst!123|credentialsRef|apiKey/);
  }, 60_000);
});

function listen(server: Server): Promise<string> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`));
  });
}

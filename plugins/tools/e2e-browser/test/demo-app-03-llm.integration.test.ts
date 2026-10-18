import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AnalysisContext, TargetApplicationProfile } from '@agento/core';
import {
  TesterArmyE2EAdapter,
  portalBrowserOptions,
} from '../src/index.js';
import { BrowserWorkflowOrchestrator, LLMWorkflowPlanner } from '../../../../packages/workflow/dist/index.js';
import { createOpenAIModelProvider } from '../../../models/openai/dist/index.js';

const suite = process.env.AGENTO_OPENAI_INTEGRATION === '1' ? describe : describe.skip;

function listen(server: Server): Promise<string> {
  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${address.port}`);
    });
    server.on('error', reject);
  });
}

function close(server: Server): Promise<void> {
  return new Promise(resolve => server.close(() => resolve()));
}

function contextFor(baseUrl: string, target: TargetApplicationProfile): AnalysisContext {
  return {
    project: {
      id: `project-${target.id}`,
      name: target.id,
      mode: 'black-box',
      baseUrl,
      allowedOrigins: target.baseOrigins,
      languages: [],
    },
    components: [],
    endpoints: [],
    identities: target.personas ?? [],
    resources: [],
    signals: [],
    evidence: [],
  };
}

suite('Live LLM-assisted unscripted planning on Demo App 03 (Audit Portal)', () => {
  let portalServer: Server;
  let portalOrigin: string;

  beforeAll(async () => {
    const { createApp: createPortalApp } = await import(
      new URL('../../../../demo-apps/demo-app-03/src/app.ts', import.meta.url).pathname
    );
    portalServer = createServer(createPortalApp());
    portalOrigin = await listen(portalServer);
  }, 30_000);

  afterAll(async () => {
    await Promise.all([portalServer].filter(Boolean).map(close));
  });

  it('navigates from Dashboard to Reports to Detail using live LLM reasoning without any hardcoded recipes', async () => {
    const baseOptions = portalBrowserOptions([portalOrigin]);
    // Strip workflow hints and recipes to force the LLM to dynamically plan every step
    const target: TargetApplicationProfile = {
      ...baseOptions.target!,
      workflowHints: {},
    };

    const realProvider = createOpenAIModelProvider();
    const provider = {
      id: realProvider.id,
      async generateStructured(req: any) {
        console.log('LLM REQUEST INPUT:', JSON.stringify(req.input, null, 2));
        const res = await realProvider.generateStructured(req);
        console.log('LLM RESPONSE:', JSON.stringify(res, null, 2));
        return res;
      }
    };
    const planner = new LLMWorkflowPlanner(provider as any, {
      maxModelCalls: 8,
      callTimeoutMs: 30_000,
      minimumConfidence: 0.5,
    });

    const driver = new TesterArmyE2EAdapter({
      target,
      ...(baseOptions.credentials ? { credentials: baseOptions.credentials } : {}),
    });

    const orchestrator = new BrowserWorkflowOrchestrator({
      driver,
      target,
      semanticPlanner: planner,
      completion: ({ pageModel, network }) => {
        const foundApi = network.some(r => r.url === `${portalOrigin}/reports/REP-501` && r.status === 200);
        const onReportPage = pageModel.visibleTextSummary.includes('Report Opened')
          || pageModel.headings.some(h => h.includes('REP-501'));
        return foundApi || onReportPage;
      },
    });

    const ctx = contextFor(portalOrigin, target);
    const observation = await orchestrator.observe(ctx, {
      id: 'unscripted-audit-goal',
      identityId: 'analyst',
      goal: 'Open the latest audit report',
    });

    if (observation.outcome !== 'COMPLETED') {
      console.log('FAILURE DIAGNOSTICS:', JSON.stringify(observation.diagnostics, null, 2));
      console.log('OBSERVATION EVIDENCE:', JSON.stringify(observation.evidence, null, 2));
    }
    expect(observation.outcome).toBe('COMPLETED');
    expect(observation.diagnostics).toEqual([]);

    // Verify model was actively consulted in workflow evidence
    const workflowEv = observation.evidence.find(
      e => e.kind === 'browser-observation' && e.summary.includes('planning')
    );
    expect(workflowEv).toBeDefined();
    expect((workflowEv?.facts as any).modelCalls).toBeGreaterThanOrEqual(1);

    // Verify the report was reached and recorded in evidence
    const reportEvidence = observation.evidence.find(
      e => e.kind === 'http-response' && e.facts.url === `${portalOrigin}/reports/REP-501`
    );
    expect(reportEvidence).toBeDefined();
    expect(reportEvidence?.facts.status).toBe(200);
  }, 120_000);
});

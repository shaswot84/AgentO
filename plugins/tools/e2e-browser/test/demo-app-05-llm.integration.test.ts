import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AnalysisContext, TargetApplicationProfile } from '@agento/core';
import {
  TesterArmyE2EAdapter,
  opsConsoleBrowserOptions,
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

suite('Live LLM-assisted unscripted planning on Demo App 05 (Cloud Ops Console)', () => {
  let opsServer: Server;
  let opsOrigin: string;

  beforeAll(async () => {
    const { createApp: createOpsApp } = await import(
      new URL('../../../../demo-apps/demo-app-05/src/app.ts', import.meta.url).pathname
    );
    opsServer = createServer(createOpsApp());
    opsOrigin = await listen(opsServer);
  }, 30_000);

  afterAll(async () => {
    await Promise.all([opsServer].filter(Boolean).map(close));
  });

  it('autonomously navigates tabs, inspects incident modal, and triggers acknowledgment using LLM planning', async () => {
    const baseOptions = opsConsoleBrowserOptions([opsOrigin]);
    // Strip workflow hints and recipes to force the LLM to dynamically plan every step
    const target: TargetApplicationProfile = {
      ...baseOptions.target!,
      workflowHints: {},
    };

    const provider = createOpenAIModelProvider();
    const planner = new LLMWorkflowPlanner(provider, {
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
        const ackObserved = network.some(
          r => r.url === `${opsOrigin}/api/triage/INC-9942/acknowledge` && r.status === 200
        );
        const onPageEscalated = pageModel.visibleTextSummary.includes('Escalated to Commander');
        return ackObserved || onPageEscalated;
      },
    });

    const ctx = contextFor(opsOrigin, target);
    const observation = await orchestrator.observe(ctx, {
      id: 'unscripted-triage-goal',
      identityId: 'responder',
      goal: 'Examine and acknowledge the critical security incident',
    });

    expect(observation.outcome).toBe('COMPLETED');
    expect(observation.diagnostics).toEqual([]);

    // Verify model was actively consulted in workflow evidence
    const workflowEv = observation.evidence.find(
      e => e.kind === 'browser-observation' && e.summary.includes('planning')
    );
    expect(workflowEv).toBeDefined();
    expect((workflowEv?.facts as any).modelCalls).toBeGreaterThanOrEqual(1);

    // Verify acknowledgment API call was dispatched and captured
    const ackEvidence = observation.evidence.find(
      e => e.kind === 'http-response' && e.facts.url === `${opsOrigin}/api/triage/INC-9942/acknowledge`
    );
    expect(ackEvidence).toBeDefined();
    expect(ackEvidence?.facts.status).toBe(200);
  }, 120_000);
});

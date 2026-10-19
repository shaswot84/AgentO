import { expect, it } from 'vitest';
import { AgentOOrchestrator } from '@agento/core';
import { CWE614Plugin, toCoreEvidence } from '@agento/cwe';
import { MemoryEvidenceStore } from '@agento/evidence';
import { VerificationJudge } from '../src/index.js';
import { context, cookies, route } from './helpers.js';

it('uses captured proof through the core verification port and exports the final finding', async () => {
  const rule = new CWE614Plugin({ sensitiveCookieNames: ['sid'] });
  const ctx = context();
  const store = new MemoryEvidenceStore();
  const verifier = new VerificationJudge({ plugins: [rule], evidenceStore: store });
  const report = await new AgentOOrchestrator({ plugins: [rule], verifier, evidenceStore: store,
    frameworkAdapter: { id: 'framework', capabilities: ['route-extraction'], supports: async () => true,
      extract: async () => ({ components: ctx.components, endpoints: ctx.endpoints, resources: ctx.resources,
        signals: ctx.signals, evidence: [route] }) },
    scanner: { id: 'runner', capabilities: ['probe:cookie-security', 'request-executor', 'response-collector', 'cookie-analyzer',
      'authentication-manager', 'cookie-inspector'], execute: async (_context, plan) => ({ id: 'result',
        planId: plan.id, producerId: 'runner', outcome: 'COMPLETED', summary: 'Cookie probe.',
        evidence: [toCoreEvidence(cookies(), 'order')] }) },
  }).run({ project: ctx.project, identities: ctx.identities });
  expect(report.findings[0]!.status).toBe('CONFIRMED');
  expect(store.exportFinding(report.findings[0]!).evidence).toHaveLength(2);
});

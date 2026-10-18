import { describe, expect, it, vi } from 'vitest';
import { AgentOOrchestrator, type SecurityScanner } from '@agento/core';
import { CWE1004Plugin, toCoreEvidence } from '@agento/cwe';
import { SecurityTestPlanner, type StructuredTestPlan } from '../src/index.js';
import { bindings, candidate, flatModel, model, project } from './helpers.js';

describe('rule and core compatibility', () => {
  it.each([false, true])('preserves plan/evidence association for a cookie target (fixed: %s)', async fixed => {
    const { planner, context, hypothesis, rule } = await candidate('CWE-1004', model(fixed));
    const plan = (await planner.plan(context, hypothesis, bindings)).plans[0]!;
    const proof = toCoreEvidence({ id: 'observed-cookie', probeId: 'cookie-security', projectId: project.id,
      capturedAt: '2026-10-18T00:00:00Z', outcome: 'COMPLETED', diagnostics: [], observations: [{
        identityId: 'alice', context: 'authenticated', response: { responseId: 'response', url: 'https://shop.test/orders/123',
          method: 'GET', status: 200, body: { sha256: 'a'.repeat(64), byteLength: 1, truncated: false },
          timings: { startedAt: '2026-10-18T00:00:00Z', firstByteMs: 1, durationMs: 2 } },
        cookies: [{ name: 'sid', value: '[REDACTED]', domain: 'shop.test', path: '/', hostOnly: true,
          httpOnly: fixed, secure: fixed, sameSite: 'Lax', expiresAt: null, maxAge: null, partitioned: false, source: 'response' }],
      }] }, plan.endpointId);
    const finding = await rule.evaluateEvidence(context, hypothesis, [{ id: 'result', planId: plan.id,
      producerId: 'synthetic-probe-host', outcome: 'COMPLETED', summary: 'Synthetic collected observations', evidence: [proof] }]);
    expect(finding.testPlanIds).toEqual([plan.id]); expect(finding.evidenceIds).toEqual([proof.id]);
    expect(finding.status).toBe(fixed ? 'REJECTED' : 'CONFIRMED');
  });

  it.each([false, true])('wires the optional core planner and keeps blocked drafts from dispatch (blocked: %s)', async blocked => {
    const context = flatModel(model(false, { path: '/orders', parameters: [] }));
    const rule = new CWE1004Plugin(blocked ? {} : { sensitiveCookieNames: ['sid'] });
    const planner = new SecurityTestPlanner({ plugins: [rule] });
    const planCall = vi.spyOn(planner, 'generateTests');
    const execute = vi.fn<SecurityScanner['execute']>(async (_context, plan) => {
      expect((plan as StructuredTestPlan).readiness).toBe('READY');
      expect(plan.steps.at(-1)!.action).toBe('verify');
      return { id: 'result', planId: plan.id, producerId: 'synthetic-host', outcome: 'COMPLETED', summary: 'No collected proof', evidence: [] };
    });
    const report = await new AgentOOrchestrator({ plugins: [rule], testPlanner: planner,
      frameworkAdapter: { id: 'fixture', capabilities: [], supports: async () => true,
        extract: async () => ({ components: context.components, endpoints: context.endpoints,
          resources: context.resources, signals: context.signals, evidence: context.evidence }) },
      scanner: { id: 'synthetic-host', capabilities: ['probe:cookie-security', 'request-executor', 'response-collector',
        'cookie-analyzer', 'authentication-manager', 'cookie-inspector'], execute },
    }).run({ project, identities: context.identities });
    expect(planCall).toHaveBeenCalledOnce(); expect(execute).toHaveBeenCalledTimes(blocked ? 0 : 1);
    expect(report.plans).toHaveLength(blocked ? 0 : 1);
    expect(report.findings[0]!.status).toBe('NOT_REPRODUCED');
  });
});

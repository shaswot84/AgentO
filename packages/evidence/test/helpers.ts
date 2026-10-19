import type { CoreProviders, Evidence, Finding, Project } from '@agento/core';

export const project: Project = { id: 'shop', name: 'Synthetic shop', mode: 'code-aware', baseUrl: 'https://shop.test',
  allowedOrigins: ['https://shop.test'], languages: ['typescript'] };
export const scope = { project, capabilityIds: ['request-executor', 'response-collector'], environmentId: 'test' };
export function evidence(id = 'proof', extra: Partial<Evidence> = {}): Evidence {
  return { id, projectId: project.id, kind: 'http-response', producerId: 'probe:authorization',
    capturedAt: '2026-10-19T00:00:00Z', summary: 'Synthetic response observation.',
    facts: { status: 200, responseId: 'response', headers: { 'content-type': ['application/json'] } }, ...extra };
}
export function finding(ids = ['proof'], extra: Partial<Finding> = {}): Finding {
  return { id: 'finding', projectId: project.id, hypothesisId: 'hypothesis', cweId: 'CWE-639', owaspCategory: 'A01',
    title: 'Synthetic finding', status: 'CONFIRMED', severity: 'high', confidence: 'high',
    rootCause: 'Synthetic explanation.', evidenceIds: ids, testPlanIds: [], ...extra };
}

export function fakeProviders(): CoreProviders {
  return {
    plugins: [{ cweId: 'CWE-639',
      detectCandidates: async context => [{ id: 'hypothesis', projectId: project.id, cweId: 'CWE-639', status: 'HYPOTHESIS',
        reason: 'Synthetic candidate.', evidenceIds: context.evidence.map(item => item.id) }],
      generateTests: async () => [{ id: 'plan', hypothesisId: 'hypothesis', cweId: 'CWE-639', executor: 'scanner',
        requiredCapabilities: ['synthetic-check'], risk: 'passive', targetUrl: project.baseUrl, identityIds: [], steps: [] }],
      evaluateEvidence: async (_context, _hypothesis, results) => finding(results.flatMap(result => result.evidence.map(item => item.id))),
    }],
    frameworkAdapter: { id: 'framework', capabilities: ['route-extraction'], supports: async () => true,
      extract: async () => ({ components: [], endpoints: [], resources: [], signals: [], evidence: [evidence('source', { kind: 'source-location' })] }) },
    staticAnalyzer: { id: 'static', capabilities: ['static-analysis'], analyze: async () => ({ signals: [],
      evidence: [evidence('static', { kind: 'static-analysis' })] }) },
    browser: { id: 'browser', capabilities: ['browser-observation'],
      observe: async () => ({ endpoints: [], resources: [], signals: [], evidence: [evidence('browser', { kind: 'browser-observation' })] }),
      execute: async () => { throw new Error('unused'); } },
    scanner: { id: 'scanner', capabilities: ['synthetic-check'], execute: async (_context, plan) => ({
      id: 'result', planId: plan.id, producerId: 'scanner', outcome: 'COMPLETED', summary: 'Synthetic test.',
      evidence: [evidence('proof', { producerId: 'fake-scanner' })],
    }) },
  };
}

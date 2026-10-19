import type { Evidence, Finding, FindingStatus, SecurityHypothesis, SecurityTestPlan, SecurityTestResult } from '@agento/core';
import { MemoryEvidenceStore } from '@agento/evidence';
import type { ReportInput } from '../src/index.js';

export function fixture(status: FindingStatus = 'CONFIRMED') {
  const project = { id: 'project', name: 'Example service', mode: 'code-aware' as const,
    baseUrl: 'https://example.test', repositoryPath: '/private/repository', allowedOrigins: ['https://example.test'], languages: ['typescript'] };
  const source = { file: 'src/routes/orders.ts', startLine: 24, endLine: 28 };
  const store = new MemoryEvidenceStore();
  const raw: Evidence[] = [
    { id: 'source', projectId: project.id, kind: 'source-location', producerId: 'express', capturedAt: '2026-10-19T10:00:00Z',
      summary: 'Order handler reads a caller-selected order.', source, endpointId: 'orders', facts: { operation: 'order.lookup' } },
    { id: 'runtime', projectId: project.id, kind: 'authorization', producerId: 'probe:authorization', capturedAt: '2026-10-19T10:01:00Z',
      summary: 'The second user received the owner response.', endpointId: 'orders', facts: {
        request: { method: 'GET', url: 'https://example.test/api/orders/102' }, response: { status: 200 },
        ownerMarkersMatch: true, bodyEqual: true,
      } },
  ];
  store.capture([raw[0]!], { project, capabilityIds: ['framework-analysis'] });
  store.capture([raw[1]!], { project, capabilityIds: ['request-executor', 'response-collector'], probeId: 'authorization', targetUrl: 'https://example.test/api/orders/102' });
  const hypothesis: SecurityHypothesis = { id: 'hypothesis', projectId: project.id, status: 'HYPOTHESIS', cweId: 'CWE-639',
    reason: 'A caller-selected order requires an ownership check.', endpointId: 'orders', source, evidenceIds: ['source'] };
  const plan: SecurityTestPlan = { id: 'plan', hypothesisId: hypothesis.id, cweId: hypothesis.cweId, executor: 'browser', risk: 'active',
    targetUrl: 'https://example.test/api/orders/102?token=private-value', identityIds: ['owner', 'attacker'],
    requiredCapabilities: ['request-executor', 'response-collector'], steps: [
      { id: 'owner', action: 'Read the order as its owner', parameters: { password: 'PRIVATE_PASSWORD', valueRef: 'private:order-id' }, expectedObservation: 'Retain the successful baseline response.' },
      { id: 'attacker', action: 'Read the same order as a second user', parameters: { sessionRef: 'PRIVATE_SESSION' }, expectedObservation: 'Compare status, body hashes, and private owner marker matches.' },
    ] };
  const result: SecurityTestResult = { id: 'result', planId: plan.id, producerId: 'probe:authorization', outcome: 'COMPLETED',
    summary: 'PRIVATE_ADAPTER_DEBUG', evidence: [store.get('runtime')!] };
  const finding: Finding = { id: 'finding', projectId: project.id, hypothesisId: hypothesis.id, cweId: hypothesis.cweId,
    owaspCategory: 'A01:2025', title: 'Order ownership check is missing', status, severity: 'high', confidence: 'high',
    rootCause: 'The second user received a complete response that matched the private order markers.',
    endpointId: 'orders', source, evidenceIds: ['source', 'runtime'], testPlanIds: ['plan'] };
  const input: ReportInput = { context: { project, endpoints: [{ id: 'orders', componentId: 'app', method: 'GET', path: '/api/orders/:id',
    parameters: [{ name: 'id', location: 'path', required: true }], authentication: 'required', roles: [], handler: source, evidenceIds: ['source'] }] },
    hypotheses: [hypothesis], findings: [finding], plans: [plan], results: [result], decisions: [{ finding,
      staticEvidenceIds: ['source'], runtimeEvidenceIds: ['runtime'], diagnostics: [] }] };
  return { project, store, input, finding, hypothesis, plan, result, source };
}
export const generatedAt = '2026-10-19T10:02:00Z';

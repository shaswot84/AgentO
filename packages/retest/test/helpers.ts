import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { vi } from 'vitest';
import type { AnalysisContext, Evidence, Finding } from '@agento/core';
import { CWE639Plugin, toCoreEvidence, type ProbeTestPlan } from '@agento/cwe';
import type { AuthorizationEvidence, HttpResponseEvidence } from '@agento/runtime';
import { MemoryEvidenceStore } from '@agento/evidence';
import { ExpressRemediationProvider } from '@agento/remediation';
import { RetestEngine, type RetestInput } from '../src/index.js';

export const repository = fileURLToPath(new URL('../../../demo-apps/demo-app-01/', import.meta.url));
export const digest = (value: string) => createHash('sha256').update(value).digest('hex');
export const response = (url: string, status = 200): HttpResponseEvidence => ({ responseId: 'response', url, method: 'GET', status,
  body: { sha256: digest(String(status)), byteLength: 10, truncated: false },
  timings: { startedAt: '2026-10-19T12:00:00Z', firstByteMs: 1, durationMs: 2 } });
export function authorization(url: string, blocked = false): AuthorizationEvidence {
  const comparison = { statusDelta: 0, bodyEqual: true, byteLengthDelta: 0, durationDeltaMs: 0, ownerMarkersMatch: !blocked };
  return { id: 'original-probe', projectId: 'demo', probeId: 'authorization', capturedAt: '2026-10-19T12:00:00Z',
    outcome: 'COMPLETED', diagnostics: [], resourceId: 'order', ownerIdentityId: 'alice', attackerIdentityId: 'bob',
    owner: response(url), attacker: response(url, blocked ? 403 : 200), anonymous: response(url, 401),
    attackerComparison: comparison, anonymousComparison: { ...comparison, ownerMarkersMatch: false } };
}
export async function fixture() {
  const project = { id: 'demo', name: 'Synthetic original-probe fixture', mode: 'code-aware' as const,
    baseUrl: 'https://127.0.0.1:3443', allowedOrigins: ['https://127.0.0.1:3443'], languages: ['typescript'], repositoryPath: repository };
  const store = new MemoryEvidenceStore();
  const rule = new CWE639Plugin();
  const path = 'src/routes/orders.ts', content = readFileSync(repository + path, 'utf8');
  const source = store.capture([{ id: 'source', projectId: project.id, kind: 'source-location', producerId: 'snapshot',
    capturedAt: '2026-10-19T12:00:00Z', source: { file: path, startLine: 1 }, summary: 'Synthetic source binding.',
    facts: { sourceSha256: digest(content) } }], { project, capabilityIds: ['source-snapshot'] });
  const targetUrl = project.baseUrl + '/api/orders/101';
  const plan: ProbeTestPlan = { id: 'plan', hypothesisId: 'hypothesis', cweId: 'CWE-639', executor: 'scanner',
    requiredCapabilities: rule.metadata().requiredCapabilities, identityIds: ['alice', 'bob'], risk: 'active', targetUrl,
    probeId: 'authorization', scope: { projectId: project.id, targetUrl, method: 'GET',
      authorization: { resourceId: 'order', ownerIdentityId: 'alice', attackerIdentityId: 'bob', attackerIsUnauthorized: true, anonymousIsUnauthorized: true } },
    steps: [{ id: 'replay', action: 'Replay original resource request', parameters: { privateBinding: 'PRIVATE_INPUT' }, expectedObservation: 'Compare access.' }] };
  const before = store.capture([toCoreEvidence(authorization(targetUrl), 'endpoint')], {
    project, targetUrl, probeId: plan.probeId, capabilityIds: plan.requiredCapabilities });
  const context: AnalysisContext = { project, identities: [], components: [], resources: [], signals: [],
    endpoints: [{ id: 'endpoint', componentId: 'app', path: '/api/orders/:id', method: 'GET', roles: [], parameters: [], authentication: 'required', evidenceIds: ['source'] }],
    evidence: [...source, ...before] };
  const finding: Finding = { id: 'finding', projectId: project.id, hypothesisId: 'hypothesis', cweId: 'CWE-639',
    owaspCategory: 'A01:2025', status: 'CONFIRMED', title: 'Synthetic confirmed resource disclosure', confidence: 'high', severity: 'high',
    rootCause: 'Synthetic authorization fixture.', endpointId: 'endpoint', evidenceIds: ['source', before[0]!.id], testPlanIds: [plan.id] };
  const provider = new ExpressRemediationProvider({ evidenceStore: store, sources: [{ path, content, sha256: digest(content), evidenceIds: ['source'] }] });
  const remediation = await provider.suggest(context, finding);
  const input: RetestInput = { context, finding, plan, remediation,
    originalResult: { id: 'result', planId: plan.id, producerId: 'probe-runner', outcome: 'COMPLETED', summary: 'Synthetic original probe.', evidence: before } };
  const session = { id: 'isolated:test', baseUrl: 'https://127.0.0.1:4444',
    runRegression: vi.fn(async () => ({ security: 'PASSED' as const, normalFlow: 'PASSED' as const })),
    replay: vi.fn(async (_plan: ProbeTestPlan, targetUrl: string) => authorization(targetUrl, true)), dispose: vi.fn(async () => {}) };
  const environment = { create: vi.fn(async () => session) };
  const engine = new RetestEngine({ evidenceStore: store, rules: [rule], environment });
  return { input, store, rule, session, environment, engine };
}

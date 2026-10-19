import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { AnalysisContext, CWEId, Evidence, Finding, SecurityHypothesis, SecurityTestPlan, SecurityTestResult } from '@agento/core';
import { MemoryEvidenceStore } from '@agento/evidence';
import { recipes } from '../src/catalog.js';
import { ExpressRemediationProvider, sourceDigest, type SourceSnapshot } from '../src/index.js';

export const repository = fileURLToPath(new URL('../../../demo-apps/demo-app-01/', import.meta.url));
export function fixture(cweId: CWEId = 'CWE-639') {
  const recipe = recipes.find(item => item.cweId === cweId)!;
  const project = { id: 'demo', name: 'Synthetic confirmed input', mode: 'code-aware' as const, repositoryPath: repository,
    baseUrl: 'https://127.0.0.1:3443', allowedOrigins: ['https://127.0.0.1:3443'], languages: ['typescript'] };
  const store = new MemoryEvidenceStore();
  const sources: SourceSnapshot[] = recipe.files.map(file => {
    const content = readFileSync(repository + file.path, 'utf8');
    return { path: file.path, content, sha256: sourceDigest(content), evidenceIds: ['snapshot:' + file.path] };
  });
  const raw: Evidence[] = sources.map(source => ({ id: source.evidenceIds[0]!, projectId: project.id, kind: 'source-location',
    producerId: 'host-source-snapshot', capturedAt: '2026-10-19T10:00:00Z', summary: 'Synthetic source snapshot binding',
    source: { file: source.path, startLine: 1 }, facts: { sourceSha256: source.sha256, synthetic: true } }));
  const sourceEvidence = store.capture(raw, { project, capabilityIds: ['source-snapshot'] });
  const targetUrl = project.baseUrl + recipe.endpoint.replace(':id', '101');
  const runtime = store.capture([{ id: 'runtime', projectId: project.id, kind: 'http-response', producerId: 'synthetic-probe',
    capturedAt: '2026-10-19T10:01:00Z', endpointId: 'endpoint', summary: 'Synthetic confirmation supplied by caller', facts: { synthetic: true } }],
  { project, capabilityIds: ['synthetic-probe'], targetUrl });
  const context: AnalysisContext = { project, components: [], identities: [], resources: [], signals: [],
    endpoints: [{ id: 'endpoint', componentId: 'app', path: recipe.endpoint,
      method: ['CWE-1004', 'CWE-614'].includes(cweId) ? 'POST' : 'GET', authentication: 'unknown', parameters: [], roles: [],
      handler: { file: sources[0]!.path, startLine: 1 }, evidenceIds: [raw[0]!.id] }], evidence: [...sourceEvidence, ...runtime] };
  const hypothesis: SecurityHypothesis = { id: 'hypothesis', projectId: project.id, cweId, status: 'HYPOTHESIS',
    reason: 'Synthetic candidate', endpointId: 'endpoint', evidenceIds: [raw[0]!.id] };
  const finding: Finding = { id: 'finding', hypothesisId: hypothesis.id, projectId: project.id, cweId, owaspCategory: 'A01',
    title: 'Synthetic confirmed input', status: 'CONFIRMED', severity: 'high', confidence: 'high', rootCause: 'Synthetic fixture',
    endpointId: 'endpoint', evidenceIds: [...sourceEvidence.map(item => item.id), 'runtime'], testPlanIds: ['plan'] };
  const plan: SecurityTestPlan = { id: 'plan', hypothesisId: hypothesis.id, cweId, executor: 'scanner', risk: 'passive', targetUrl,
    requiredCapabilities: ['synthetic-probe'], identityIds: [], steps: [{ id: 'observe', action: 'Synthetic observation', parameters: {}, expectedObservation: 'Synthetic runtime record' }] };
  const result: SecurityTestResult = { id: 'result', planId: plan.id, producerId: 'synthetic-probe', outcome: 'COMPLETED', summary: 'Synthetic result', evidence: runtime };
  return { context, finding, sources, store, hypothesis, plan, result,
    provider: new ExpressRemediationProvider({ evidenceStore: store, sources }) };
}

import { writeFileSync } from 'node:fs';
import { MemoryEvidenceStore } from '@agento/evidence';
import { buildSecurityReport, reportToJSON, reportToMarkdown } from '../dist/index.js';

// Synthetic documentation fixture. This script does not access a target.
const project = { id: 'synthetic-example', name: 'Synthetic report example (not a live scan)',
  mode: 'code-aware', baseUrl: 'https://example.invalid', allowedOrigins: ['https://example.invalid'], languages: ['typescript'] };
const source = { file: 'src/routes/orders.ts', startLine: 24, endLine: 28 };
const store = new MemoryEvidenceStore();
try {
  store.capture([{ id: 'example:source', projectId: project.id, kind: 'source-location', producerId: 'documentation-fixture',
    capturedAt: '2026-10-19T10:00:00Z', summary: 'Synthetic source observation for the order handler.',
    source, endpointId: 'orders', facts: { operation: 'order.lookup', input: 'id', fixture: true } }],
  { project, capabilityIds: ['framework-analysis'], environmentId: 'synthetic' });
  const hypothesis = { id: 'example:ownership', projectId: project.id, cweId: 'CWE-639', status: 'HYPOTHESIS',
    reason: 'A caller-selected order identifier needs an ownership check. Runtime verification is pending.',
    endpointId: 'orders', source, evidenceIds: ['example:source'] };
  const plan = { id: 'example:authorization-plan', hypothesisId: hypothesis.id, cweId: hypothesis.cweId,
    executor: 'browser', risk: 'active', targetUrl: 'https://example.invalid/api/orders/:id', identityIds: ['owner', 'second-user'],
    requiredCapabilities: ['authentication-manager', 'request-executor', 'response-comparator'], steps: [
      { id: 'baseline', action: 'Read an owned order as the owner', parameters: {}, expectedObservation: 'Collect a complete successful baseline.' },
      { id: 'control', action: 'Read the same order as an unauthorized second user', parameters: {}, expectedObservation: 'Compare status, response hashes, and private owner markers.' },
    ] };
  const report = buildSecurityReport({ context: { project, endpoints: [{ id: 'orders', componentId: 'app', method: 'GET',
    path: '/api/orders/:id', parameters: [{ name: 'id', location: 'path', required: true }], authentication: 'required',
    roles: [], handler: source, evidenceIds: ['example:source'] }] }, hypotheses: [hypothesis], findings: [], plans: [plan] },
  { evidenceStore: store, generatedAt: '2026-10-19T10:02:00Z' });
  writeFileSync(new URL('report.json', import.meta.url), reportToJSON(report));
  writeFileSync(new URL('report.md', import.meta.url), reportToMarkdown(report));
} finally { store.close(); }

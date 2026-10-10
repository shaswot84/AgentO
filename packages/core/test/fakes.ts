import type {
  BrowserWorkflowDriver, CoreProviders, CWEId, CWEPlugin, Evidence, FrameworkAdapter,
  Project, ReasoningModel, RemediationProvider, SecurityScanner, StaticAnalyzer,
} from '../src/index.js';

export const project: Project = {
  id: 'project', name: 'Fake shop', mode: 'code-aware', repositoryPath: '/fake/shop',
  baseUrl: 'http://localhost:3000', allowedOrigins: ['http://localhost:3000'], languages: ['typescript'],
};

export function evidence(id: string, kind: Evidence['kind'], producerId: string): Evidence {
  return { id, projectId: project.id, kind, producerId, capturedAt: '2026-10-10T00:00:00Z',
    summary: 'Synthetic observation', facts: { synthetic: true } };
}

export function fakePlugin(cweId: CWEId = 'CWE-639', executor: 'scanner' | 'browser' = 'scanner'): CWEPlugin {
  return {
    cweId,
    async detectCandidates(context) {
      return [{ id: `hypothesis:${cweId}`, projectId: context.project.id, cweId,
        status: 'HYPOTHESIS', reason: 'Synthetic candidate', evidenceIds: context.evidence.map(item => item.id) }];
    },
    async generateTests(context, hypothesis) {
      return [{ id: `plan:${cweId}`, hypothesisId: hypothesis.id, cweId, executor,
        requiredCapabilities: ['synthetic-check'], risk: 'passive', targetUrl: context.project.baseUrl,
        identityIds: [], steps: [{ id: 'observe', action: 'synthetic-check', parameters: {},
          expectedObservation: 'Synthetic access observation' }] }];
    },
    async evaluateEvidence(context, hypothesis, results) {
      const completed = results.some(result => result.outcome === 'COMPLETED' && result.evidence.length > 0);
      return { id: `finding:${cweId}`, projectId: context.project.id, hypothesisId: hypothesis.id,
        cweId, owaspCategory: 'A01', title: 'Synthetic finding', status: completed ? 'CONFIRMED' : 'HYPOTHESIS',
        severity: 'medium', confidence: completed ? 'high' : 'low', rootCause: 'Synthetic explanation',
        evidenceIds: results.flatMap(result => result.evidence.map(item => item.id)),
        testPlanIds: results.map(result => result.planId) };
    },
  };
}

/** These structural implementations compile against every Phase 2 interface. No real tools run. */
export function fakeProviders(): CoreProviders {
  const staticAnalyzer: StaticAnalyzer = {
    id: 'fake-static', capabilities: ['static-analysis'],
    async analyze(project) {
      return { signals: [{ id: 'signal', projectId: project.id, producerId: this.id,
        cweIds: ['CWE-639'], summary: 'Candidate only', evidenceIds: ['static-evidence'] }],
        evidence: [evidence('static-evidence', 'static-analysis', this.id)] };
    },
  };
  const frameworkAdapter: FrameworkAdapter = {
    id: 'fake-framework', capabilities: ['route-extraction'],
    async supports() { return true; },
    async extract(project) {
      return { components: [{ id: 'api', projectId: project.id, name: 'API', kind: 'service' }],
        endpoints: [{ id: 'order', componentId: 'api', method: 'GET', path: '/api/orders/:id',
          parameters: [{ name: 'id', location: 'path', required: true }], authentication: 'required',
          roles: [], evidenceIds: ['framework-evidence'] }], resources: [], signals: [],
        evidence: [evidence('framework-evidence', 'source-location', this.id)] };
    },
  };
  const browser: BrowserWorkflowDriver = {
    id: 'fake-browser', capabilities: ['synthetic-check'],
    async observe() {
      return { endpoints: [], resources: [{ id: 'order-resource', projectId: project.id, type: 'Order',
        externalKey: '123', ownerIdentityId: 'alice', endpointId: 'order', evidenceIds: ['browser-evidence'] }],
        signals: [], evidence: [evidence('browser-evidence', 'resource-ownership', this.id)] };
    },
    async execute(_context, plan) {
      return { id: `result:${plan.id}`, planId: plan.id, producerId: this.id, outcome: 'COMPLETED',
        summary: 'Synthetic test completed', evidence: [evidence(`proof:${plan.id}`, 'http-response', this.id)] };
    },
  };
  const scanner: SecurityScanner = {
    id: 'fake-scanner', capabilities: ['synthetic-check'],
    async execute(_context, plan) {
      return { id: `result:${plan.id}`, planId: plan.id, producerId: this.id, outcome: 'COMPLETED',
        summary: 'Synthetic test completed', evidence: [evidence(`proof:${plan.id}`, 'http-response', this.id)] };
    },
  };
  const reasoning: ReasoningModel = {
    id: 'fake-model', capabilities: ['hypothesis-review'],
    async reviewHypotheses(_context, hypotheses) { return hypotheses; },
  };
  const remediation: RemediationProvider = {
    id: 'fake-remediation', capabilities: ['patch-suggestion'],
    async suggest(_context, finding) {
      return { findingId: finding.id, explanation: 'Check resource ownership', patch: 'Synthetic patch suggestion',
        regressionTest: 'Synthetic regression test suggestion', evidenceIds: finding.evidenceIds };
    },
  };
  return { plugins: [fakePlugin()], staticAnalyzer, frameworkAdapter, browser, scanner, reasoning, remediation };
}

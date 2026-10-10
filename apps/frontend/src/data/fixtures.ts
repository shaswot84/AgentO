import type { Endpoint, Evidence, EvidenceKind, FindingStatus, JsonValue, Severity, SourceLocation, CWEId } from '@agento/core';
import type { FindingDetail, ProjectSummary, ScanSnapshot } from '../client/types';
import { demoDiscovery } from './demo-discovery';

export const DEMO_PROJECT_ID = 'demo-shop';
const capturedAt = '2026-10-10T00:00:00.000Z';

export const demoProject: ProjectSummary = {
  id: DEMO_PROJECT_ID,
  name: 'AgentO Demo Store',
  repositoryPath: 'demo-app',
  baseUrl: 'http://localhost:3000',
  allowedOrigins: ['http://localhost:3000'],
  mode: demoDiscovery.mode,
  languages: demoDiscovery.languages,
  dataSource: 'demo-fixture',
  createdAt: capturedAt,
};

export const demoScan: ScanSnapshot = {
  id: 'demo-scan-fixture',
  projectId: DEMO_PROJECT_ID,
  source: 'demo-fixture',
  state: 'complete',
  completedAt: capturedAt,
  summary: 'Illustrative scan fixture with five evidence states. Only discovery metadata comes from a saved repository discovery run; no security scan runs in this frontend.',
  stages: [
    { id: 'discovery', label: 'Saved discovery snapshot', status: 'complete', details: 'Saved output of repository discovery for demo-app. Express, SQLite, and session middleware detected.' },
    { id: 'adapter', label: 'Framework adapter availability', status: 'unavailable', details: 'No Express framework adapter is registered. Saved discovery selects black-box mode.' },
    { id: 'static', label: 'Static analysis fixture', status: 'complete', details: 'Illustrative source observations with repository-relative locations; no analyzer executes here.' },
    { id: 'browser', label: 'Browser observations fixture', status: 'complete', details: 'Illustrative browser evidence only; no target browser workflow executes here.' },
    { id: 'scanner', label: 'Scanner results fixture', status: 'complete', details: 'Illustrative test outcomes only; no scanner or network request executes here.' },
    { id: 'evaluation', label: 'Evidence evaluation fixture', status: 'complete', details: 'Five fixture findings demonstrate every FindingStatus value.' },
    { id: 'remediation', label: 'Remediation fixture', status: 'complete', details: 'Illustrative fix guidance for review; no repository patches are applied.' },
  ],
};

interface FindingSeed {
  readonly id: string;
  readonly cweId: CWEId;
  readonly category: string;
  readonly title: string;
  readonly status: FindingStatus;
  readonly severity: Severity;
  readonly confidence: 'low' | 'medium' | 'high';
  readonly path: string;
  readonly method?: Endpoint['method'];
  readonly authentication: Endpoint['authentication'];
  readonly source: SourceLocation;
  readonly rootCause: string;
  readonly evidenceKind: EvidenceKind;
  readonly observation: string;
  readonly runtimeEvidence?: {
    readonly kind: 'http-response' | 'browser-observation';
    readonly observation: string;
    readonly facts: Readonly<Record<string, JsonValue>>;
  };
  readonly remediation: string;
  readonly regressionTest: string;
}

function fixtureFinding(seed: FindingSeed): FindingDetail {
  const evidenceId = `evidence-${seed.id}`;
  const endpointId = `endpoint-${seed.id}`;
  const evidence: Evidence[] = [{
    id: evidenceId,
    projectId: DEMO_PROJECT_ID,
    kind: seed.evidenceKind,
    producerId: 'frontend-demo-fixture',
    capturedAt,
    summary: `Illustrative fixture: ${seed.observation}`,
    ...(seed.evidenceKind === 'browser-observation' ? {} : { source: seed.source }),
    endpointId,
    facts: { fixture: true, observation: seed.observation, containsCredentials: false },
  }];
  if (seed.runtimeEvidence) {
    evidence.push({
      id: `${evidenceId}-response`,
      projectId: DEMO_PROJECT_ID,
      kind: seed.runtimeEvidence.kind,
      producerId: 'frontend-demo-fixture',
      capturedAt,
      summary: `Synthetic runtime fixture: ${seed.runtimeEvidence.observation}`,
      endpointId,
      facts: { ...seed.runtimeEvidence.facts, fixture: true, synthetic: true, containsCredentials: false },
    });
  }
  const evidenceIds = evidence.map((item) => item.id);
  return {
    id: seed.id,
    projectId: DEMO_PROJECT_ID,
    hypothesisId: `hypothesis-${seed.id}`,
    cweId: seed.cweId,
    owaspCategory: seed.category,
    title: seed.title,
    status: seed.status,
    severity: seed.severity,
    confidence: seed.confidence,
    rootCause: seed.rootCause,
    source: seed.source,
    sourceType: 'demo-fixture',
    endpointId,
    evidenceIds,
    testPlanIds: [`fixture-plan-${seed.id}`],
    endpoint: {
      id: endpointId,
      componentId: 'demo-express-service',
      method: seed.method ?? 'GET',
      path: seed.path,
      parameters: seed.id === 'finding-idor' ? [{ name: 'id', location: 'path', required: true }]
        : seed.path.includes('search') ? [{ name: 'q', location: 'query', required: false }] : [],
      authentication: seed.authentication,
      roles: [],
      handler: seed.source,
      evidenceIds,
    },
    evidence,
    remediation: {
      findingId: seed.id,
      explanation: seed.remediation,
      regressionTest: seed.regressionTest,
      evidenceIds,
    },
  };
}

/** These verdicts demonstrate interface states; they are not live security results. */
export const demoFindings: readonly FindingDetail[] = [
  fixtureFinding({
    id: 'finding-idor', cweId: 'CWE-639', category: 'A01: Broken Access Control',
    title: 'Order access without ownership verification', status: 'CONFIRMED', severity: 'high', confidence: 'high',
    path: '/api/orders/:id', authentication: 'required', source: { file: 'src/routes/orders.ts', startLine: 104, endLine: 107 },
    rootCause: 'In the vulnerable demo branch, the handler returns an order selected by request ID without checking that the signed-in user owns it.',
    evidenceKind: 'source-location',
    observation: 'The repository source reference points to the vulnerable branch returning the selected order. Ownership verification is present only in the earlier fixed branch.',
    runtimeEvidence: {
      kind: 'http-response',
      observation: 'Synthetic customer-A receives a 200 response for order-B owned by customer-B in the vulnerable scenario; the matching fixed control returns 403. No live request was made.',
      facts: { identityLabel: 'customer-A', resourceLabel: 'order-B', ownerLabel: 'customer-B',
        vulnerableStatusCode: 200, fixedControlStatusCode: 403, responseBodyRedacted: true },
    },
    remediation: 'Require order ownership or an explicitly permitted administrator role before returning order data. Apply the check on every object access.',
    regressionTest: 'Use two customer identities. The owner receives their order; the other customer receives 403 without order data. Check the approved administrator case separately.',
  }),
  fixtureFinding({
    id: 'finding-sql', cweId: 'CWE-89', category: 'A05: Injection',
    title: 'Search input interpolated into SQL', status: 'LIKELY', severity: 'high', confidence: 'medium',
    path: '/api/search', authentication: 'optional', source: { file: 'src/routes/search.ts', startLine: 44, endLine: 49 },
    rootCause: 'The vulnerable demo branch embeds the query parameter inside a SQL string before passing it to the database.',
    evidenceKind: 'static-analysis',
    observation: 'The illustrative source observation shows a query built from request input. This fixture has no conclusive controlled database execution evidence.',
    remediation: 'Use a prepared query with bound values for the search pattern. Keep database error details out of client responses.',
    regressionTest: 'Search strings containing quote characters should be treated as data, preserve expected search behavior, and never widen the result scope.',
  }),
  fixtureFinding({
    id: 'finding-cors', cweId: 'CWE-942', category: 'A02: Security Misconfiguration',
    title: 'Credentialed CORS may trust arbitrary origins', status: 'HYPOTHESIS', severity: 'medium', confidence: 'low',
    path: '/api/profile', authentication: 'required', source: { file: 'src/middleware/cors.ts', startLine: 24, endLine: 26 },
    rootCause: 'The vulnerable demo middleware reflects an incoming origin and enables credentials. Exploitability still depends on browser and session behavior.',
    evidenceKind: 'configuration',
    observation: 'An illustrative middleware observation raises a CORS candidate. No authenticated cross-origin browser test is represented as completed evidence.',
    remediation: 'Use an explicit trusted origin allowlist and enable credentials only for approved origins. Verify behavior with the intended authentication configuration.',
    regressionTest: 'Trusted origins receive the intended headers; untrusted origins do not receive a credentialed allow-origin response.',
  }),
  fixtureFinding({
    id: 'finding-xss', cweId: 'CWE-79', category: 'A05: Injection',
    title: 'Reflected search markup in fixed-mode control', status: 'NOT_REPRODUCED', severity: 'medium', confidence: 'medium',
    path: '/search', authentication: 'optional', source: { file: 'src/routes/search.ts', startLine: 78, endLine: 80 },
    rootCause: 'The vulnerable branch reflects raw query text, while the fixed branch escapes HTML characters before inserting them into the page.',
    evidenceKind: 'browser-observation',
    observation: 'The illustrative fixed-mode control renders HTML-looking input as text. The fixture does not reproduce script execution for this scenario.',
    remediation: 'Retain output encoding for the HTML context. Recheck every other rendering context rather than treating this control as proof of global safety.',
    regressionTest: 'HTML-looking search text remains visible as literal text and does not create active DOM elements or trigger event handlers.',
  }),
  fixtureFinding({
    id: 'finding-cookie', cweId: 'CWE-1004', category: 'A02: Security Misconfiguration',
    title: 'HttpOnly omission in fixed-mode cookie control', status: 'REJECTED', severity: 'low', confidence: 'high',
    path: '/api/auth/login', method: 'POST', authentication: 'optional', source: { file: 'src/middleware/auth.ts', startLine: 57, endLine: 62 },
    rootCause: 'The fixed-mode cookie configuration explicitly enables HttpOnly. The illustrative candidate was based on the presence of cookie middleware alone.',
    evidenceKind: 'configuration',
    observation: 'The illustrative source control has httpOnly enabled. Middleware presence alone does not establish an unsafe cookie configuration.',
    remediation: 'No fix is needed for this fixed-mode candidate. Preserve HttpOnly and verify cookie attributes when configuration changes.',
    regressionTest: 'Inspect the fixed-mode Set-Cookie attributes without retaining cookie values. Confirm HttpOnly remains present.',
  }),
];

import type { Endpoint, Evidence, EvidenceKind, FindingStatus, JsonValue, Severity, SourceLocation, CWEId } from '@agento/core';
import type { BrowserWorkflowResult, FindingDetail, ProjectSummary, ScanSnapshot } from '../client/types.ts';
import { demoDiscovery } from './demo-discovery.ts';


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
    { id: 'adapter', label: 'Live framework analysis', status: 'unavailable', details: 'Saved discovery describes adapter support. Live framework analysis is not connected in this preview.' },
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

export const demoWorkflows: readonly BrowserWorkflowResult[] = [
  {
    id: 'wf-alice-orders',
    projectId: DEMO_PROJECT_ID,
    goal: 'Login as Alice and open her newest order.',
    identityId: 'alice',
    personaLabel: 'Alice (Customer)',
    targetUrl: 'http://localhost:3000',
    outcome: 'COMPLETED',
    completionType: 'recipe-completed',
    durationMs: 1420,
    actionsCount: 8,
    recoveryAttempts: 0,
    finalUrl: 'http://localhost:3000/orders.html',
    sourceType: 'demo-fixture',
    executedAt: '2026-10-10T00:01:15.000Z',
    endpoints: [
      {
        id: 'ep-orders-102', componentId: 'demo-express-service', method: 'GET', path: '/api/orders/102',
        parameters: [{ name: 'id', location: 'path', required: true }], authentication: 'required', roles: ['customer'],
        evidenceIds: ['ev-wf-alice-net-6'],
      },
      {
        id: 'ep-orders-list', componentId: 'demo-express-service', method: 'GET', path: '/api/orders',
        parameters: [], authentication: 'required', roles: ['customer'], evidenceIds: ['ev-wf-alice-net-5'],
      },
      {
        id: 'ep-auth-login', componentId: 'demo-express-service', method: 'POST', path: '/api/auth/login',
        parameters: [], authentication: 'optional', roles: [], evidenceIds: ['ev-wf-alice-net-2'],
      },
      {
        id: 'ep-auth-me', componentId: 'demo-express-service', method: 'GET', path: '/api/auth/me',
        parameters: [], authentication: 'required', roles: ['customer'], evidenceIds: ['ev-wf-alice-net-3'],
      },
    ],
    network: [
      { url: 'http://localhost:3000/login.html', method: 'GET', status: 200, resourceType: 'document', blocked: false, timestamp: '2026-10-10T00:01:15.110Z', headers: { 'content-type': 'text/html; charset=utf-8' } },
      { url: 'http://localhost:3000/api/auth/login', method: 'POST', status: 200, resourceType: 'fetch', blocked: false, timestamp: '2026-10-10T00:01:15.340Z', headers: { 'content-type': 'application/json', 'set-cookie': 'session=sess-alice-491f; Path=/; HttpOnly' } },
      { url: 'http://localhost:3000/api/auth/me', method: 'GET', status: 200, resourceType: 'fetch', blocked: false, timestamp: '2026-10-10T00:01:15.420Z', headers: { 'content-type': 'application/json' } },
      { url: 'http://localhost:3000/orders.html', method: 'GET', status: 200, resourceType: 'document', blocked: false, timestamp: '2026-10-10T00:01:15.650Z', headers: { 'content-type': 'text/html; charset=utf-8' } },
      { url: 'http://localhost:3000/api/orders', method: 'GET', status: 200, resourceType: 'fetch', blocked: false, timestamp: '2026-10-10T00:01:15.820Z', headers: { 'content-type': 'application/json' } },
      { url: 'http://localhost:3000/api/orders/102', method: 'GET', status: 200, resourceType: 'fetch', blocked: false, timestamp: '2026-10-10T00:01:16.210Z', headers: { 'content-type': 'application/json' } },
    ],
    steps: [
      { actionType: 'navigate', url: 'http://localhost:3000/login.html', outcome: 'completed', details: 'Navigated to entry login page' },
      { actionType: 'fill-credential', selector: '#username', outcome: 'completed', details: 'Filled username for persona alice' },
      { actionType: 'fill-credential', selector: '#password', outcome: 'completed', details: 'Filled password for persona alice' },
      { actionType: 'click', selector: '#login-form button[type=submit]', outcome: 'completed', details: 'Submitted authentication form' },
      { actionType: 'verify-session', url: 'http://localhost:3000/api/auth/me', outcome: 'completed', details: 'Session verified: user alice (customer)' },
      { actionType: 'navigate', url: 'http://localhost:3000/orders.html', outcome: 'completed', details: 'Navigated to orders dashboard' },
      { actionType: 'click', selector: '#orders-table-body tr:first-child button', outcome: 'completed', details: 'Clicked view order #102' },
      { actionType: 'wait-visible', selector: '#idor-result-container', outcome: 'completed', details: 'Verified order detail panel rendered' },
    ],
    session: {
      personaId: 'alice',
      authenticated: true,
      reused: false,
      sessionRef: 'sess-alice-491f',
      targetId: 'storefront',
    },
    pageModelSummary: {
      title: 'Order History — AgentO Demo Store',
      headings: ['Your Orders', 'Order #102 Details'],
      interactiveElementCount: 14,
    },
    diagnostics: [],
    evidence: [
      {
        id: 'ev-wf-alice-obs', projectId: DEMO_PROJECT_ID, kind: 'browser-observation', producerId: 'tester-army-e2e-adapter',
        capturedAt: '2026-10-10T00:01:16.250Z', summary: 'Browser workflow completed; observations carry no vulnerability verdict.',
        facts: { outcome: 'COMPLETED', executedActions: 8, networkRecordCount: 6, blockedCount: 0, droppedCount: 0, url: 'http://localhost:3000/orders.html' },
      },
      {
        id: 'ev-wf-alice-sess', projectId: DEMO_PROJECT_ID, kind: 'identity-session', producerId: 'tester-army-e2e-adapter',
        capturedAt: '2026-10-10T00:01:15.430Z', summary: 'Verified isolated browser identity session.',
        facts: { authenticated: true, reused: false, sessionRef: 'sess-alice-491f', rawStateIncluded: false, targetId: 'storefront' },
      },
      {
        id: 'ev-wf-alice-plan', projectId: DEMO_PROJECT_ID, kind: 'browser-observation', producerId: 'workflow-orchestrator',
        capturedAt: '2026-10-10T00:01:16.260Z', summary: 'Bounded browser workflow planning outcome',
        facts: { workflowId: 'wf-alice-orders', completion: 'recipe-completed', modelCalls: 0, modelTokens: 0, actions: 8, recoveryAttempts: 0, url: 'http://localhost:3000/orders.html' },
      },
    ],
  },
  {
    id: 'wf-bob-orders',
    projectId: DEMO_PROJECT_ID,
    goal: 'Login as Bob and open his newest order.',
    identityId: 'bob',
    personaLabel: 'Bob (Customer)',
    targetUrl: 'http://localhost:3000',
    outcome: 'COMPLETED',
    completionType: 'recipe-completed',
    durationMs: 640,
    actionsCount: 4,
    recoveryAttempts: 0,
    finalUrl: 'http://localhost:3000/orders.html',
    sourceType: 'demo-fixture',
    executedAt: '2026-10-10T00:02:00.000Z',
    endpoints: [
      {
        id: 'ep-orders-201', componentId: 'demo-express-service', method: 'GET', path: '/api/orders/201',
        parameters: [{ name: 'id', location: 'path', required: true }], authentication: 'required', roles: ['customer'],
        evidenceIds: ['ev-wf-bob-net-3'],
      },
    ],
    network: [
      { url: 'http://localhost:3000/orders.html', method: 'GET', status: 200, resourceType: 'document', blocked: false, timestamp: '2026-10-10T00:02:00.120Z', headers: { 'content-type': 'text/html; charset=utf-8' } },
      { url: 'http://localhost:3000/api/auth/me', method: 'GET', status: 200, resourceType: 'fetch', blocked: false, timestamp: '2026-10-10T00:02:00.220Z', headers: { 'content-type': 'application/json' } },
      { url: 'http://localhost:3000/api/orders', method: 'GET', status: 200, resourceType: 'fetch', blocked: false, timestamp: '2026-10-10T00:02:00.350Z', headers: { 'content-type': 'application/json' } },
      { url: 'http://localhost:3000/api/orders/201', method: 'GET', status: 200, resourceType: 'fetch', blocked: false, timestamp: '2026-10-10T00:02:00.580Z', headers: { 'content-type': 'application/json' } },
    ],
    steps: [
      { actionType: 'restore-session', outcome: 'completed', details: 'Reused verified authenticated session from file store' },
      { actionType: 'navigate', url: 'http://localhost:3000/orders.html', outcome: 'completed', details: 'Navigated to orders page with preserved cookie' },
      { actionType: 'click', selector: '#orders-table-body tr:first-child button', outcome: 'completed', details: 'Selected Bob newest order #201' },
      { actionType: 'wait-visible', selector: '#idor-result-container', outcome: 'completed', details: 'Verified order detail panel rendered' },
    ],
    session: {
      personaId: 'bob',
      authenticated: true,
      reused: true,
      sessionRef: 'sess-bob-812e',
      targetId: 'storefront',
    },
    pageModelSummary: {
      title: 'Order History — AgentO Demo Store',
      headings: ['Your Orders', 'Order #201 Details'],
      interactiveElementCount: 11,
    },
    diagnostics: [],
    evidence: [
      {
        id: 'ev-wf-bob-obs', projectId: DEMO_PROJECT_ID, kind: 'browser-observation', producerId: 'tester-army-e2e-adapter',
        capturedAt: '2026-10-10T00:02:00.610Z', summary: 'Browser workflow completed; observations carry no vulnerability verdict.',
        facts: { outcome: 'COMPLETED', executedActions: 4, networkRecordCount: 4, blockedCount: 0, droppedCount: 0, url: 'http://localhost:3000/orders.html' },
      },
      {
        id: 'ev-wf-bob-sess', projectId: DEMO_PROJECT_ID, kind: 'identity-session', producerId: 'tester-army-e2e-adapter',
        capturedAt: '2026-10-10T00:02:00.100Z', summary: 'Verified isolated browser identity session (reused from cache).',
        facts: { authenticated: true, reused: true, sessionRef: 'sess-bob-812e', rawStateIncluded: false, targetId: 'storefront' },
      },
    ],
  },
  {
    id: 'wf-admin-oversight',
    projectId: DEMO_PROJECT_ID,
    goal: 'Login as Admin and review system orders.',
    identityId: 'admin',
    personaLabel: 'Admin (System Administrator)',
    targetUrl: 'http://localhost:3000',
    outcome: 'COMPLETED',
    completionType: 'recipe-completed',
    durationMs: 1310,
    actionsCount: 7,
    recoveryAttempts: 0,
    finalUrl: 'http://localhost:3000/orders.html',
    sourceType: 'demo-fixture',
    executedAt: '2026-10-10T00:02:45.000Z',
    endpoints: [
      {
        id: 'ep-orders-301', componentId: 'demo-express-service', method: 'GET', path: '/api/orders/301',
        parameters: [{ name: 'id', location: 'path', required: true }], authentication: 'required', roles: ['admin'],
        evidenceIds: ['ev-wf-admin-net-4'],
      },
    ],
    network: [
      { url: 'http://localhost:3000/login.html', method: 'GET', status: 200, resourceType: 'document', blocked: false, timestamp: '2026-10-10T00:02:45.100Z', headers: { 'content-type': 'text/html; charset=utf-8' } },
      { url: 'http://localhost:3000/api/auth/login', method: 'POST', status: 200, resourceType: 'fetch', blocked: false, timestamp: '2026-10-10T00:02:45.320Z', headers: { 'content-type': 'application/json', 'set-cookie': 'session=sess-admin-901a; Path=/; HttpOnly' } },
      { url: 'http://localhost:3000/orders.html', method: 'GET', status: 200, resourceType: 'document', blocked: false, timestamp: '2026-10-10T00:02:45.540Z', headers: { 'content-type': 'text/html; charset=utf-8' } },
      { url: 'http://localhost:3000/api/orders/301', method: 'GET', status: 200, resourceType: 'fetch', blocked: false, timestamp: '2026-10-10T00:02:45.890Z', headers: { 'content-type': 'application/json' } },
    ],
    steps: [
      { actionType: 'navigate', url: 'http://localhost:3000/login.html', outcome: 'completed', details: 'Navigated to login page' },
      { actionType: 'fill-credential', selector: '#username', outcome: 'completed', details: 'Filled username for persona admin' },
      { actionType: 'fill-credential', selector: '#password', outcome: 'completed', details: 'Filled password for persona admin' },
      { actionType: 'click', selector: '#login-form button[type=submit]', outcome: 'completed', details: 'Submitted administrator credentials' },
      { actionType: 'navigate', url: 'http://localhost:3000/orders.html', outcome: 'completed', details: 'Opened administrator order overview' },
      { actionType: 'click', selector: '#orders-table-body tr:first-child button', outcome: 'completed', details: 'Inspected admin order #301' },
      { actionType: 'wait-visible', selector: '#idor-result-container', outcome: 'completed', details: 'Admin order data rendered' },
    ],
    session: {
      personaId: 'admin',
      authenticated: true,
      reused: false,
      sessionRef: 'sess-admin-901a',
      targetId: 'storefront',
    },
    pageModelSummary: {
      title: 'Administrator Console — AgentO Demo Store',
      headings: ['System Orders', 'Privileged Record #301'],
      interactiveElementCount: 18,
    },
    diagnostics: [],
    evidence: [
      {
        id: 'ev-wf-admin-obs', projectId: DEMO_PROJECT_ID, kind: 'browser-observation', producerId: 'tester-army-e2e-adapter',
        capturedAt: '2026-10-10T00:02:46.100Z', summary: 'Browser workflow completed; observations carry no vulnerability verdict.',
        facts: { outcome: 'COMPLETED', executedActions: 7, networkRecordCount: 4, blockedCount: 0, droppedCount: 0, url: 'http://localhost:3000/orders.html' },
      },
    ],
  },
  {
    id: 'wf-portal-analyst',
    projectId: DEMO_PROJECT_ID,
    goal: 'Login as Analyst, track 302 redirect with CSRF token, and open latest report.',
    identityId: 'analyst',
    personaLabel: 'Analyst (Multi-Page Portal)',
    targetUrl: 'http://localhost:3300',
    outcome: 'COMPLETED',
    completionType: 'deterministic',
    durationMs: 1540,
    actionsCount: 6,
    recoveryAttempts: 0,
    finalUrl: 'http://localhost:3300/reports/REP-501',
    sourceType: 'demo-fixture',
    executedAt: '2026-10-10T00:03:30.000Z',
    endpoints: [
      {
        id: 'ep-reports-501', componentId: 'portal-express-service', method: 'GET', path: '/reports/REP-501',
        parameters: [{ name: 'id', location: 'path', required: true }], authentication: 'required', roles: ['analyst'],
        evidenceIds: ['ev-wf-portal-net-4'],
      },
    ],
    network: [
      { url: 'http://localhost:3300/login', method: 'GET', status: 200, resourceType: 'document', blocked: false, timestamp: '2026-10-10T00:03:30.120Z', headers: { 'content-type': 'text/html' } },
      { url: 'http://localhost:3300/login', method: 'POST', status: 302, resourceType: 'document', blocked: false, timestamp: '2026-10-10T00:03:30.410Z', headers: { location: '/dashboard', 'set-cookie': 'portal_session=sess-analyst-3300; HttpOnly' } },
      { url: 'http://localhost:3300/dashboard', method: 'GET', status: 200, resourceType: 'document', blocked: false, timestamp: '2026-10-10T00:03:30.680Z', headers: { 'content-type': 'text/html' } },
      { url: 'http://localhost:3300/reports/REP-501', method: 'GET', status: 200, resourceType: 'document', blocked: false, timestamp: '2026-10-10T00:03:31.250Z', headers: { 'content-type': 'text/html' } },
    ],
    steps: [
      { actionType: 'navigate', url: 'http://localhost:3300/login', outcome: 'completed', details: 'Navigated to MPA portal login' },
      { actionType: 'extract-csrf', selector: 'input[name=_csrf]', outcome: 'completed', details: 'Extracted hidden CSRF token from server HTML' },
      { actionType: 'fill-credential', selector: '#username', outcome: 'completed', details: 'Filled username for persona analyst' },
      { actionType: 'fill-credential', selector: '#password', outcome: 'completed', details: 'Filled password for persona analyst' },
      { actionType: 'submit-redirect', outcome: 'completed', details: 'Tracked 302 redirect from /login to /dashboard' },
      { actionType: 'navigate', url: 'http://localhost:3300/reports/REP-501', outcome: 'completed', details: 'Reached report detail view' },
    ],
    session: {
      personaId: 'analyst',
      authenticated: true,
      reused: false,
      sessionRef: 'sess-analyst-3300',
      targetId: 'portal',
    },
    pageModelSummary: {
      title: 'Analyst Security Reports — Corporate Portal',
      headings: ['Quarterly Incident Log', 'Report #REP-501'],
      interactiveElementCount: 9,
    },
    diagnostics: [],
    evidence: [
      {
        id: 'ev-wf-portal-obs', projectId: DEMO_PROJECT_ID, kind: 'browser-observation', producerId: 'tester-army-e2e-adapter',
        capturedAt: '2026-10-10T00:03:31.420Z', summary: 'Browser workflow completed; observations carry no vulnerability verdict.',
        facts: { outcome: 'COMPLETED', executedActions: 6, networkRecordCount: 4, blockedCount: 0, droppedCount: 0, url: 'http://localhost:3300/reports/REP-501' },
      },
    ],
  },
  {
    id: 'wf-scope-enforcement',
    projectId: DEMO_PROJECT_ID,
    goal: 'Exfiltrate telemetry via WebSocket and unauthorized third-party CDN.',
    identityId: 'operator',
    personaLabel: 'Operator (Strict Scope Verification)',
    targetUrl: 'http://localhost:3400',
    outcome: 'FAILED',
    completionType: 'unconfirmed',
    durationMs: 820,
    actionsCount: 3,
    recoveryAttempts: 0,
    finalUrl: 'http://localhost:3400/dashboard',
    sourceType: 'demo-fixture',
    executedAt: '2026-10-10T00:04:10.000Z',
    endpoints: [],
    network: [
      { url: 'http://localhost:3400/dashboard', method: 'GET', status: 200, resourceType: 'document', blocked: false, timestamp: '2026-10-10T00:04:10.150Z', headers: { 'content-type': 'text/html' } },
      { url: 'https://unauthorized-cdn.evil.example/track.js', method: 'GET', status: null, resourceType: 'script', blocked: true, blockedReason: 'origin-scope', timestamp: '2026-10-10T00:04:10.420Z' },
      { url: 'ws://localhost:3400/escape/websocket', method: 'GET', status: null, resourceType: 'websocket', blocked: true, blockedReason: 'websocket-unsupported', timestamp: '2026-10-10T00:04:10.650Z' },
    ],
    steps: [
      { actionType: 'navigate', url: 'http://localhost:3400/dashboard', outcome: 'completed', details: 'Navigated to in-scope SPA dashboard' },
      { actionType: 'request', url: 'https://unauthorized-cdn.evil.example/track.js', outcome: 'rejected', code: 'scope-denied', details: 'AgentO exact-origin policy refused external request' },
      { actionType: 'websocket-connect', url: 'ws://localhost:3400/escape/websocket', outcome: 'rejected', code: 'websocket-unsupported', details: 'WebSocket connection refused by primary REST policy' },
    ],
    session: {
      personaId: 'operator',
      authenticated: false,
      reused: false,
      targetId: 'edge-spa',
    },
    pageModelSummary: {
      title: 'Operations Dashboard — Edge SPA',
      headings: ['Telemetry Stream'],
      interactiveElementCount: 6,
    },
    diagnostics: [
      { code: 'scope-denied', message: 'An action or browser request was refused by the browser scope policy.' },
      { code: 'websocket-unsupported', message: 'WebSocket connections are refused by the REST browser capability port.' },
    ],
    evidence: [
      {
        id: 'ev-wf-scope-denied', projectId: DEMO_PROJECT_ID, kind: 'browser-observation', producerId: 'tester-army-e2e-adapter',
        capturedAt: '2026-10-10T00:04:10.820Z', summary: 'Browser workflow failed; observations carry no vulnerability verdict.',
        facts: { outcome: 'FAILED', executedActions: 3, networkRecordCount: 3, blockedCount: 2, droppedCount: 0, diagnosticCodes: ['scope-denied', 'websocket-unsupported'] },
      },
    ],
  },
];


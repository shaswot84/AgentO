import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, request as httpsRequest, type Server } from 'node:https';
import type { RequestListener } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AnalysisContext, CWEId, Evidence, Identity, Project } from '@agento/core';
import { CWE79Plugin, CWE89Plugin, CWE639Plugin, CWE862Plugin, CWE942Plugin, CWE1004Plugin, CWE614Plugin,
  toCoreEvidence, type CWEPlugin, type NormalizedProbeEvidence, type ProbeTestPlan } from '@agento/cwe';
import { FileEvidenceStore } from '@agento/evidence';
import { AuthorizationProbe, CapabilityRegistry, CookieSecurityProbe, CrossOriginProbe, DeterministicRequestExecutor,
  NormalizedCookieAnalyzer, NormalizedHeaderAnalyzer, NormalizedResponseCollector, NormalizedResponseComparator,
  SQLInjectionProbe, XSSProbe, type AuthSession, type AuthenticationManager, type HttpTransport } from '@agento/runtime';
import { VerificationJudge } from '../src/index.js';

const suite = process.env.AGENTO_VERIFIER_INTEGRATION === '1' ? describe : describe.skip;
suite('judge against the real storefront over trusted loopback TLS', () => {
  let server: Server, origin: string, directory: string, certificate: Buffer;
  let database: { close(): void }, setMode: (mode: 'vulnerable' | 'fixed') => void;
  const oldDatabase = process.env.DB_PATH;
  beforeAll(async () => {
    directory = mkdtempSync(join(tmpdir(), 'agento-verifier-'));
    const key = join(directory, 'key.pem'), cert = join(directory, 'cert.pem');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', key,
      '-out', cert, '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
    certificate = readFileSync(cert);
    process.env.DB_PATH = ':memory:';
    const app: { createApp(): RequestListener } = await import(new URL('../../../demo-apps/demo-app-01/src/app.ts', import.meta.url).pathname);
    const db: { db: { close(): void }; initDatabase(): void } = await import(new URL('../../../demo-apps/demo-app-01/src/db/database.ts', import.meta.url).pathname);
    const config: { setSecurityMode: typeof setMode } = await import(new URL('../../../demo-apps/demo-app-01/src/config.ts', import.meta.url).pathname);
    database = db.db; db.initDatabase(); setMode = config.setSecurityMode;
    server = createServer({ key: readFileSync(key), cert: certificate }, app.createApp());
    await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    origin = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    if (server) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
    database?.close();
    if (directory) rmSync(directory, { recursive: true, force: true });
    if (oldDatabase === undefined) delete process.env.DB_PATH; else process.env.DB_PATH = oldDatabase;
  });
  // Trust only this test CA. Keep runtime scope checks and TLS certificate validation enabled.
  const transport: HttpTransport = { send: request => new Promise((resolve, reject) => {
    const outgoing = httpsRequest(request.url, { ca: certificate, method: request.method, headers: request.headers,
      signal: request.signal, agent: false }, incoming => {
      const chunks: Buffer[] = [], headers: Record<string, string[]> = {};
      for (let i = 0; i < incoming.rawHeaders.length; i += 2) (headers[incoming.rawHeaders[i]!.toLowerCase()] ??= []).push(incoming.rawHeaders[i + 1]!);
      let size = 0, truncated = false;
      incoming.on('data', (chunk: Buffer) => {
        const remaining = Math.max(0, request.maxBodyBytes - size);
        chunks.push(chunk.subarray(0, remaining)); size += chunk.length;
        truncated ||= size > request.maxBodyBytes;
      });
      incoming.on('end', () => resolve({ status: incoming.statusCode!, headers, body: Buffer.concat(chunks), truncated, firstByteMs: 1 }));
      incoming.on('error', reject);
    });
    outgoing.on('error', reject); outgoing.end(request.body);
  }) };
  it.each(['vulnerable', 'fixed'] as const)('has grounded results for all seven CWEs in %s mode', async mode => {
    setMode(mode);
    const project: Project = { id: `demo-${mode}`, name: 'Judge demo', mode: 'code-aware', baseUrl: origin,
      allowedOrigins: [origin], languages: ['typescript'] };
    const identities: readonly Identity[] = ['alice', 'bob', 'admin'].map(id => ({ id, label: id,
      roles: [id === 'admin' ? 'admin' : 'customer'], authentication: 'session-cookie' }));
    const executor = new DeterministicRequestExecutor({ baseUrl: origin, allowedOrigins: [origin], transport });
    const analyzer = new NormalizedCookieAnalyzer(), sessions = new Map<string, AuthSession>();
    const manager: AuthenticationManager = { establishSession: async identity => {
      if (sessions.has(identity.id)) return sessions.get(identity.id)!;
      const login = await executor.execute({ url: '/api/auth/login', method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: identity.id, password: `${identity.id}123` }) });
      expect(login.status).toBe(200);
      const cookie = (login.headers['set-cookie'] ?? []).map(value => value.split(';')[0]).join('; ');
      const session: AuthSession = { id: `session:${identity.id}`, identityId: identity.id, expiresAt: new Date(Date.now() + 60_000).toISOString(),
        http: { execute: request => executor.execute({ ...request, headers: { ...request.headers, cookie } }) },
        cookies: async () => analyzer.analyze(login), network: () => [], withBrowser: async () => { throw new Error('No browser'); }, close: async () => {} };
      sessions.set(identity.id, session); return session;
    } };
    const capabilities = new CapabilityRegistry().register('request-executor', executor).register('response-collector', new NormalizedResponseCollector())
      .register('cookie-analyzer', analyzer).register('header-analyzer', new NormalizedHeaderAnalyzer())
      .register('response-comparator', new NormalizedResponseComparator()).register('authentication-manager', manager)
      .register('cookie-inspector', { inspect: session => session.cookies() });
    const definitions: readonly [CWEId, string][] = [['CWE-1004', '/api/auth/me'], ['CWE-614', '/api/auth/me'],
      ['CWE-942', '/api/auth/me'], ['CWE-639', '/api/orders/101'], ['CWE-862', '/api/admin/users'],
      ['CWE-79', '/search'], ['CWE-89', '/api/search']];
    const findings = [];
    for (const [cweId, path] of definitions) {
      const admin = cweId === 'CWE-862';
      const policy = { resourceId: admin ? 'admin-users' : 'order-1', ownerIdentityId: admin ? 'admin' : 'alice',
        attackerIdentityId: admin ? 'alice' : 'bob', attackerIsUnauthorized: true, anonymousIsUnauthorized: true };
      const options = { sensitiveCookieNames: ['auth_token'], untrustedOrigins: ['https://unapproved.invalid'], authorizationPolicies: [policy] };
      const constructors = { 'CWE-1004': CWE1004Plugin, 'CWE-614': CWE614Plugin, 'CWE-942': CWE942Plugin,
        'CWE-639': CWE639Plugin, 'CWE-862': CWE862Plugin, 'CWE-79': CWE79Plugin, 'CWE-89': CWE89Plugin };
      const rule: CWEPlugin = new constructors[cweId as keyof typeof constructors](options);
      const store = new FileEvidenceStore(join(directory, `${mode}-${cweId}`));
      try {
        const source: Evidence = { id: 'source', projectId: project.id, producerId: 'fixture-source', kind: 'static-analysis',
          endpointId: 'endpoint', capturedAt: '2026-10-19T00:00:00Z', summary: 'Static suspicion retained for both modes.', facts: { cweId } };
        const evidence = store.capture([source], { project, capabilityIds: ['static-analysis'] });
        const ctx: AnalysisContext = { project, identities, components: [{ id: 'api', projectId: project.id, name: 'API', kind: 'service' }],
          endpoints: [{ id: 'endpoint', componentId: 'api', path, method: 'GET', roles: admin ? ['admin'] : [],
            authentication: cweId === 'CWE-79' || cweId === 'CWE-89' ? 'optional' : 'required',
            parameters: [{ name: 'q', location: 'query', required: false }], evidenceIds: ['source'] }],
          resources: [{ id: policy.resourceId, projectId: project.id, type: 'fixture', externalKey: '1',
            endpointId: 'endpoint', ownerIdentityId: policy.ownerIdentityId, evidenceIds: ['source'] }],
          signals: [{ id: 'candidate', projectId: project.id, producerId: 'fixture-source', endpointId: 'endpoint', cweIds: [cweId],
            summary: 'Candidate only.', evidenceIds: ['source'] }], evidence };
        const hypothesis = (await rule.detectCandidates(ctx))[0]!;
        const plans = await rule.generateTests(ctx, hypothesis);
        const plan = plans[0]! as ProbeTestPlan;
        const common = { project, capabilities };
        let observation: NormalizedProbeEvidence;
        if (cweId === 'CWE-1004' || cweId === 'CWE-614') observation = await new CookieSecurityProbe().execute({ ...common,
          request: { url: path }, identities });
        else if (cweId === 'CWE-942') observation = await new CrossOriginProbe().execute({ ...common, request: { url: path },
          identity: identities[0]!, origins: options.untrustedOrigins });
        else if (cweId === 'CWE-639' || cweId === 'CWE-862') {
          const owner = identities.find(item => item.id === policy.ownerIdentityId)!, attacker = identities.find(item => item.id === policy.attackerIdentityId)!;
          const ownerSession = await manager.establishSession(owner);
          const baseline = await ownerSession.http.execute({ url: path });
          const body = JSON.parse(Buffer.from(baseline.body.data, 'base64').toString());
          expect(baseline.status).toBe(200);
          const marker: string = admin ? body.users.find((user: { username: string }) => user.username === 'admin').email : body.order.shipping_address;
          observation = await new AuthorizationProbe().execute({ ...common, owner, attacker, resource: {
            id: policy.resourceId, ownerIdentityId: owner.id, request: { url: path }, ownerMarkers: [marker] } });
        } else {
          const input = { ...common, request: { url: `${path}?q=Laptop` }, parameter: { name: 'q', location: 'query' as const } };
          observation = cweId === 'CWE-79' ? await new XSSProbe().execute(input) : await new SQLInjectionProbe().execute(input);
        }
        const proof = store.capture([toCoreEvidence(observation, 'endpoint')], { project, targetUrl: plan.targetUrl, capabilityIds: plan.requiredCapabilities });
        const input = { context: { ...ctx, evidence: [...evidence, ...proof] }, hypothesis, plans,
          results: [{ id: 'result', planId: plan.id, producerId: 'probe-runner', outcome: 'COMPLETED' as const, summary: 'Actual probe.', evidence: proof }] };
        const decision = await new VerificationJudge({ plugins: [rule], evidenceStore: store }).judge(input);
        findings.push(decision.finding);
        expect(decision.runtimeEvidenceIds).toHaveLength(1);
        expect(JSON.stringify(decision)).not.toMatch(/alice123|bob123|admin123|sess_alice|shipping_address/);
        expect(decision.diagnostics).toEqual([]);
        expect(decision.finding.status, `${cweId}: ${decision.finding.rootCause}`).toBe(mode === 'vulnerable' && !['CWE-79', 'CWE-89'].includes(cweId) ? 'CONFIRMED' : 'NOT_REPRODUCED');
        const checkpoint = store.headDigest; store.close();
        const reopened = new FileEvidenceStore(join(directory, `${mode}-${cweId}`), { expectedHeadDigest: checkpoint });
        try {
          const replay = await new VerificationJudge({ plugins: [rule], evidenceStore: reopened }).judge(input);
          expect(replay).toEqual(decision);
          expect(reopened.exportFinding(replay.finding).evidence).toHaveLength(2);
        } finally { reopened.close(); }
      } finally { store.close(); }
    }
    expect(findings.filter(item => item.status === 'CONFIRMED')).toHaveLength(mode === 'fixed' ? 0 : 5);
  }, 30_000);
});

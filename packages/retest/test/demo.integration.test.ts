import { execFile, execFileSync, fork } from 'node:child_process';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { request as httpsRequest } from 'node:https';
import { createRequire } from 'node:module';
import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import type { AnalysisContext, CWEId, Finding, Identity, Project } from '@agento/core';
import { MVP_CWES } from '@agento/core';
import { CWE79Plugin, CWE89Plugin, CWE639Plugin, CWE862Plugin, CWE942Plugin, CWE1004Plugin, CWE614Plugin,
  toCoreEvidence, type CWEPlugin, type NormalizedProbeEvidence, type ProbeTestPlan } from '@agento/cwe';
import { FileEvidenceStore } from '@agento/evidence';
import { ExpressRemediationProvider, EXPRESS_STOREFRONT_SOURCE_PATHS } from '@agento/remediation';
import { AuthorizationProbe, CapabilityRegistry, CookieSecurityProbe, CrossOriginProbe, DeterministicRequestExecutor,
  NormalizedCookieAnalyzer, NormalizedHeaderAnalyzer, NormalizedResponseCollector, NormalizedResponseComparator,
  SQLInjectionProbe, type AuthSession, type AuthenticationManager, type HttpTransport, type XSSEvidence } from '@agento/runtime';
import { buildSecurityReport, reportToJSON } from '@agento/reporting';
import { LocalPatchEnvironment, RetestEngine, type LocalTarget, type RetestInput } from '../src/index.js';
import { digest, repository } from './helpers.js';

const suite = process.env.AGENTO_RETEST_INTEGRATION === '1' ? describe : describe.skip;
suite('closed loop against separate copies of the actual Express storefront', () => {
  let directory: string, key: string, cert: string, certificate: Buffer;
  beforeAll(() => {
    directory = mkdtempSync(join(tmpdir(), 'agento-retest-live-')); key = join(directory, 'key.pem'); cert = join(directory, 'cert.pem');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
      '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'], { stdio: 'ignore' });
    certificate = readFileSync(cert);
  });
  afterAll(() => { if (directory) rmSync(directory, { recursive: true, force: true }); });
  const include = ['src', 'public', 'package.json', 'tsconfig.json'];
  async function start(path: string, signal: AbortSignal): Promise<LocalTarget> {
    const child = fork(fileURLToPath(new URL('./fixtures/storefront.mjs', import.meta.url)), [path, key, cert], {
      cwd: path, execArgv: ['--import', join(repository, 'node_modules/tsx/dist/loader.mjs')],
      stdio: ['ignore', 'ignore', 'pipe', 'ipc'], signal,
      env: { PATH: process.env.PATH, NODE_ENV: 'test', DB_PATH: ':memory:' },
    });
    let startupError = ''; child.stderr?.on('data', chunk => { startupError = (startupError + chunk.toString()).slice(-4000); });
    const dispose = async () => {
      if (child.exitCode !== null || child.signalCode) return;
      await new Promise<void>(resolve => {
        const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
        child.once('exit', () => { clearTimeout(timer); resolve(); }); child.kill('SIGTERM');
      });
    };
    try {
      const baseUrl = await new Promise<string>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Startup timed out')), 10_000);
        child.once('message', message => { clearTimeout(timer); resolve((message as { baseUrl: string }).baseUrl); });
        child.once('error', error => { clearTimeout(timer); reject(error); });
        child.once('exit', () => { clearTimeout(timer); reject(new Error('Target exited: ' + startupError)); });
      });
      return { baseUrl, dispose };
    } catch (error) { await dispose(); throw error; }
  }
  async function regression(path: string, input: RetestInput, signal: AbortSignal) {
    const output = join(path, 'test-results.json');
    await promisify(execFile)(process.execPath, [join(repository, 'node_modules/typescript/bin/tsc'), '-p', 'tsconfig.json', '--noEmit'], { cwd: path, signal, timeout: 20_000 });
    let commandPassed = true;
    try {
      await promisify(execFile)(process.execPath, [join(repository, 'node_modules/vitest/vitest.mjs'), 'run', input.remediation.regressionTestPath,
        '--reporter=json', '--outputFile=' + output], { cwd: path, signal, timeout: 30_000,
        env: { PATH: process.env.PATH, AGENTO_TEST_TLS_KEY: key, AGENTO_TEST_TLS_CERT: cert, DB_PATH: ':memory:' } });
    } catch { commandPassed = false; }
    const report = JSON.parse(readFileSync(output, 'utf8')) as { testResults: { assertionResults: { title: string; status: string }[] }[] };
    const assertions = report.testResults.flatMap(item => item.assertionResults);
    const status = (prefix: string) => {
      const selected = assertions.filter(item => item.title.startsWith(prefix));
      return commandPassed && selected.length && selected.every(item => item.status === 'passed') ? 'PASSED' as const : 'FAILED' as const;
    };
    return { security: status('security:'), normalFlow: status('normal:') };
  }
  const transport: HttpTransport = { send: request => new Promise((resolve, reject) => {
    const outgoing = httpsRequest(request.url, { ca: certificate, method: request.method, headers: request.headers,
      signal: request.signal, agent: false }, incoming => {
      const chunks: Buffer[] = [], headers: Record<string, string[]> = {};
      for (let i = 0; i < incoming.rawHeaders.length; i += 2) (headers[incoming.rawHeaders[i]!.toLowerCase()] ??= []).push(incoming.rawHeaders[i + 1]!);
      let bytes = 0;
      incoming.on('data', (chunk: Buffer) => { bytes += chunk.length; if (bytes <= request.maxBodyBytes) chunks.push(chunk); });
      incoming.on('error', reject);
      incoming.on('end', () => resolve({ status: incoming.statusCode!, headers, body: Buffer.concat(chunks), truncated: bytes > request.maxBodyBytes, firstByteMs: 1 }));
    });
    outgoing.on('error', reject); outgoing.end(request.body);
  }) };
  async function probe(project: Project, rule: CWEPlugin, path: string, signal: AbortSignal): Promise<NormalizedProbeEvidence> {
    const identities: Identity[] = ['alice', 'bob', 'admin'].map(id => ({ id, label: id,
      roles: [id === 'admin' ? 'admin' : 'customer'], authentication: 'session-cookie' }));
    const executor = new DeterministicRequestExecutor({ baseUrl: project.baseUrl, allowedOrigins: [project.baseUrl], transport });
    const cookies = new NormalizedCookieAnalyzer(), collector = new NormalizedResponseCollector();
    const manager: AuthenticationManager = { establishSession: async identity => {
      const login = await executor.execute({ url: '/api/auth/login', method: 'POST', signal, headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: identity.id, password: identity.id + '123' }) });
      expect(login.status).toBe(200);
      const cookie = (login.headers['set-cookie'] ?? []).map(item => item.split(';')[0]).join('; ');
      const session: AuthSession = { id: 'session:' + identity.id, identityId: identity.id, expiresAt: new Date(Date.now() + 60_000).toISOString(),
        http: { execute: input => executor.execute({ ...input, signal, headers: { ...input.headers, cookie } }) },
        cookies: async () => cookies.analyze(login), network: () => [], withBrowser: async () => { throw new Error(); }, close: async () => {} };
      return session;
    } };
    const capabilities = new CapabilityRegistry().register('request-executor', executor).register('response-collector', collector)
      .register('cookie-analyzer', cookies).register('header-analyzer', new NormalizedHeaderAnalyzer())
      .register('response-comparator', new NormalizedResponseComparator()).register('authentication-manager', manager)
      .register('cookie-inspector', { inspect: session => session.cookies() });
    const common = { project, capabilities, signal }, cwe = rule.cweId;
    if (cwe === 'CWE-1004' || cwe === 'CWE-614') {
      const login = await executor.execute({ url: path, method: 'POST', signal, headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'alice', password: 'alice123' }) });
      return { id: 'cookie:' + digest(project.baseUrl), probeId: 'cookie-security', projectId: project.id, capturedAt: new Date().toISOString(),
        outcome: 'COMPLETED', diagnostics: [], observations: [{ identityId: 'alice', context: 'authenticated', response: collector.evidence(login), cookies: await cookies.analyze(login) }] };
    }
    if (cwe === 'CWE-942') return new CrossOriginProbe().execute({ ...common, request: { url: path }, origins: ['https://untrusted.invalid'], identity: identities[0]! });
    if (cwe === 'CWE-639' || cwe === 'CWE-862') {
      const owner = identities[cwe === 'CWE-862' ? 2 : 0]!, attacker = identities[cwe === 'CWE-862' ? 0 : 1]!;
      const baseline = await (await manager.establishSession(owner)).http.execute({ url: path });
      const body = JSON.parse(Buffer.from(baseline.body.data, 'base64').toString());
      const marker = cwe === 'CWE-862' ? body.users.find((user: { username: string }) => user.username === 'admin').email : body.order.shipping_address;
      return new AuthorizationProbe().execute({ ...common, owner, attacker, resource: { id: 'resource', ownerIdentityId: owner.id,
        request: { url: path }, ownerMarkers: [marker] } });
    }
    if (cwe === 'CWE-89') {
      // Small objective syntax adapter. Confirmation still comes from the original runtime probe's actual responses.
      capabilities.register('sql-scanner', { scan: async request => {
        const url = new URL(request.request.url); url.searchParams.set('q', "SecureKey'");
        const reply = await request.executor.execute({ ...request.request, url: url.href });
        const databaseError = /SQLITE_ERROR|SqliteError/.test(Buffer.from(reply.body.data, 'base64').toString());
        return { technique: 'error', dbmsFingerprint: databaseError ? 'SQLite' : null, observedDifference: databaseError };
      } });
      return new SQLInjectionProbe().execute({ ...common, request: { url: path + '?q=SecureKey' },
        parameter: { name: 'q', location: 'query' }, sqlBooleanContext: 'like-pattern', responseJsonPointer: '/results' });
    }
    // This host replay keeps the exact original script payload/canary, with execution observed in real Chromium.
    const canary = 'agento-original-retest-canary', payload = `<agento-canary id="${canary}"></agento-canary><script>window.name="${canary}"</script>`;
    const baseline = await executor.execute({ url: path + '?q=SecureKey', signal });
    const injectedUrl = project.baseUrl + path + '?q=' + encodeURIComponent(payload);
    const injected = await executor.execute({ url: injectedUrl, signal });
    const browserPackage = createRequire(new URL('../../../plugins/tools/e2e-browser/package.json', import.meta.url));
    const { chromium } = await import(browserPackage.resolve('playwright-core'));
    const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
    try {
      const page = await browser.newPage({ ignoreHTTPSErrors: true });
      await page.route('**/*', async (route: any) => {
        if (new URL(route.request().url()).origin !== project.baseUrl) await route.abort(); else await route.continue();
      });
      await page.goto(injectedUrl);
      const executionConfirmed = await page.evaluate((marker: string) => window.name === marker, canary);
      const domSinkReached = await page.locator('agento-canary#' + canary).count() > 0;
      return { id: 'xss:' + digest(project.baseUrl), projectId: project.id, probeId: 'xss', capturedAt: new Date().toISOString(), outcome: 'COMPLETED', diagnostics: [],
        parameter: { name: 'q', location: 'query' }, baseline: collector.evidence(baseline), injected: collector.evidence(injected), canary,
        literalReflection: Buffer.from(injected.body.data, 'base64').toString().includes(payload), reflectionContexts: ['html'],
        browser: { url: injectedUrl, canaryVisible: false }, executionConfirmed, domSinkReached } as XSSEvidence;
    } finally { await browser.close(); }
  }
  const cases: { cweId: typeof MVP_CWES[number]; repair: string }[] = [...MVP_CWES.map(cweId => ({ cweId, repair: 'reviewed' })),
    { cweId: 'CWE-639', repair: 'ineffective' }, { cweId: 'CWE-639', repair: 'crash' }];
  it.each(cases)('$cweId $repair repair replays original proof and records the correct status', async ({ cweId, repair }) => {
    const label = cweId + '-' + repair;
    const beforePath = join(directory, label); mkdirSync(beforePath);
    for (const entry of include) cpSync(join(repository, entry), join(beforePath, entry), { recursive: true });
    symlinkSync(join(repository, 'node_modules'), join(beforePath, 'node_modules'), 'dir');
    const controller = new AbortController(), beforeTarget = await start(beforePath, controller.signal);
    const admin = cweId === 'CWE-862';
    const ruleOptions = { sensitiveCookieNames: ['auth_token'], untrustedOrigins: ['https://untrusted.invalid'],
      authorizationPolicies: [{ resourceId: 'resource', ownerIdentityId: admin ? 'admin' : 'alice', attackerIdentityId: admin ? 'alice' : 'bob', attackerIsUnauthorized: true, anonymousIsUnauthorized: true }] };
    const constructors = { 'CWE-639': CWE639Plugin, 'CWE-862': CWE862Plugin, 'CWE-942': CWE942Plugin,
      'CWE-1004': CWE1004Plugin, 'CWE-614': CWE614Plugin, 'CWE-79': CWE79Plugin, 'CWE-89': CWE89Plugin };
    const rule = new constructors[cweId](ruleOptions), endpointPath = cweId === 'CWE-639' ? '/api/orders/:id' : admin ? '/api/admin/users'
      : cweId === 'CWE-79' ? '/search' : cweId === 'CWE-89' ? '/api/search' : ['CWE-1004', 'CWE-614'].includes(cweId) ? '/api/auth/login' : '/api/products';
    const path = endpointPath.replace(':id', '101');
    const project: Project = { id: 'demo', name: 'Actual isolated storefront', mode: 'code-aware', baseUrl: beforeTarget.baseUrl,
      allowedOrigins: [beforeTarget.baseUrl], repositoryPath: repository, languages: ['typescript'] };
    const store = new FileEvidenceStore(join(directory, 'evidence-' + label));
    try {
      const sources = EXPRESS_STOREFRONT_SOURCE_PATHS.map(path => { const content = readFileSync(repository + path, 'utf8');
        return { path, content, sha256: digest(content), evidenceIds: ['source:' + path] }; });
      const sourceRecords = store.capture(sources.map(source => ({ id: source.evidenceIds[0]!, projectId: project.id,
        kind: 'source-location' as const, producerId: 'snapshot', capturedAt: new Date().toISOString(), summary: 'Reviewed source snapshot.',
        source: { file: source.path, startLine: 1 }, facts: { sourceSha256: source.sha256 } })), { project, capabilityIds: ['source-snapshot'] });
      const original = await probe(project, rule, path, controller.signal), targetUrl = project.baseUrl + path;
      const scope = { projectId: project.id, targetUrl, method: ['CWE-1004', 'CWE-614'].includes(cweId) ? 'POST' : 'GET',
        parameter: { name: 'q', location: 'query' as const }, ...ruleOptions, authorization: ruleOptions.authorizationPolicies[0]! };
      expect((await rule.evaluate([original], scope)).status).toBe('CONFIRMED');
      const runtime = store.capture([toCoreEvidence(original, 'endpoint')], { project, targetUrl, probeId: rule.metadata().probeId, capabilityIds: rule.metadata().requiredCapabilities });
      const context: AnalysisContext = { project, identities: [], components: [], resources: [], signals: [], evidence: [...sourceRecords, ...runtime],
        endpoints: [{ id: 'endpoint', componentId: 'app', path: endpointPath, method: scope.method as 'POST' | 'GET', authentication: 'unknown', roles: [], parameters: [], evidenceIds: [sourceRecords[0]!.id] }] };
      const plan: ProbeTestPlan = { id: 'plan', hypothesisId: 'hypothesis', cweId, executor: 'scanner', risk: 'active', targetUrl,
        identityIds: [], requiredCapabilities: rule.metadata().requiredCapabilities, steps: [], probeId: rule.metadata().probeId, scope };
      const finding: Finding = { id: 'finding', projectId: project.id, hypothesisId: 'hypothesis', cweId, owaspCategory: rule.metadata().owaspCategory,
        title: rule.metadata().title, status: 'CONFIRMED', severity: rule.metadata().severity, confidence: 'high', rootCause: 'Original probe confirmed the reviewed demo defect.',
        endpointId: 'endpoint', evidenceIds: [...sourceRecords.map(item => item.id), runtime[0]!.id], testPlanIds: [plan.id] };
      let remediation = await new ExpressRemediationProvider({ evidenceStore: store, sources }).suggest(context, finding);
      if (repair !== 'reviewed') {
        const file = remediation.files[0]!, before = readFileSync(repository + file.path, 'utf8');
        const after = (repair === 'crash' ? "throw new Error('Controlled broken repair');\n" : '// Controlled ineffective repair.\n') + before;
        const oldLines = before.slice(0, -1).split('\n'), newLines = after.slice(0, -1).split('\n');
        const patch = [`diff --git a/${file.path} b/${file.path}`, `--- a/${file.path}`, `+++ b/${file.path}`,
          `@@ -1,${oldLines.length} +1,${newLines.length} @@`, ...oldLines.map(line => '-' + line), ...newLines.map(line => '+' + line), ''].join('\n');
        remediation = { ...remediation, patch, files: [{ ...file, afterSha256: digest(after) }] };
      }
      const input: RetestInput = { context, finding, plan, remediation, originalResult: { id: 'original', planId: plan.id,
        producerId: 'original-probe', outcome: 'COMPLETED', summary: 'Actual vulnerable application.', evidence: runtime } };
      const originalJson = JSON.stringify(input);
      await beforeTarget.dispose();
      const environment = new LocalPatchEnvironment({ sourceDirectory: repository, include,
        dependencyDirectory: join(repository, 'node_modules'), start, regression,
        replay: (target, originalPlan, rebasedTarget, signal) => {
          expect(originalPlan).toEqual(plan); expect(new URL(rebasedTarget).pathname).toBe(path);
          return probe({ ...project, baseUrl: target.baseUrl, allowedOrigins: [target.baseUrl] }, rule, path, signal);
        } });
      const result = await new RetestEngine({ evidenceStore: store, rules: [rule], environment, timeoutMs: 120_000 }).run(input);
      const expectedStatus = repair === 'reviewed' ? 'FIX_VERIFIED' : repair === 'ineffective' ? 'FIX_FAILED' : 'FIX_INCONCLUSIVE';
      expect(result.status, JSON.stringify(store.get(result.comparisonEvidenceId))).toBe(expectedStatus);
      expect(result.beforeEvidenceIds).toEqual([runtime[0]!.id]); expect(result.afterEvidenceIds).toHaveLength(repair === 'crash' ? 0 : 1);
      expect(JSON.stringify(input)).toBe(originalJson);
      for (const source of sources) expect(readFileSync(repository + source.path, 'utf8')).toBe(source.content);
      const report = buildSecurityReport({ context, findings: [finding], plans: [plan], results: [input.originalResult], remediation: [remediation], retests: [result] }, { evidenceStore: store });
      expect(report.findings[0]!.retest.status).toBe(expectedStatus);
      expect(reportToJSON(report)).not.toMatch(/alice123|bob123|admin123/);
      expect(JSON.stringify(report.evidence)).not.toContain('shipping_address');
      const checkpoint = store.headDigest; store.close();
      const reopened = new FileEvidenceStore(join(directory, 'evidence-' + label), { expectedHeadDigest: checkpoint });
      try { expect(reopened.get(result.comparisonEvidenceId)!.facts.status).toBe(expectedStatus); } finally { reopened.close(); }
    } finally { await beforeTarget.dispose(); store.close(); }
  }, 120_000);
});

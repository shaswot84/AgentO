import { execFile, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, request as httpsRequest, type Server } from 'node:https';
import type { RequestListener } from 'node:http';
import type { AddressInfo } from 'node:net';
import { promisify } from 'node:util';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DeterministicRequestExecutor, type HttpTransport } from '@agento/runtime';
import { FileEvidenceStore } from '@agento/evidence';
import { fromCoreEvidence } from '@agento/cwe';
import { runA02Scan, HttpCookieAuthenticationManager } from '../src/index.js';

const suite = process.env.AGENTO_A02_INTEGRATION === '1' ? describe : describe.skip;
suite('A02 from real storefront source to verified runtime report', () => {
  let server: Server, origin: string, directory: string, certificate: Buffer;
  let database: { close(): void }, setMode: (mode: 'vulnerable' | 'fixed') => void;
  const oldDatabase = process.env.DB_PATH;
  beforeAll(async () => {
    directory = mkdtempSync(join(tmpdir(), 'agento-a02-live-'));
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
  // The test CA is trusted explicitly. No TLS validation or runtime scope check is disabled.
  const transport: HttpTransport = { send: request => new Promise((resolve, reject) => {
    const outgoing = httpsRequest(request.url, { ca: certificate, method: request.method, headers: request.headers,
      signal: request.signal, agent: false }, incoming => {
      const chunks: Buffer[] = [], headers: Record<string, string[]> = {};
      for (let i = 0; i < incoming.rawHeaders.length; i += 2) (headers[incoming.rawHeaders[i]!.toLowerCase()] ??= []).push(incoming.rawHeaders[i + 1]!);
      let size = 0, truncated = false;
      incoming.on('data', (chunk: Buffer) => {
        const remaining = Math.max(0, request.maxBodyBytes - size);
        chunks.push(chunk.subarray(0, remaining)); size += chunk.length; truncated ||= size > request.maxBodyBytes;
      });
      incoming.on('end', () => resolve({ status: incoming.statusCode!, headers, body: Buffer.concat(chunks), truncated, firstByteMs: 1 }));
      incoming.on('error', reject);
    });
    outgoing.on('error', reject); outgoing.end(request.body);
  }) };
  it.each(['vulnerable', 'fixed'] as const)('discovers, plans, probes, verifies and reports %s mode', async mode => {
    setMode(mode);
    const executor = new DeterministicRequestExecutor({ baseUrl: origin, allowedOrigins: [origin], transport });
    const authentication = new HttpCookieAuthenticationManager({ executor, login: async identity => ({
      url: '/api/auth/login', method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: identity.id, password: `${identity.id}123` }),
    }) });
    const store = new FileEvidenceStore(join(directory, mode));
    try {
      const report = await runA02Scan({ project: { id: `store-${mode}`, name: 'A02 storefront', mode: 'code-aware',
        repositoryPath: new URL('../../../demo-apps/demo-app-01', import.meta.url).pathname, baseUrl: origin,
        allowedOrigins: [origin], languages: ['typescript'] }, paths: ['/api/auth/me'],
        identities: [{ id: 'alice', label: 'Alice', roles: ['customer'], authentication: 'session-cookie' }],
        sensitiveCookieNames: ['auth_token'], untrustedOrigins: ['https://unapproved.invalid'],
        authentication, transport, evidenceStore: store,
        policy: { allowedOrigins: [origin], allowedMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
          tools: { 'a02-http': {}, 'a02-auth': {} }, approval: { risks: [], severities: [] } } });
      expect(report.findings).toHaveLength(3);
      expect(report.findings.every(finding => finding.status === (mode === 'vulnerable' ? 'CONFIRMED' : 'NOT_REPRODUCED')),
        JSON.stringify(report.decisions)).toBe(true);
      expect(report.executions.every(item => item.outcome === 'COMPLETED'), JSON.stringify(report.executions)).toBe(true);
      expect(report.executions.filter(item => item.probeId === 'cookie-security' && !item.reused)).toHaveLength(1);
      expect(report.context.evidence.filter(item => fromCoreEvidence(item))).toHaveLength(2);
      expect(report.decisions.every(item => item.runtimeEvidenceIds.length === 1 && item.diagnostics.length === 0)).toBe(true);
      const cookieProofs = report.decisions.filter(item => item.finding.cweId !== 'CWE-942').map(item => item.runtimeEvidenceIds[0]);
      expect(new Set(cookieProofs).size).toBe(1);
      for (const finding of report.findings) expect(store.exportFinding(finding).evidence.length).toBeGreaterThan(1);
      expect(JSON.stringify(report)).not.toMatch(/alice123|sess_alice|shipping_address|sessionToken/);
    } finally { store.close(); await authentication.close(); }
  }, 30_000);

  it('runs the built CLI with private environment credentials and writes a readable proof report', async () => {
    setMode('vulnerable');
    const config = join(directory, 'cli.json'), output = join(directory, 'report.json');
    const example = JSON.parse(readFileSync(new URL('../examples/storefront.json', import.meta.url), 'utf8'));
    example.project.repositoryPath = new URL('../../../demo-apps/demo-app-01', import.meta.url).pathname;
    example.project.baseUrl = origin; example.project.allowedOrigins = [origin]; example.policy.allowedOrigins = [origin];
    example.evidenceDirectory = join(directory, 'cli-evidence'); example.output = output;
    writeFileSync(config, JSON.stringify(example));
    const { stdout, stderr } = await promisify(execFile)(process.execPath, [new URL('../dist/cli.js', import.meta.url).pathname, config], {
      env: { ...process.env, NODE_EXTRA_CA_CERTS: join(directory, 'cert.pem'), AGENTO_A02_USERNAME: 'alice', AGENTO_A02_PASSWORD: 'alice123' },
    });
    expect(stderr).toBe(''); expect(stdout).toContain('3 verdicts; 3 confirmed.');
    const report = JSON.parse(readFileSync(output, 'utf8'));
    expect(report.findings).toHaveLength(3);
    expect(report.executions.filter((item: { reused: boolean }) => item.reused)).toHaveLength(1);
    expect(statSync(output).mode & 0o777).toBe(0o600);
    expect(readFileSync(output, 'utf8')).not.toMatch(/alice123|sess_alice/);
    await expect(promisify(execFile)(process.execPath, [new URL('../dist/cli.js', import.meta.url).pathname, config], {
      env: { ...process.env, AGENTO_A02_USERNAME: 'alice', AGENTO_A02_PASSWORD: 'alice123' },
    })).rejects.toMatchObject({ code: 1, stderr: 'A02 scan failed: invalid-options.\n' });
  }, 30_000);
});

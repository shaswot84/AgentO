import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { createServer, type Server, type RequestListener } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FileEvidenceStore } from '@agento/evidence';
import { fromCoreEvidence } from '@agento/cwe';
import { storefrontBrowserOptions } from '@agento/tool-e2e-browser';
import type { AuthorizationEvidence } from '@agento/runtime';
import { runA01Scan, type AuthorizationTarget } from '../src/index.js';

const suite = process.env.AGENTO_A01_INTEGRATION === '1' ? describe : describe.skip;
suite('isolated Chromium logins and authorization proof against the actual storefront', () => {
  let server: Server, origin: string, directory: string, database: { close(): void }, setMode: (mode: 'vulnerable' | 'fixed') => void;
  const oldDatabase = process.env.DB_PATH;
  const observed: { path: string; cookie: string; status: number }[] = [];
  const input = JSON.parse(readFileSync(new URL('../examples/storefront.json', import.meta.url), 'utf8'));
  const repositoryPath = new URL('../../../demo-apps/demo-app-01', import.meta.url).pathname;
  beforeAll(async () => {
    directory = mkdtempSync(join(tmpdir(), 'agento-a01-live-')); process.env.DB_PATH = ':memory:';
    const app: { createApp(): RequestListener } = await import(new URL('../../../demo-apps/demo-app-01/src/app.ts', import.meta.url).pathname);
    const db: { db: { close(): void }; initDatabase(): void } = await import(new URL('../../../demo-apps/demo-app-01/src/db/database.ts', import.meta.url).pathname);
    const config: { setSecurityMode: typeof setMode } = await import(new URL('../../../demo-apps/demo-app-01/src/config.ts', import.meta.url).pathname);
    database = db.db; db.initDatabase(); setMode = config.setSecurityMode;
    const listener = app.createApp();
    server = createServer((request, response) => {
      const path = request.url ?? '';
      if (['/api/orders/102', '/api/admin/users'].includes(path)) response.on('finish', () => {
        observed.push({ path, cookie: request.headers.cookie ?? '', status: response.statusCode });
      });
      listener(request, response);
    });
    await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    if (server) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
    database?.close(); if (directory) rmSync(directory, { recursive: true, force: true });
    if (oldDatabase === undefined) delete process.env.DB_PATH; else process.env.DB_PATH = oldDatabase;
  });
  it.each(['vulnerable', 'fixed'] as const)('reliably verifies both CWEs in %s mode with distinct authenticated and anonymous requests', async mode => {
    setMode(mode);
    // Each repeat gets new browser contexts, authentication manager and proof journal.
    for (const repeat of [0, 1]) {
      observed.length = 0;
      const store = new FileEvidenceStore(join(directory, `${mode}-${repeat}`)), browser = storefrontBrowserOptions([origin]);
      try {
        const report = await runA01Scan({ project: { ...input.project, repositoryPath, baseUrl: origin, allowedOrigins: [origin] },
          targets: input.targets as AuthorizationTarget[], target: browser.target!, credentials: browser.credentials!, evidenceStore: store,
          policy: { ...input.policy, allowedOrigins: [origin] } });
        expect(report.hypotheses, JSON.stringify(report.diagnostics)).toHaveLength(2); expect(report.diagnostics).toEqual([]);
        expect(report.executions.every(item => item.outcome === 'COMPLETED'), JSON.stringify(report.executions)).toBe(true);
        expect(report.findings.every(item => item.status === (mode === 'vulnerable' ? 'CONFIRMED' : 'NOT_REPRODUCED')), JSON.stringify(report.decisions)).toBe(true);
        expect(observed).toHaveLength(6);
        for (const path of ['/api/orders/102', '/api/admin/users']) {
          const requests = observed.filter(item => item.path === path);
          expect(requests[0]!.status).toBe(200);
          expect(requests[0]!.cookie).toContain('agento_sid='); expect(requests[1]!.cookie).toContain('agento_sid=');
          expect(requests[0]!.cookie).not.toBe(requests[1]!.cookie); expect(requests[2]!.cookie).toBe('');
          expect(requests[1]!.status).toBe(mode === 'vulnerable' ? 200 : 403); expect(requests[2]!.status).toBe(401);
        }
        for (const decision of report.decisions) {
          expect(decision.diagnostics).toEqual([]); expect(decision.staticEvidenceIds.length).toBeGreaterThan(0); expect(decision.runtimeEvidenceIds).toHaveLength(1);
          expect(store.exportFinding(decision.finding).evidence.length).toBeGreaterThan(1);
        }
        const proof = report.context.evidence.map(fromCoreEvidence).find(item => item?.probeId === 'authorization'
          && (item as AuthorizationEvidence).resourceId === 'alice-order') as AuthorizationEvidence;
        expect(proof.ownerIdentityId).toBe('alice'); expect(proof.attackerIdentityId).toBe('bob');
        expect(proof.attackerComparison.ownerMarkersMatch).toBe(mode === 'vulnerable');
        const publicData = JSON.stringify(report);
        expect(publicData).not.toMatch(/alice123|bob123|admin123|sess_alice|sess_bob|sess_admin|124 Alice Way|admin@agento.local/);
        expect(readFileSync(join(directory, `${mode}-${repeat}`, 'evidence.jsonl'), 'utf8')).not.toMatch(/alice123|sess_alice|124 Alice Way/);
      } finally { store.close(); }
    }
  }, 180_000);
  it('runs the built JSON CLI with environment credentials and refuses existing report and proof paths', async () => {
    setMode('vulnerable');
    const config = structuredClone(input);
    config.project = { ...config.project, repositoryPath, baseUrl: origin, allowedOrigins: [origin] }; config.policy.allowedOrigins = [origin];
    config.output = join(directory, 'cli-report.json'); config.evidenceDirectory = join(directory, 'cli-proof');
    const path = join(directory, 'config.json'); writeFileSync(path, JSON.stringify(config));
    const env = { ...process.env, AGENTO_ALICE_USERNAME: 'alice', AGENTO_ALICE_PASSWORD: 'alice123', AGENTO_BOB_USERNAME: 'bob',
      AGENTO_BOB_PASSWORD: 'bob123', AGENTO_ADMIN_USERNAME: 'admin', AGENTO_ADMIN_PASSWORD: 'admin123' };
    const command = () => promisify(execFile)(process.execPath, [new URL('../dist/cli.js', import.meta.url).pathname, path], { env, timeout: 120_000 });
    const result = await command(); expect(result.stderr).toBe(''); expect(result.stdout).toContain('2 verdicts; 2 confirmed.');
    expect(statSync(config.output).mode & 0o777).toBe(0o600); expect(JSON.parse(readFileSync(config.output, 'utf8')).category).toBe('A01:2025');
    await expect(command()).rejects.toMatchObject({ code: 1, stderr: 'A01 scan failed: invalid-options.\n' });
    config.output = join(directory, 'second-report.json'); writeFileSync(path, JSON.stringify(config));
    await expect(command()).rejects.toMatchObject({ code: 1, stderr: 'A01 scan failed: scan-failed.\n' });
  }, 180_000);
});

import { execFile } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { createServer, type Server, type RequestListener } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DalfoxAdapter, SqlmapAdapter } from '@agento/security-scanners';
import { FileEvidenceStore } from '@agento/evidence';
import type { XSSEvidence } from '@agento/runtime';
import { fromCoreEvidence } from '@agento/cwe';
import { runA05Scan } from '../src/index.js';

const suite = process.env.AGENTO_A05_INTEGRATION === '1' ? describe : describe.skip;
suite('native Semgrep, Dalfox, sqlmap and Chromium against the actual storefront', () => {
  let server: Server, origin: string, directory: string, database: { close(): void }, setMode: (mode: 'vulnerable' | 'fixed') => void;
  const oldDatabase = process.env.DB_PATH;
  const semgrepExecutable = process.env.AGENTO_SEMGREP_EXECUTABLE ?? 'semgrep';
  const dalfoxExecutable = process.env.AGENTO_DALFOX_EXECUTABLE ?? 'dalfox';
  const sqlmapExecutable = process.env.AGENTO_SQLMAP_EXECUTABLE ?? 'sqlmap';
  beforeAll(async () => {
    directory = mkdtempSync(join(tmpdir(), 'agento-a05-live-')); process.env.DB_PATH = ':memory:';
    const app: { createApp(): RequestListener } = await import(new URL('../../../demo-apps/demo-app-01/src/app.ts', import.meta.url).pathname);
    const db: { db: { close(): void }; initDatabase(): void } = await import(new URL('../../../demo-apps/demo-app-01/src/db/database.ts', import.meta.url).pathname);
    const config: { setSecurityMode: typeof setMode } = await import(new URL('../../../demo-apps/demo-app-01/src/config.ts', import.meta.url).pathname);
    database = db.db; db.initDatabase(); setMode = config.setSecurityMode;
    server = createServer(app.createApp());
    await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    if (server) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
    database?.close(); if (directory) rmSync(directory, { recursive: true, force: true });
    if (oldDatabase === undefined) delete process.env.DB_PATH; else process.env.DB_PATH = oldDatabase;
  });
  it.each(['vulnerable', 'fixed'] as const)('runs and verifies %s mode with retained source-to-runtime proof', async mode => {
    setMode(mode); const store = new FileEvidenceStore(join(directory, mode));
    try {
      const report = await runA05Scan({ project: { id: `a05-${mode}`, name: 'A05 storefront', mode: 'code-aware',
        baseUrl: origin, allowedOrigins: [origin], languages: ['typescript'],
        repositoryPath: new URL('../../../demo-apps/demo-app-01', import.meta.url).pathname },
        targets: [{ path: '/search', cweId: 'CWE-79', inputs: { q: 'SecureKey' } },
          { path: '/api/search', cweId: 'CWE-89', inputs: { q: 'SecureKey' }, sqlBooleanContext: 'like-pattern', responseJsonPointer: '/results' }],
        allowAnonymous: true, semgrepExecutable, maxScannerRequests: 512,
        scanners: [new DalfoxAdapter({ executable: dalfoxExecutable }).registration(), new SqlmapAdapter({ executable: sqlmapExecutable }).registration()],
        evidenceStore: store, policy: { allowedOrigins: [origin], allowedMethods: ['GET'], maxRequestsPerExecution: 600,
          rateLimit: { maxRequests: 2000, windowMs: 60000 },
          tools: { 'a05-http': {}, 'a05-browser': {}, 'dalfox-adapter': {}, 'sqlmap-adapter': {} }, approval: { risks: [], severities: [] } } });
      expect(report.findings, JSON.stringify(report.diagnostics)).toHaveLength(2);
      expect(report.executions.every(item => item.outcome === 'COMPLETED'), JSON.stringify(report.executions)).toBe(true);
      expect(report.diagnostics, JSON.stringify(report.context.evidence.filter(item => fromCoreEvidence(item)))).toEqual([]);
      expect(report.findings.filter(item => item.status === 'CONFIRMED'), JSON.stringify(report.decisions)).toHaveLength(mode === 'vulnerable' ? 2 : 0);
      const proof = report.context.evidence.map(fromCoreEvidence).find(item => item?.probeId === 'xss');
      expect(proof?.probeId === 'xss' && (proof as XSSEvidence).executionConfirmed).toBe(mode === 'vulnerable');
      expect(report.audit.filter(item => item.operation === 'tool')).toHaveLength(2);
      for (const decision of report.decisions) {
        expect(decision.diagnostics).toEqual([]); expect(decision.staticEvidenceIds.length).toBeGreaterThan(0);
        expect(decision.runtimeEvidenceIds).toHaveLength(1); expect(store.exportFinding(decision.finding).evidence.length).toBeGreaterThan(1);
      }
      expect(JSON.stringify(report)).not.toMatch(/rawExecutedQuery|alice123|sess_alice|window.name/);
    } finally { store.close(); }
  }, 180_000);
  it('runs the built CLI and protects its output and journal from reuse', async () => {
    setMode('vulnerable');
    const input = JSON.parse(readFileSync(new URL('../examples/storefront.json', import.meta.url), 'utf8'));
    input.project.baseUrl = origin; input.project.allowedOrigins = [origin]; input.policy.allowedOrigins = [origin];
    input.project.repositoryPath = new URL('../../../demo-apps/demo-app-01', import.meta.url).pathname;
    input.semgrepExecutable = semgrepExecutable; input.dalfoxExecutable = dalfoxExecutable; input.sqlmapExecutable = sqlmapExecutable;
    input.maxScannerRequests = 512; input.policy.maxRequestsPerExecution = 600;
    input.evidenceDirectory = join(directory, 'cli-proof'); input.output = join(directory, 'report.json');
    const path = join(directory, 'config.json'); writeFileSync(path, JSON.stringify(input));
    const command = () => promisify(execFile)(process.execPath, [new URL('../dist/cli.js', import.meta.url).pathname, path], { env: process.env });
    const result = await command(); expect(result.stderr).toBe(''); expect(result.stdout).toContain('2 verdicts; 2 confirmed.');
    expect(statSync(input.output).mode & 0o777).toBe(0o600);
    expect(JSON.parse(readFileSync(input.output, 'utf8')).category).toBe('A05:2025');
    await expect(command()).rejects.toMatchObject({ code: 1, stderr: 'A05 scan failed: invalid-options.\n' });
    input.output = join(directory, 'second-report.json'); writeFileSync(path, JSON.stringify(input));
    await expect(command()).rejects.toMatchObject({ code: 1, stderr: 'A05 scan failed: scan-failed.\n' });
    expect(existsSync(input.output)).toBe(false);
  }, 180_000);
});

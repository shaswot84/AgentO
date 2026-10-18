import { access, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import type { Evidence } from '@agento/core';
import { ExpressFrameworkAdapter } from '@agento/framework-express';
import { SemgrepAdapter } from '@agento/tool-semgrep';
import { buildApplicationSecurityModel, fromFrameworkAnalysis, fromStaticAnalysis } from '@agento/security-model';
import { engine, project, provider } from './helpers.js';

const roots: string[] = [];
const executable = process.env.AGENTO_SEMGREP_EXECUTABLE ?? 'semgrep';
afterEach(async () => { await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true }))); });
describe.skipIf(process.env.AGENTO_HYPOTHESIS_INTEGRATION !== '1')('installed source tool integration', () => {
  it('generates all seven hypotheses from real demo extraction, Semgrep and explicit fixture ownership', async () => {
    const target = { ...project, repositoryPath: fileURLToPath(new URL('../../../demo-apps/demo-app-01/', import.meta.url)) };
    const source = await new ExpressFrameworkAdapter().extract(target);
    const staticAnalysis = await new SemgrepAdapter({ executable, frameworkAnalysis: source }).analyze(target);
    expect(staticAnalysis.status).toBe('completed'); expect(staticAnalysis.diagnostics).toEqual([]);
    const order = source.endpoints.find(endpoint => endpoint.path === '/api/orders/:id')!;
    // The caller supplies the controlled demo's known owner; the engine never guesses ownership from SQL.
    const ownership: Evidence = { id: 'demo-order-owner', projectId: project.id, producerId: 'controlled-demo-fixture',
      capturedAt: '2026-10-18T00:00:00Z', kind: 'resource-ownership', endpointId: order.id, identityId: 'alice',
      summary: 'Controlled fixture declares Alice owns demo Order 101.', facts: { resourceId: 'order-101', ownerIdentityId: 'alice' } };
    const input = buildApplicationSecurityModel({ project: target,
      identities: [{ id: 'alice', label: 'Alice', roles: ['customer'], authentication: 'session-cookie' }],
      contributions: [fromFrameworkAnalysis(source), fromStaticAnalysis(staticAnalysis), { source: 'declared', evidence: [ownership],
        resources: [{ id: 'order-101', projectId: project.id, type: 'Order', externalKey: '101', ownerIdentityId: 'alice',
          endpointId: order.id, evidenceIds: [ownership.id] }] }] });
    const result = await engine({ provider: provider(() => ({ hypotheses: [] })) }).generate(input);
    expect(new Set(result.hypotheses.map(h => h.cweId))).toEqual(new Set(['CWE-639', 'CWE-862', 'CWE-942', 'CWE-1004', 'CWE-614', 'CWE-79', 'CWE-89']));
    expect(result.hypotheses.every(h => h.status === 'HYPOTHESIS' && h.evidenceIds.length > 0)).toBe(true);
    expect(result.hypotheses.find(h => h.cweId === 'CWE-79')!.evidenceIds.some(id => staticAnalysis.evidence.some(e => e.id === id))).toBe(true);
  }, 30_000);

  it('removes injection hypotheses for fixed-only HTML and SQL source controls', async () => {
    const run = async (fixed: boolean) => {
      const root = await mkdtemp(join(tmpdir(), 'agento-hypothesis-sast-')); roots.push(root);
      await writeFile(join(root, 'app.ts'), `import express from 'express';
import { writeFileSync } from 'node:fs';
writeFileSync('TARGET_EXECUTED', 'wrong');
const app = express();
function escapeHtml(value) { return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
app.get('/search', (req, res) => {
  const input = req.query.q;
  ${fixed ? "res.type('html').send(escapeHtml(input)); db.prepare('SELECT name FROM products WHERE name=?').all(input);"
    : "const html = '<h1>' + input + '</h1>'; res.type('html').send(html); const sql = 'SELECT name FROM products WHERE name=' + input; db.prepare(sql).all();"}
});`);
      const target = { ...project, repositoryPath: root }, source = await new ExpressFrameworkAdapter().extract(target);
      const staticAnalysis = await new SemgrepAdapter({ executable, frameworkAnalysis: source }).analyze(target);
      expect(staticAnalysis.status).toBe('completed');
      const result = await engine().generate(buildApplicationSecurityModel({ project: target,
        contributions: [fromFrameworkAnalysis(source), fromStaticAnalysis(staticAnalysis)] }));
      await expect(access(join(root, 'TARGET_EXECUTED'))).rejects.toThrow(); return result;
    };
    expect(new Set((await run(false)).hypotheses.map(h => h.cweId))).toEqual(new Set(['CWE-79', 'CWE-89']));
    expect((await run(true)).hypotheses).toEqual([]);
  }, 30_000);
});

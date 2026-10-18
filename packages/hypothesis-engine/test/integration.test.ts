import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AgentOOrchestrator, type AnalysisContext } from '@agento/core';
import { ExpressFrameworkAdapter } from '@agento/framework-express';
import { buildApplicationSecurityModel, fromFrameworkAnalysis } from '@agento/security-model';
import { engine, plugins, project, provider, selectAll } from './helpers.js';

const demoPath = fileURLToPath(new URL('../../../demo-apps/demo-app-01/', import.meta.url));
const roots: string[] = [];
afterEach(async () => { await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true }))); });

describe('application model and core compatibility', () => {
  it('grounds hypotheses in the real storefront source without executing target code', async () => {
    const target = { ...project, repositoryPath: demoPath };
    const source = await new ExpressFrameworkAdapter().extract(target);
    const input = buildApplicationSecurityModel({ project: target, contributions: [fromFrameworkAnalysis(source)] });
    const result = await engine().generate(input);
    expect(result.diagnostics).toEqual([]);
    const cwes = new Set(result.hypotheses.map(h => h.cweId));
    expect(cwes).toEqual(new Set(['CWE-1004', 'CWE-614', 'CWE-942', 'CWE-862', 'CWE-89']));
    const admin = result.hypotheses.filter(h => h.cweId === 'CWE-862');
    expect(admin.some(h => input.endpoints.find(e => e.id === h.endpointId)?.path === '/api/admin/users')).toBe(true);
    const sql = result.hypotheses.find(h => h.cweId === 'CWE-89')!;
    expect(input.endpoints.find(e => e.id === sql.endpointId)?.path).toBe('/api/search');
    expect(JSON.stringify(result)).not.toMatch(/alice123|agento-super-secret-demo-session-key/);
    const reviewed = await engine({ provider: provider(() => ({ hypotheses: [] })) }).generate(input);
    expect(reviewed.review).toBe('completed'); expect(reviewed.usage.modelCalls).toBe(1);
    expect(reviewed.diagnostics).toContainEqual({ code: 'model-context-limit' });
    expect(reviewed.hypotheses).toEqual(result.hypotheses);
  });

  it('produces fewer hypotheses for a fixed-only source control with explicit safe settings', async () => {
    const analyze = async (fixed: boolean) => {
      const root = await mkdtemp(join(tmpdir(), 'agento-hypotheses-')); roots.push(root);
      await writeFile(join(root, 'app.ts'), `import express from 'express';
import session from 'express-session';
import cors from 'cors';
const app = express();
app.use(session({ name: 'sid', secret: 'private-secret', cookie: { httpOnly: ${fixed}, secure: ${fixed} } }));
app.use(cors({ origin: ${fixed ? "['https://trusted.test']" : 'true'}, credentials: true }));
app.get('/search', (req, res) => {
  const q = req.query.q;
  ${fixed ? "db.prepare('SELECT name FROM products WHERE name = ?').all(q);" : "db.prepare('SELECT name FROM products WHERE name = ' + q).all();"}
  res.json({ ok: true });
});`);
      const target = { ...project, repositoryPath: root };
      const source = await new ExpressFrameworkAdapter().extract(target);
      const result = await engine().generate(buildApplicationSecurityModel({ project: target, contributions: [fromFrameworkAnalysis(source)] }));
      expect(source.endpoints).toHaveLength(1); return result;
    };
    const vulnerable = await analyze(false), fixed = await analyze(true);
    expect(vulnerable.hypotheses.map(h => h.cweId).sort()).toEqual(['CWE-1004', 'CWE-614', 'CWE-89', 'CWE-942']);
    expect(fixed.hypotheses).toEqual([]);
  });

  it('implements the existing ReasoningModel port without planner or probe dispatch changes', async () => {
    const target = { ...project, repositoryPath: demoPath }, rules = plugins();
    const report = await new AgentOOrchestrator({ plugins: rules, frameworkAdapter: new ExpressFrameworkAdapter(),
      reasoning: engine({ plugins: rules }) }).run({ project: target, identities: [] });
    expect(report.hypotheses.length).toBeGreaterThan(0);
    expect(report.hypotheses.every(h => h.status === 'HYPOTHESIS' && h.evidenceIds.length)).toBe(true);
    expect(report.results.every(result => result.outcome === 'SKIPPED')).toBe(true);
    expect(report.findings.every(finding => finding.status !== 'CONFIRMED')).toBe(true);
  });

  it('generation never invokes plugin test or verdict methods', async () => {
    const rule = plugins()[0]!;
    const generateTests = vi.spyOn(rule, 'generateTests'), evaluateEvidence = vi.spyOn(rule, 'evaluateEvidence');
    const input: AnalysisContext = { project, identities: [], components: [], endpoints: [], resources: [], signals: [], evidence: [] };
    await engine({ plugins: [rule], provider: provider(selectAll) }).generate(input);
    expect(generateTests).not.toHaveBeenCalled(); expect(evaluateEvidence).not.toHaveBeenCalled();
  });
});

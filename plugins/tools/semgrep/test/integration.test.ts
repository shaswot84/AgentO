import { access, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AgentOOrchestrator } from '@agento/core';
import { ExpressFrameworkAdapter } from '@agento/framework-express';
import { describe, expect, it } from 'vitest';
import { SemgrepAdapter } from '../src/index.js';
import { runCli } from '../src/cli.js';
import { now, project, repository } from './helpers.js';

const executable = process.env.AGENTO_SEMGREP_EXECUTABLE ?? 'semgrep';
const demoPath = fileURLToPath(new URL('../../../../demo-apps/demo-app-01/', import.meta.url));
describe.skipIf(process.env.AGENTO_SEMGREP_INTEGRATION !== '1')('installed Semgrep integration', () => {
  it('scans the real demo and joins candidates to Express endpoints through core contracts', async () => {
    const target = project(demoPath);
    const frameworkAdapter = new ExpressFrameworkAdapter({ now });
    const frameworkAnalysis = await frameworkAdapter.extract(target);
    const analysis = await new SemgrepAdapter({ executable, now, frameworkAnalysis }).analyze(target);
    expect(analysis.status).toBe('completed');
    expect(analysis.diagnostics).toEqual([]);
    expect(analysis.signals).toHaveLength(2);
    const expected = [['CWE-89', '/api/search', 21, 49], ['CWE-79', '/search', 74, 149]] as const;
    for (const [cweId, path, sourceLine, sinkLine] of expected) {
      const signal = analysis.signals.find(item => item.cweIds.includes(cweId))!;
      const endpoint = frameworkAnalysis.endpoints.find(item => item.id === signal.endpointId);
      expect(endpoint?.path).toBe(path);
      const evidence = analysis.evidence.find(item => item.id === signal.evidenceIds[0]);
      expect(evidence?.facts).toMatchObject({ runtimeVerified: false, sink: { location: { startLine: sinkLine } },
        sources: [{ location: { file: 'src/routes/search.ts', startLine: sourceLine } }] });
    }
    const report = await new AgentOOrchestrator({ plugins: [], frameworkAdapter,
      staticAnalyzer: new SemgrepAdapter({ executable, now, frameworkAnalysis }) }).run({ project: target, identities: [] });
    expect(report.context.signals).toEqual(analysis.signals);
    expect(report.findings).toEqual([]);
    expect(report.context.evidence.some(item => item.facts.observation === 'static-analysis-run')).toBe(true);
    for (const secret of ['alice123', 'agento-super-secret-demo-session-key', 'check_id', 'rawExecutedQuery']) {
      expect(JSON.stringify(analysis)).not.toContain(secret);
    }
  }, 30_000);

  it('distinguishes unsafe JS/TS sinks from escaped HTML and parameterized SQL without executing target code', async () => {
    const unsafe = `import express from 'express';
import { writeFileSync } from 'node:fs';
writeFileSync('TARGET_EXECUTED', 'wrong');
const app = express();
app.get('/search', (req, res) => {
  const input = req.query.q;
  const html = '<h1>' + input + '</h1>';
  res.status(200).type('html').send(html);
  const sql = 'SELECT name FROM products WHERE name=' + input;
  db.prepare(sql).all();
});`;
    const fixed = `import express from 'express';
const app = express();
function escapeHtml(value) { return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
app.get('/search', (req, res) => {
  const input = req.query.q;
  res.type('html').send(escapeHtml(input));
  db.prepare('SELECT name FROM products WHERE name=?').all(input);
  db.query('SELECT name FROM products WHERE name=$1', [input]);
});`;
    for (const extension of ['js', 'ts']) {
      const unsafePath = await repository({ [`src/app.${extension}`]: unsafe, '.semgrepignore': '*', 'package.json': '{}' });
      const fixedPath = await repository({ [`src/app.${extension}`]: fixed });
      const adapter = new SemgrepAdapter({ executable, now });
      const candidates = await adapter.analyze(project(unsafePath));
      expect(candidates.status).toBe('completed');
      expect(candidates.signals.map(item => item.cweIds[0]).sort()).toEqual(['CWE-79', 'CWE-89']);
      expect(candidates.evidence.find(item => item.facts.ruleId === 'agento.express.request-to-html')?.facts.responseFormat).toBe('html');
      const safe = await adapter.analyze(project(fixedPath));
      expect(safe.status).toBe('completed');
      expect(safe.signals).toEqual([]);
      await expect(access(join(unsafePath, 'TARGET_EXECUTED'))).rejects.toThrow();
      expect(await readFile(join(unsafePath, `src/app.${extension}`), 'utf8')).toBe(unsafe);
    }
  }, 30_000);

  it('demonstrates the standalone normalized JSON CLI', async () => {
    const out: string[] = [], errors: string[] = [];
    const result = await runCli([demoPath, '--executable', executable], text => out.push(text), text => errors.push(text));
    expect(result).toBe(0);
    expect(errors).toEqual([]);
    expect(JSON.parse(out.join('')).signals).toHaveLength(2);
  }, 15_000);
});

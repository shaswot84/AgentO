import { access, readFile, readdir, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { AgentOOrchestrator } from '@agento/core';
import type { FrameworkAnalysis } from '@agento/core';
import { describe, expect, it, vi } from 'vitest';
import { SemgrepAdapter } from '../src/index.js';
import { runCli } from '../src/cli.js';
import { ExecutionError } from '../src/runner.js';
import type { SemgrepInvocation } from '../src/types.js';
import { match, now, output, project, repository } from './helpers.js';

const html = `function handler(req, res) {\n  const input = req.query.q;\n  const html = '<h1>' + input + '</h1>';\n  res.type('html').send(html);\n}`;
const sql = `function handler(req, res) {\n  const input = req.body.name;\n  const sql = 'SELECT * FROM products WHERE name=' + input;\n  if (unsafe) { db.prepare(sql).all(); }\n}`;

describe('normalization and source context', () => {
  it('normalizes both candidate families with one-based source/sink locations and no provider data', async () => {
    const code = `${html}\n${sql.replace('handler', 'other')}`;
    const root = await repository({ 'src/app.ts': code });
    const analysis = await new SemgrepAdapter({ now, runner: async () => output([
      match(code, 'html'), match(code, 'sql', 'agento.express.request-to-sql'),
    ]) }).analyze(project(root));
    expect(analysis.status).toBe('completed');
    expect(analysis.signals.map(item => item.cweIds)).toEqual([['CWE-79'], ['CWE-89']]);
    const candidates = analysis.evidence.filter(item => item.facts.observation === 'static-candidate');
    expect(candidates[0]?.facts).toMatchObject({ runtimeVerified: false, requiresRuntimeVerification: true,
      sink: { kind: 'send' }, sources: [{ location: { file: 'src/app.ts', startLine: 2 }, kind: 'request-query' }], responseFormat: 'html' });
    expect(candidates[1]?.facts).toMatchObject({ sink: { kind: 'prepare' },
      sources: [{ location: { file: 'src/app.ts', startLine: 7 }, kind: 'request-body' }], conditions: [{ branch: 'then' }] });
    const json = JSON.stringify(analysis);
    for (const secret of ['RAW_SECRET', 'SOURCE_SECRET', 'TOKEN_SECRET', 'TOP_LEVEL_SECRET', 'CWE-999', 'check_id', '<h1>']) {
      expect(json).not.toContain(secret);
    }
    for (const signal of analysis.signals) {
      expect(signal).not.toHaveProperty('status');
      expect(signal.evidenceIds.every(id => analysis.evidence.some(item => item.id === id))).toBe(true);
    }
  });

  it('deduplicates exact matches, keeps distinct sinks and produces stable IDs across timestamps', async () => {
    const code = 'function route(req,res) { const q = req.query.q; const other = q; res.send(q); res.end(other); }';
    const root = await repository({ 'src/app.ts': code });
    const runner = async () => output([match(code, 'q'), match(code, 'q'), match(code, 'other')]);
    const first = await new SemgrepAdapter({ runner, now }).analyze(project(root));
    const second = await new SemgrepAdapter({ runner, now: () => '2026-10-12T01:00:00Z' }).analyze(project(root));
    expect(first.signals).toHaveLength(2);
    expect(second.signals).toEqual(first.signals);
    expect(new Set(first.evidence.map(item => item.id)).size).toBe(first.evidence.length);
    expect(first.evidence.map(item => item.id)).toEqual(second.evidence.map(item => item.id));
  });

  it('rejects out-of-snapshot paths, unknown rules, prototype keys and invalid ranges while retaining valid candidates', async () => {
    const root = await repository({ 'src/app.ts': html });
    const good = match(html, 'html');
    const analysis = await new SemgrepAdapter({ now, runner: async invocation => output([
      good, { ...good, path: '../private.ts' }, { ...good, path: '/etc/passwd' },
      { ...good, path: join(invocation.cwd, '..', 'private.ts') }, { ...good, path: 'src/missing.ts' },
      { ...good, check_id: 'CWE-89-confirmed' }, { ...good, check_id: '__proto__' },
      { ...good, start: { line: 0, col: 1 } }, { ...good, end: { line: 9999, col: 1 } },
    ]) }).analyze(project(root));
    expect(analysis.status).toBe('partial');
    expect(analysis.signals).toHaveLength(1);
    expect(analysis.diagnostics.map(item => item.code)).toContain('invalid-match');
    expect(analysis.diagnostics.map(item => item.code)).toContain('unknown-rule');
    expect(JSON.stringify(analysis)).not.toContain('private.ts');
  });

  it('accepts absolute snapshot locations and translates UTF-8 columns to AST positions', async () => {
    const code = 'function route(req,res) { const q = req.query.q; /* नेपाली */ res.send(q); }';
    const root = await repository({ 'src/app.ts': code });
    const analysis = await new SemgrepAdapter({ runner: async invocation => output([
      match(code, 'q', undefined, join(invocation.cwd, 'src/app.ts')),
    ]) }).analyze(project(root));
    expect(analysis.status).toBe('completed');
    expect(analysis.evidence[1]?.facts).toMatchObject({ sink: { kind: 'send' }, sources: [{ kind: 'request-query' }] });
  });

  it('follows local aliases and destructuring without mixing shadowed variables or nested callbacks', async () => {
    const code = `function handler(req, res) {
  const { q: input } = req.query;
  const html = input;
  function other(req) { const html = req.body; return html; }
  res.send(html);
}`;
    const root = await repository({ 'src/app.ts': code });
    const analysis = await new SemgrepAdapter({ runner: async () => output([match(code, 'html')]) }).analyze(project(root));
    expect(analysis.evidence[1]?.facts.sources).toEqual([{ kind: 'request-query',
      location: { file: 'src/app.ts', startLine: 2, endLine: 2, symbol: 'query' } }]);
  });

  it('keeps conditional assignment candidates and does not certify sanitizer implementations', async () => {
    const code = `function handler(req, res) {
  const q = req.query.q;
  let html = escapeHtml(q);
  if (unsafe) html = q;
  res.send(html);
}`;
    const root = await repository({ 'src/app.ts': code });
    const analysis = await new SemgrepAdapter({ runner: async () => output([match(code, 'html')]) }).analyze(project(root));
    expect(analysis.evidence[1]?.facts).toMatchObject({ sources: [{ kind: 'request-query' }], contextResolution: 'syntax-only' });
  });

  it('does not assign another receiver’s content type to the matched response', async () => {
    const code = `function handler(req, res, other) { const q = req.query.q; other.type('html'); res.send(q); }`;
    const root = await repository({ 'src/app.ts': code });
    const analysis = await new SemgrepAdapter({ runner: async () => output([match(code, 'q')]) }).analyze(project(root));
    expect(analysis.evidence[1]?.facts.responseFormat).toBe('unknown');
  });

  it('associates only precomputed same-project endpoints without calling a framework provider', async () => {
    const root = await repository({ 'src/app.ts': html });
    const frameworkAnalysis: FrameworkAnalysis = { signals: [], evidence: [], resources: [],
      components: [{ id: 'service', projectId: 'shop', name: 'Shop', kind: 'service' }],
      endpoints: [{ id: 'search', componentId: 'service', method: 'GET', path: '/search', parameters: [],
        authentication: 'unknown', roles: [], evidenceIds: [], handler: { file: 'src/app.ts', startLine: 1, endLine: 5 } }] };
    const analysis = await new SemgrepAdapter({ frameworkAnalysis, runner: async () => output([match(html, 'html')]) }).analyze(project(root));
    expect(analysis.signals[0]?.endpointId).toBe('search');
    expect(analysis.evidence[1]?.endpointId).toBe('search');
    expect(analysis.evidence[1]?.facts.endpointIds).toEqual(['search']);
    const other = await new SemgrepAdapter({ frameworkAnalysis, runner: async () => output([match(html, 'html')]) })
      .analyze({ ...project(root), id: 'other-project' });
    expect(other.signals[0]).not.toHaveProperty('endpointId');
  });
});

describe('execution isolation and failures', () => {
  it('scans a bounded source-only snapshot with fixed arguments and removes it afterwards', async () => {
    const root = await repository({ 'src/app.ts': html, 'package.json': '{"scripts":{"postinstall":"RAW_SECRET"}}',
      'src/test/unsafe.ts': html, 'src/example.spec.ts': html, 'src/shims.d.ts': html,
      '.semgrepignore': '*', 'node_modules/unsafe.js': html, 'dist/app.js': html, '.env': 'SECRET' });
    await symlink(join(root, 'src/app.ts'), join(root, 'linked.ts'));
    let snapshot = '';
    const runner = vi.fn(async (invocation: SemgrepInvocation) => {
      snapshot = invocation.cwd;
      expect(snapshot).not.toBe(root);
      expect(await readdir(snapshot)).toEqual(['src']);
      expect(await readdir(join(snapshot, 'src'))).toEqual(['app.ts']);
      expect(await readFile(join(snapshot, 'src/app.ts'), 'utf8')).toBe(html);
      expect(invocation.args).toContain('--oss-only');
      expect(invocation.args).toContain('--disable-nosem');
      expect(invocation.args).toContain('--no-error');
      expect(invocation.args.slice(-2)).toEqual(['--', '.']);
      expect(invocation.args).not.toContain('--autofix');
      expect(invocation.executable).toBe('trusted-semgrep');
      return output([match(html, 'html')]);
    });
    const analysis = await new SemgrepAdapter({ executable: 'trusted-semgrep', runner }).analyze(project(root));
    expect(analysis.status).toBe('completed');
    expect(runner).toHaveBeenCalledTimes(1);
    await expect(access(snapshot)).rejects.toThrow();
    expect(await readFile(join(root, 'src/app.ts'), 'utf8')).toBe(html);
  });

  it('skips black-box and unsupported projects and diagnoses missing repositories without executing a tool', async () => {
    const root = await repository({ 'src/app.ts': html });
    const runner = vi.fn(async () => output());
    const adapter = new SemgrepAdapter({ runner });
    expect((await adapter.analyze({ ...project(root), mode: 'black-box' })).status).toBe('skipped');
    expect((await adapter.analyze({ ...project(root), languages: ['python'] })).status).toBe('skipped');
    expect((await adapter.analyze(project(join(root, 'absent')))).status).toBe('failed');
    expect((await adapter.analyze({ ...project(root), repositoryPath: undefined } as unknown as ReturnType<typeof project>)).status).toBe('failed');
    expect(runner).not.toHaveBeenCalled();
  });

  it('does not follow a symlink repository root', async () => {
    const root = await repository({ 'src/app.ts': html });
    const container = await repository({});
    await symlink(root, join(container, 'linked'));
    const runner = vi.fn(async () => output());
    const analysis = await new SemgrepAdapter({ runner }).analyze(project(join(container, 'linked')));
    expect(analysis.status).toBe('failed');
    expect(runner).not.toHaveBeenCalled();
  });

  it('reports parse and size limits while scanning remaining usable files', async () => {
    const root = await repository({ 'src/app.ts': html, 'broken.ts': 'function {', 'huge.ts': ' '.repeat(1_048_577) });
    const analysis = await new SemgrepAdapter({ runner: async () => output([match(html, 'html')]) }).analyze(project(root));
    expect(analysis.status).toBe('partial');
    expect(analysis.diagnostics.map(item => item.code)).toEqual(expect.arrayContaining(['parse-failed', 'limit-reached']));
    expect(analysis.signals).toHaveLength(1);
  });

  it('returns completed empty analysis for an empty repository and records provenance', async () => {
    const runner = vi.fn(async () => output());
    const analysis = await new SemgrepAdapter({ runner }).analyze(project(await repository({ 'README.md': 'Empty' })));
    expect(analysis.status).toBe('completed');
    expect(analysis.signals).toEqual([]);
    expect(analysis.evidence[0]?.facts.status).toBe('completed');
    expect(runner).not.toHaveBeenCalled();
  });

  it.each(['tool-not-found', 'timeout', 'output-limit'] as const)('sanitizes %s and removes the temporary snapshot', async code => {
    const root = await repository({ 'src/app.ts': html });
    let snapshot = '';
    const analysis = await new SemgrepAdapter({ runner: async invocation => {
      snapshot = invocation.cwd; throw new ExecutionError(code);
    } }).analyze(project(root));
    expect(analysis.status).toBe('failed');
    expect(analysis.diagnostics[0]?.code).toBe(code);
    expect(analysis.evidence[0]?.facts.status).toBe('failed');
    await expect(access(snapshot)).rejects.toThrow();
  });

  it.each(['not json', '{"results":{}}', '{"results":[],"errors":{}}'])('rejects malformed tool output', async stdout => {
    const root = await repository({ 'src/app.ts': html });
    const analysis = await new SemgrepAdapter({ runner: async () => ({ exitCode: 0, stdout }) }).analyze(project(root));
    expect(analysis.status).toBe('failed');
    expect(analysis.diagnostics[0]?.code).toBe('invalid-output');
  });

  it('retains partial candidates on tool errors without forwarding raw error messages', async () => {
    const root = await repository({ 'src/app.ts': html });
    const analysis = await new SemgrepAdapter({ runner: async () => ({ ...output([match(html, 'html')],
      [{ message: 'ERROR_SECRET', source: '/secret/path' }]), exitCode: 2 }) }).analyze(project(root));
    expect(analysis.status).toBe('partial');
    expect(analysis.signals).toHaveLength(1);
    expect(analysis.diagnostics.map(item => item.code)).toEqual(['scan-error', 'tool-failed']);
    expect(JSON.stringify(analysis)).not.toContain('ERROR_SECRET');
  });

  it('records a failed run when a nonzero tool exit produces no candidates', async () => {
    const root = await repository({ 'src/app.ts': html });
    const analysis = await new SemgrepAdapter({ runner: async () => ({ ...output(), exitCode: 2 }) }).analyze(project(root));
    expect(analysis.status).toBe('failed');
    expect(analysis.signals).toEqual([]);
    expect(analysis.evidence[0]?.facts.diagnosticCodes).toContain('tool-failed');
  });

  it('reports an incomplete scan when the tool silently skips selected source', async () => {
    const root = await repository({ 'src/app.ts': html });
    const analysis = await new SemgrepAdapter({ runner: async () => output([], [], []) }).analyze(project(root));
    expect(analysis.status).toBe('partial');
    expect(analysis.diagnostics[0]?.code).toBe('scan-error');
  });

  it('preserves failure provenance through the real core contract', async () => {
    const root = await repository({ 'src/app.ts': html });
    const report = await new AgentOOrchestrator({ plugins: [], staticAnalyzer: new SemgrepAdapter({ runner: async () => {
      throw new Error('SENSITIVE_COMMAND_SECRET');
    } }) }).run({ project: project(root), identities: [] });
    expect(report.context.evidence[0]?.facts.status).toBe('failed');
    expect(report.findings).toEqual([]);
    expect(JSON.stringify(report)).not.toContain('SENSITIVE_COMMAND_SECRET');
  });

  it('rejects invalid execution limits and enforces injected runner output limits', async () => {
    expect(() => new SemgrepAdapter({ timeoutMs: 0 })).toThrow();
    expect(() => new SemgrepAdapter({ maxOutputBytes: Infinity })).toThrow();
    const root = await repository({ 'src/app.ts': html });
    const analysis = await new SemgrepAdapter({ maxOutputBytes: 2, runner: async () => output() }).analyze(project(root));
    expect(analysis.diagnostics[0]?.code).toBe('output-limit');
  });

  it('prints CLI help and rejects ambiguous executable arguments', async () => {
    const out: string[] = [], errors: string[] = [];
    expect(await runCli(['--help'], text => out.push(text), text => errors.push(text))).toBe(0);
    expect(out[0]).toContain('runtime verification');
    expect(await runCli([], text => out.push(text), text => errors.push(text))).toBe(1);
    expect(await runCli(['repo', '--config', 'https://example.com'], text => out.push(text), text => errors.push(text))).toBe(1);
  });

  it('prints normalized CLI failure JSON with an unsuccessful exit status for missing tools', async () => {
    const root = await repository({ 'src/app.ts': html });
    const out: string[] = [], errors: string[] = [];
    expect(await runCli([root, '--executable', join(root, 'missing-semgrep')], text => out.push(text), text => errors.push(text))).toBe(1);
    const analysis = JSON.parse(out.join(''));
    expect(analysis.status).toBe('failed');
    expect(analysis.diagnostics[0].code).toBe('tool-not-found');
    expect(errors).toEqual([]);
  });
});

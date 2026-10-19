import { mkdtempSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SemgrepAdapter } from '@agento/tool-semgrep';
import { ExpressFrameworkAdapter } from '@agento/framework-express';
import type { BrowserController, HttpTransport, TransportRequest } from '@agento/runtime';
import type { ToolRegistration } from '@agento/capability-registry';
import type { A05ScanOptions } from '../src/index.js';

export function repository() {
  const path = mkdtempSync(join(tmpdir(), 'agento-a05-unit-'));
  writeFileSync(join(path, 'package.json'), '{"dependencies":{"express":"*"}}');
  writeFileSync(join(path, 'app.js'), `import express from 'express';
const app = express();
app.get('/search', (req, res) => {
  const input = req.query.q;
  const keep = req.query.keep;
  const html = '<h1>' + input + '</h1>';
  res.send(html);
});
app.get('/sql', (req, res) => {
  const input = req.query.q;
  const sql = 'SELECT name FROM products WHERE name=' + input;
  db.prepare(sql).all();
});
app.get('/other', (req, res) => {res.send(req.query.other);});
`);
  return path;
}
export async function setup(repositoryPath: string, mode: 'vulnerable' | 'fixed' = 'vulnerable') {
  const origin = 'https://target.test';
  const project = { id: 'a05-unit', name: 'A05 unit target', mode: 'code-aware' as const, repositoryPath,
    baseUrl: origin, allowedOrigins: [origin], languages: ['javascript'] };
  const framework = await new ExpressFrameworkAdapter().extract(project);
  const staticAnalyzer = new SemgrepAdapter({ frameworkAnalysis: framework, runner: async invocation => {
    const text = await readFile(join(invocation.cwd, 'app.js'), 'utf8');
    const results = [['html', 'agento.express.request-to-html'], ['sql', 'agento.express.request-to-sql']].map(([name, check_id]) => {
      const offset = text.indexOf(name!, text.indexOf(name === 'html' ? 'res.send(' : 'db.prepare('));
      const lines = text.slice(0, offset).split('\n');
      return { check_id, path: 'app.js', start: { line: lines.length, col: lines.at(-1)!.length + 1 },
        end: { line: lines.length, col: lines.at(-1)!.length + name!.length + 1 } };
    });
    return { exitCode: 0, stdout: JSON.stringify({ results, errors: [], paths: { scanned: ['app.js'] } }) };
  } });
  const calls: TransportRequest[] = [], scans: string[] = [];
  const transport: HttpTransport = { send: async request => {
    calls.push(request);
    const url = new URL(request.url), q = url.searchParams.get('q') ?? '';
    const results = mode === 'fixed' ? [] : q.includes("'1'='2") ? [] : [{ name: 'private-result' }];
    const body = url.pathname === '/sql' ? JSON.stringify({ query: q, results })
      : mode === 'vulnerable' ? q : q.replaceAll('<', '&lt;');
    return { status: mode === 'vulnerable' && url.pathname === '/sql' && q.endsWith("'") ? 500 : 200,
      headers: { 'content-type': [url.pathname === '/sql' ? 'application/json' : 'text/html'] },
      body: Buffer.from(body), firstByteMs: 1, truncated: false };
  } };
  const browser: BrowserController = { withGuard: guard => ({ withSession: async (identity, callback) => {
    let current = '';
    return callback({ id: 'page', identityId: identity.id, perform: async action => {
      if (action.action === 'navigate') { guard.assertRequest({ url: action.url, method: 'GET' }); current = action.url; }
    }, inspect: async () => ({ url: current, controls: [], visibleTextSummary: '' }),
    readCanary: async () => ({ executed: mode === 'vulnerable', elementPresent: mode === 'vulnerable' }),
    cookies: async () => [], network: () => [], transferCookies: async () => [], importCookies: async () => {} });
  } }), withSession: async () => { throw new Error('unguarded browser'); } };
  const scanners: ToolRegistration[] = [
    { metadata: { id: 'test-xss', capabilities: ['xss-scanner'], supportedCwes: ['CWE-79'], protocols: ['http', 'https'], risk: 'active' },
      capabilities: { 'xss-scanner': { scan: async input => { scans.push(input.request.url); await input.executor.execute(input.request);
        return { executionConfirmed: null, domSinkReached: null }; } } } },
    { metadata: { id: 'test-sql', capabilities: ['sql-scanner'], supportedCwes: ['CWE-89'], protocols: ['http', 'https'], risk: 'active' },
      capabilities: { 'sql-scanner': { scan: async input => { scans.push(input.request.url); await input.executor.execute(input.request);
        return { technique: 'boolean', dbmsFingerprint: null, observedDifference: null }; } } } },
  ];
  const options: A05ScanOptions = { project, targets: [{ path: '/search', cweId: 'CWE-79', inputs: { q: 'private-baseline', keep: 'constant' } },
    { path: '/sql', cweId: 'CWE-89', inputs: { q: 'private-baseline' }, responseJsonPointer: '/results', sqlBooleanContext: 'like-pattern' }],
    staticAnalyzer, transport, browser, scanners, allowAnonymous: true,
    policy: { allowedOrigins: [origin], allowedMethods: ['GET'], tools: { 'a05-http': {}, 'a05-browser': {}, 'test-xss': {}, 'test-sql': {} },
      approval: { risks: [], severities: [] } } };
  return { options, calls, scans };
}

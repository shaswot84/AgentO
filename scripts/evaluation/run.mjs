import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { MemoryEvidenceStore } from '../../packages/evidence/dist/index.js';
import { ExpressFrameworkAdapter } from '../../plugins/frameworks/express/dist/index.js';
import { SemgrepAdapter } from '../../plugins/tools/semgrep/dist/index.js';
import { DalfoxAdapter, SqlmapAdapter } from '../../plugins/tools/security-scanners/dist/index.js';
import { storefrontBrowserOptions } from '../../plugins/tools/e2e-browser/dist/index.js';
import { DeterministicRequestExecutor } from '../../packages/runtime/dist/index.js';
import { CapabilityRegistry } from '../../packages/capability-registry/dist/index.js';
import { PolicyEngine } from '../../packages/policy-engine/dist/index.js';
import { runA01Scan } from '../../packages/a01/dist/index.js';
import { runA02Scan, HttpCookieAuthenticationManager } from '../../packages/a02/dist/index.js';
import { runA05Scan } from '../../packages/a05/dist/index.js';
import { startTarget } from './target.mjs';
import { score, summarize } from './metrics.mjs';
import { verifyResults } from './verify.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const manifest = JSON.parse(readFileSync(new URL('./cases.json', import.meta.url), 'utf8'));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const args = process.argv.slice(2);
if (args.includes('--help')) {
  console.log('Usage: node --import ./demo-apps/demo-app-01/node_modules/tsx/dist/loader.mjs scripts/evaluation/run.mjs --output /tmp/new-result.json [--repeats 2]');
  process.exit(0);
}
if (args.length !== 2 && args.length !== 4 || args[0] !== '--output' || !args[1]
  || args.length === 4 && (args[2] !== '--repeats' || !/^[1-5]$/.test(args[3]))) throw new Error('invalid-arguments');
const output = resolve(args[1]), repeats = Number(args[3] ?? 2);
// Reserve the report before any target work; never overwrite a prior run.
mkdirSync(dirname(output), { recursive: true });
const { openSync, closeSync } = await import('node:fs');
closeSync(openSync(output, 'wx', 0o600));

const repositoryPath = join(root, 'demo-apps/demo-app-01');
const tools = {
  semgrep: process.env.AGENTO_SEMGREP_EXECUTABLE ?? 'semgrep',
  dalfox: process.env.AGENTO_DALFOX_EXECUTABLE ?? 'dalfox',
  sqlmap: process.env.AGENTO_SQLMAP_EXECUTABLE ?? 'sqlmap',
};
const toolVersions = {};
const versionDirectory = mkdtempSync(join(tmpdir(), 'agento-evaluation-versions-'));
try {
  for (const [name, executable] of Object.entries(tools)) {
    // A missing native tool is an error, never a synthetic replacement.
    let text;
    try {
      text = execFileSync(executable, ['--version'], { timeout: 15_000, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
        env: { PATH: process.env.PATH, SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0',
          SEMGREP_SETTINGS_FILE: join(versionDirectory, 'settings.yml'), SEMGREP_LOG_FILE: join(versionDirectory, 'semgrep.log'),
          XDG_CONFIG_HOME: versionDirectory, XDG_CACHE_HOME: versionDirectory } });
    } catch { throw new Error(`tool-preflight-failed:${name}`); }
    toolVersions[name] = text.match(/\d+\.\d+(?:\.\d+)*(?:[^\s\u001b]*)/)?.[0] ?? 'unparsed';
  }
} finally { rmSync(versionDirectory, { recursive: true, force: true }); }
const sourceHashes = {};
function snapshot(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (['node_modules', '.git'].includes(entry.name) || entry.isSymbolicLink()) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) snapshot(path);
    else if (entry.isFile()) sourceHashes[relative(root, path)] = hash(readFileSync(path));
  }
}
for (const path of ['packages', 'plugins', 'scripts/evaluation', 'demo-apps/demo-app-01/src', 'demo-apps/demo-app-01/public']) snapshot(join(root, path));
for (const path of ['demo-apps/demo-app-01/package.json', 'demo-apps/demo-app-01/package-lock.json']) sourceHashes[path] = hash(readFileSync(join(root, path)));
const result = {
  schemaVersion: 1, generatedAt: new Date().toISOString(), target: manifest.target, repeats,
  environment: { node: process.version, platform: process.platform, arch: process.arch, tools: toolVersions,
    playwright: JSON.parse(readFileSync(join(root, 'plugins/tools/e2e-browser/node_modules/playwright-core/package.json'))).version,
    commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim() },
  manifest, sourceHashes, runs: [], summary: {},
  modelUsage: { mode: 'deterministic-recipes-no-model-provider', calls: 0, inputTokens: 0, outputTokens: 0, costUsd: 0 },
  externalProject: { status: 'NOT_RUN', reason: 'No independent real-world Express target is included in this controlled benchmark.' },
};
const target = await startTarget();
const project = (mode, origin, slice) => ({ id: `evaluation-${mode}-${slice}`, name: 'Controlled evaluation storefront',
  mode: 'code-aware', repositoryPath, baseUrl: origin, allowedOrigins: [origin], languages: ['typescript'] });
const policy = (origin, ids) => ({ allowedOrigins: [origin], allowedMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
  tools: Object.fromEntries(ids.map(id => [id, {}])), approval: { risks: [], severities: [] },
  maxRequestsPerExecution: 600, rateLimit: { maxRequests: 2000, windowMs: 60000 } });

async function measure(arm, mode, repeat, slice, cases, execute) {
  const store = new MemoryEvidenceStore(), before = target.count(), start = performance.now();
  const run = { id: `${arm}-${mode}-${repeat}-${slice}`, arm, mode, repeat, slice,
    durationMs: 0, httpRequests: 0, testsExecuted: 0, testsCompleted: 0, observations: [], diagnostics: [] };
  try {
    await execute(run, store);
  } catch (error) {
    // Preserve a failed measurement, without copying exception text or private host paths.
    run.diagnostics.push('assessment-failed');
    console.error(`${run.id}: assessment-failed (${error?.code ?? error?.name ?? 'error'})`);
  } finally {
    for (const item of cases) if (!run.observations.some(observation => observation.id === item.id))
      run.observations.push({ id: item.id, cweId: item.cweId, path: item.path, prediction: 'unknown', dynamicallyVerified: false,
        status: 'MISSING', sourceEvidenceIds: [], runtimeEvidenceIds: [], proof: null });
    run.durationMs = Math.round(performance.now() - start); run.httpRequests = target.count() - before;
    run.metrics = score(cases.map(item => ({ id: item.id, vulnerable: mode === 'vulnerable' })), run.observations);
    result.runs.push(run); store.close();
    console.log(`${run.id}: TP=${run.metrics.tp} FP=${run.metrics.fp} TN=${run.metrics.tn} FN=${run.metrics.fn} unknown=${run.metrics.inconclusive}; ${run.httpRequests} requests; ${run.durationMs} ms`);
  }
}

function retainAssessment(run, store, report, cases) {
  const executions = report.executions.filter(item => !item.reused);
  run.testsExecuted = executions.filter(item => item.outcome !== 'SKIPPED').length;
  run.testsCompleted = executions.filter(item => item.outcome === 'COMPLETED' && item.code === 'collected').length;
  run.diagnostics.push(...report.diagnostics);
  for (const item of cases) {
    const decisions = report.decisions.filter(decision => decision.finding.cweId === item.cweId
      && report.context.endpoints.some(endpoint => endpoint.id === decision.finding.endpointId && endpoint.path === item.path));
    if (decisions.length !== 1) { run.diagnostics.push('missing-or-ambiguous-verdict'); continue; }
    const decision = decisions[0], finding = decision.finding;
    const proof = store.exportFinding(finding);
    run.observations.push({ id: item.id, cweId: item.cweId, path: item.path,
      prediction: finding.status === 'CONFIRMED' ? 'positive' : finding.status === 'NOT_REPRODUCED' ? 'negative' : 'unknown',
      dynamicallyVerified: finding.status === 'CONFIRMED' && decision.runtimeEvidenceIds.length > 0 && decision.diagnostics.length === 0,
      status: finding.status, sourceEvidenceIds: decision.staticEvidenceIds, runtimeEvidenceIds: decision.runtimeEvidenceIds, proof });
  }
}

function baselineProof(store, selectedProject, item, records, status) {
  store.capture(records.filter(record => !store.get(record.id)), { project: selectedProject, targetUrl: new URL(item.path, selectedProject.baseUrl).href,
    probeId: 'evaluation-baseline', capabilityIds: ['static-analysis'] });
  return store.exportFinding({ id: `baseline:${item.id}`, projectId: selectedProject.id, cweId: item.cweId,
    status, evidenceIds: records.map(record => record.id) });
}

try {
  for (let repeat = 1; repeat <= repeats; repeat++) for (const mode of ['vulnerable', 'fixed']) {
    target.setMode(mode);
    const injectionCases = manifest.cases.filter(item => manifest.baselineCaseIds.includes(item.id));
    await measure('semgrep', mode, repeat, 'a05', injectionCases, async (run, store) => {
      const selectedProject = project(mode, target.http, 'semgrep');
      const framework = await new ExpressFrameworkAdapter().extract(selectedProject);
      const analysis = await new SemgrepAdapter({ executable: tools.semgrep, frameworkAnalysis: framework }).analyze(selectedProject);
      run.testsExecuted = 1; run.testsCompleted = analysis.status === 'completed' ? 1 : 0;
      run.diagnostics.push(...analysis.diagnostics.map(item => item.code));
      for (const item of injectionCases) {
        const signals = analysis.signals.filter(signal => signal.cweIds.includes(item.cweId)
          && framework.endpoints.some(endpoint => endpoint.id === signal.endpointId && endpoint.path === item.path));
        const ids = new Set(signals.flatMap(signal => signal.evidenceIds));
        const records = analysis.evidence.filter(record => ids.has(record.id) || record.facts.observation === 'static-analysis-run');
        run.observations.push({ id: item.id, cweId: item.cweId, path: item.path,
          prediction: analysis.status !== 'completed' ? 'unknown' : signals.length ? 'positive' : 'negative', dynamicallyVerified: false,
          status: analysis.status, sourceEvidenceIds: [...ids], runtimeEvidenceIds: [],
          proof: baselineProof(store, selectedProject, item, records, signals.length ? 'HYPOTHESIS' : 'NOT_REPRODUCED') });
      }
    });
    for (const item of injectionCases) await measure('scanners', mode, repeat, item.id, [item], async (run, store) => {
      const selectedProject = project(mode, target.http, `baseline-${item.id}`);
      const adapter = item.cweId === 'CWE-79' ? new DalfoxAdapter({ executable: tools.dalfox }) : new SqlmapAdapter({ executable: tools.sqlmap });
      const plan = { id: `baseline-${item.id}`, cweId: item.cweId, risk: 'active', requiredCapabilities: ['security-scanner'],
        targetUrl: new URL(item.path, target.http).href };
      const resolution = await new CapabilityRegistry().register(adapter.registration()).resolvePlan(plan);
      const guard = new PolicyEngine(policy(target.http, [adapter.id]));
      const input = { project: selectedProject, planId: plan.id, cweId: item.cweId,
        request: { url: `${plan.targetUrl}?q=SecureKey`, method: 'GET' }, parameter: { name: 'q', location: 'query' },
        executor: new DeterministicRequestExecutor({ baseUrl: target.http, allowedOrigins: [target.http] }), maxRequests: 512 };
      const scan = await guard.run({ project: selectedProject, plan }, resolution, execution =>
        execution.capabilities.get('security-scanner').run({ ...input, signal: execution.signal }));
      run.testsExecuted = scan.outcome === 'SKIPPED' ? 0 : 1; run.testsCompleted = scan.outcome === 'COMPLETED' ? 1 : 0;
      if (scan.error) run.diagnostics.push(scan.error.code);
      const positive = scan.evidence.some(record => record.facts.observation === 'scanner-candidate' && record.facts.cweIds.includes(item.cweId));
      const records = store.capture(scan.evidence, { project: selectedProject, targetUrl: plan.targetUrl,
        probeId: 'evaluation-baseline', capabilityIds: ['security-scanner'] });
      run.observations.push({ id: item.id, cweId: item.cweId, path: item.path,
        prediction: scan.outcome !== 'COMPLETED' ? 'unknown' : positive ? 'positive' : 'negative', dynamicallyVerified: false,
        status: scan.outcome, sourceEvidenceIds: [], runtimeEvidenceIds: [],
        proof: store.exportFinding({ id: `baseline:${item.id}`, projectId: selectedProject.id, cweId: item.cweId,
          status: positive ? 'HYPOTHESIS' : 'NOT_REPRODUCED', evidenceIds: records.map(record => record.id) }) });
    });
    for (const slice of ['a01', 'a02', 'a05']) {
      const cases = manifest.cases.filter(item => item.slice === slice);
      await measure('agento', mode, repeat, slice, cases, async (run, store) => {
        let report;
        if (slice === 'a01') {
          const browser = storefrontBrowserOptions([target.http]);
          const config = JSON.parse(readFileSync(join(root, 'packages/a01/examples/storefront.json'), 'utf8'));
          report = await runA01Scan({ project: project(mode, target.http, slice), targets: config.targets,
            target: browser.target, credentials: browser.credentials, evidenceStore: store, signal: AbortSignal.timeout(180_000),
            policy: policy(target.http, ['a01-http', 'a01-auth']) });
        } else if (slice === 'a02') {
          const executor = new DeterministicRequestExecutor({ baseUrl: target.https, allowedOrigins: [target.https], transport: target.transport });
          const authentication = new HttpCookieAuthenticationManager({ executor, login: async identity => ({
            url: '/api/auth/login', method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ username: identity.id, password: `${identity.id}123` }),
          }) });
          try {
            report = await runA02Scan({ project: project(mode, target.https, slice), paths: ['/api/auth/me'],
              identities: [{ id: 'alice', label: 'Alice', roles: ['customer'], authentication: 'session-cookie' }],
              sensitiveCookieNames: ['auth_token'], untrustedOrigins: ['https://unapproved.invalid'],
              transport: target.transport, authentication, evidenceStore: store, signal: AbortSignal.timeout(30_000),
              policy: policy(target.https, ['a02-http', 'a02-auth']) });
          } finally { await authentication.close(); }
        } else {
          const config = JSON.parse(readFileSync(join(root, 'packages/a05/examples/storefront.json'), 'utf8'));
          report = await runA05Scan({ project: project(mode, target.http, slice), targets: config.targets,
            allowAnonymous: true, semgrepExecutable: tools.semgrep, maxScannerRequests: 512,
            scanners: [new DalfoxAdapter({ executable: tools.dalfox }).registration(), new SqlmapAdapter({ executable: tools.sqlmap }).registration()],
            evidenceStore: store, signal: AbortSignal.timeout(180_000),
            policy: policy(target.http, ['a05-http', 'a05-browser', 'dalfox-adapter', 'sqlmap-adapter']) });
        }
        retainAssessment(run, store, report, cases);
      });
    }
  }
} finally { await target.close(); }
result.summary = summarize(result.runs, manifest);
verifyResults(result);
writeFileSync(output, JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
console.log(`Saved ${result.runs.length} measurements to ${output}`);
if (result.runs.some(run => run.metrics.inconclusive || run.diagnostics.length)) process.exitCode = 1;

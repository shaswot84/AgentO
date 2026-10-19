import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { discoverProject, toProject } from '../../packages/discovery/dist/index.js';
import { ExpressFrameworkAdapter } from '../../plugins/frameworks/express/dist/index.js';
import { SemgrepAdapter } from '../../plugins/tools/semgrep/dist/index.js';
import { buildApplicationSecurityModel, fromFrameworkAnalysis, fromStaticAnalysis } from '../../packages/security-model/dist/index.js';
import { SecurityHypothesisEngine } from '../../packages/hypothesis-engine/dist/index.js';
import { SecurityTestPlanner } from '../../packages/test-planner/dist/index.js';
import { CWE639Plugin, CWE862Plugin, CWE942Plugin, CWE1004Plugin, CWE614Plugin, CWE79Plugin, CWE89Plugin } from '../../plugins/cwe/dist/index.js';

const script = fileURLToPath(import.meta.url);
const manifest = JSON.parse(await readFile(new URL('./realworld-cases.json', import.meta.url), 'utf8'));
const hash = value => createHash('sha256').update(value).digest('hex');
const git = (directory, ...args) => execFileSync('git', ['-C', directory, ...args], { encoding: 'utf8', timeout: 10_000 }).trim();
const counts = (items, key) => Object.fromEntries([...new Set(items.map(key))].sort().map(value => [value, items.filter(item => key(item) === value).length]));
const empty = () => ({ components: [], endpoints: [], resources: [], signals: [], evidence: [], diagnostics: [] });

async function inspect(entry, repositories, executable) {
  const checkout = join(repositories, entry.id);
  if (git(checkout, 'rev-parse', 'HEAD') !== entry.revision) throw new Error('revision-mismatch');
  if (git(checkout, 'status', '--porcelain', '--untracked-files=all')) throw new Error('checkout-not-clean');
  const repositoryPath = join(checkout, entry.sourceRoot);
  const started = performance.now();
  const adapter = new ExpressFrameworkAdapter();
  const discovery = await discoverProject(repositoryPath, { adapters: [{ framework: 'express', languages: ['javascript', 'typescript'], adapter }] });
  // This reserved loopback origin is metadata only. No transport or target module is used.
  const project = toProject(discovery, { id: entry.id, name: entry.id, baseUrl: 'http://127.0.0.1:1', allowedOrigins: ['http://127.0.0.1:1'] });
  const supports = await adapter.supports(project);
  // Direct inspection deliberately retains partial results even if supports() is false.
  const framework = discovery.frameworks.includes('express') ? await adapter.extract(project) : empty();
  const analysis = await new SemgrepAdapter({ executable, frameworkAnalysis: framework }).analyze(project);
  const model = buildApplicationSecurityModel({ project, contributions: [fromFrameworkAnalysis(framework), fromStaticAnalysis(analysis)] });
  const plugins = [new CWE639Plugin(), new CWE862Plugin(), new CWE942Plugin(), new CWE1004Plugin(), new CWE614Plugin(), new CWE79Plugin(), new CWE89Plugin()];
  // No sensitive-cookie, account-ownership or role policy is guessed for an unfamiliar app.
  const hypotheses = await new SecurityHypothesisEngine({ plugins }).generate(model);
  const planner = new SecurityTestPlanner({ plugins });
  const planning = [];
  for (const hypothesis of hypotheses.hypotheses) planning.push(await planner.plan(model, hypothesis));
  const referenceRoutes = [];
  for (const reference of entry.routes) {
    const text = await readFile(join(repositoryPath, reference.file), 'utf8');
    if (!text.includes(reference.contains)) throw new Error('reference-source-mismatch');
    referenceRoutes.push({ method: reference.method, path: reference.path, source: reference.file,
      sourceLine: text.slice(0, text.indexOf(reference.contains)).split('\n').length,
      extracted: framework.endpoints.some(endpoint => endpoint.method === reference.method && endpoint.path === reference.path) });
  }
  const evidence = new Set(model.evidence.map(record => record.id));
  const invariants = {
    uniqueEvidenceIds: evidence.size === model.evidence.length,
    evidenceProjectBindings: model.evidence.every(record => record.projectId === project.id),
    endpointEvidenceLinks: model.endpoints.every(endpoint => endpoint.evidenceIds.every(id => evidence.has(id))),
    signalEvidenceLinks: model.signals.every(signal => signal.evidenceIds.every(id => evidence.has(id))),
    hypothesisEvidenceLinks: hypotheses.hypotheses.every(hypothesis => hypothesis.evidenceIds.length > 0 && hypothesis.evidenceIds.every(id => evidence.has(id))),
    hypothesisStates: hypotheses.hypotheses.every(hypothesis => hypothesis.status === 'HYPOTHESIS'),
    sourceUnchanged: git(checkout, 'status', '--porcelain', '--untracked-files=all') === '',
  };
  return { discovery, project, supports, framework, analysis, model, hypotheses, planning, referenceRoutes, invariants,
    durationMs: Math.round(performance.now() - started) };
}

const args = process.argv.slice(2);
if (args[0] === '--worker') {
  try {
    const entry = manifest.cases.find(item => item.id === args[1]);
    if (!entry) throw new Error('unknown-case');
    process.stdout.write(JSON.stringify(await inspect(entry, args[2], args[3])));
  } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
} else if (args.length !== 6 || args[0] !== '--repos' || args[2] !== '--output' || args[4] !== '--semgrep') {
  process.stderr.write('Usage: node scripts/evaluation/realworld.mjs --repos /path/to/checkouts --output /new/result-directory --semgrep /path/to/semgrep\n');
  process.exitCode = 1;
} else {
  const repositories = resolve(args[1]), output = resolve(args[3]);
  // Refuse overwrites and use a child-process deadline for expensive source resolution.
  await mkdir(output, { recursive: false, mode: 0o700 });
  const results = { schemaVersion: 1, generatedAt: new Date().toISOString(), nodeVersion: process.version,
    agentORevision: git(fileURLToPath(new URL('../../', import.meta.url)), 'rev-parse', 'HEAD'),
    runnerSha256: hash(await readFile(script)), manifestSha256: hash(await readFile(new URL('./realworld-cases.json', import.meta.url))),
    scope: 'source-compatibility-only', runtimeAssessments: 0, cases: [] };
  for (const entry of manifest.cases) {
    const child = spawnSync(process.execPath, [script, '--worker', entry.id, repositories, args[5]], {
      encoding: 'utf8', timeout: 180_000, maxBuffer: 32 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (child.status !== 0 || child.error) {
      const reason = child.error?.code === 'ETIMEDOUT' ? 'worker-timeout' : (child.stderr.trim().split('\n').at(-1) || 'worker-failed');
      results.cases.push({ ...entry, status: 'failed', reason });
      console.log(`${entry.id}: failed (${reason})`);
    } else {
      const detail = JSON.parse(child.stdout), artifact = `${entry.id}.json`;
      const content = `${JSON.stringify(detail, null, 2)}\n`;
      await writeFile(join(output, artifact), content, { flag: 'wx', mode: 0o600 });
      const plans = detail.planning.flatMap(item => item.plans);
      const incomplete = detail.discovery.diagnostics.length || detail.framework.diagnostics.length
        || !['completed', 'skipped'].includes(detail.analysis.status) || detail.hypotheses.diagnostics.length
        || detail.planning.some(item => item.diagnostics.length) || plans.some(plan => plan.readiness === 'BLOCKED')
        || detail.referenceRoutes.some(item => !item.extracted) || Object.values(detail.invariants).some(value => !value)
        || detail.project.mode === 'code-aware' && !detail.supports;
      results.cases.push({ ...entry, status: incomplete ? 'coverage-gap' : 'completed',
        discoveryMode: detail.project.mode, languages: detail.discovery.languages, frameworks: detail.discovery.frameworks,
        fallbackReasons: detail.discovery.fallbackReasons, discoveryDiagnosticCounts: counts(detail.discovery.diagnostics, item => item.code),
        adapterSupports: detail.supports, endpointCount: detail.framework.endpoints.length,
        frameworkDiagnosticCounts: counts(detail.framework.diagnostics, item => item.code),
        staticStatus: detail.analysis.status, staticDiagnosticCounts: counts(detail.analysis.diagnostics, item => item.code),
        toolVersion: detail.analysis.evidence[0]?.facts.toolVersion ?? null,
        staticSignalCount: detail.analysis.signals.length, mappedStaticSignalCount: detail.analysis.signals.filter(item => item.endpointId).length,
        hypothesisCount: detail.hypotheses.hypotheses.length, hypothesisDiagnosticCounts: counts(detail.hypotheses.diagnostics, item => item.code),
        planCount: plans.length, readyPlanCount: plans.filter(item => item.readiness === 'READY').length,
        planningDiagnosticCounts: counts(detail.planning.flatMap(item => item.diagnostics), item => item.code),
        prerequisites: counts(plans.flatMap(item => item.prerequisites), item => item.code),
        modelDiagnostics: detail.model.diagnostics, modelCalls: detail.hypotheses.usage.modelCalls,
        referenceRoutes: detail.referenceRoutes, invariants: detail.invariants, durationMs: detail.durationMs,
        artifact, artifactSha256: hash(content) });
      console.log(`${entry.id}: ${results.cases.at(-1).status}; ${detail.framework.endpoints.length} routes, ${detail.analysis.signals.length} static candidates`);
    }
    await writeFile(join(output, 'summary.json'), `${JSON.stringify(results, null, 2)}\n`, { mode: 0o600 });
  }
  process.exitCode = results.cases.some(item => item.status !== 'completed') ? 2 : 0;
}

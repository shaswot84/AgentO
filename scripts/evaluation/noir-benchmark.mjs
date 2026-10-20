import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { cpus, platform, arch } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { inventoryDigest, scoreParameters, scoreRoutes, systematicSample } from './endpoint-score.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const manifestPath = fileURLToPath(new URL('./realworld-cases.json', import.meta.url));
const referencesPath = fileURLToPath(new URL('./noir-references.json', import.meta.url));
const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
const references = JSON.parse(await readFile(referencesPath, 'utf8'));
const sha = value => createHash('sha256').update(value).digest('hex');
const args = process.argv.slice(2);
if (args.length !== 6 || args[0] !== '--repos' || args[2] !== '--noir' || args[4] !== '--output') {
  throw new Error('Usage: node scripts/evaluation/noir-benchmark.mjs --repos /pinned/checkouts --noir /path/to/noir --output /new/results');
}
const repositories = resolve(args[1]), executable = resolve(args[3]), output = resolve(args[5]);
const env = Object.fromEntries(['PATH', 'LANG', 'HOME', 'TMPDIR'].flatMap(key => process.env[key] ? [[key, process.env[key]]] : []));
await mkdir(output, { recursive: false, mode: 0o700 });
await mkdir(join(output, 'artifacts'));
await mkdir(join(output, 'private'));
env.XDG_CONFIG_HOME = join(output, 'private', 'config');
env.XDG_CACHE_HOME = join(output, 'private', 'cache');
const config = join(output, 'private', 'noir.yaml');
await writeFile(config, '{}\n', { mode: 0o600 });

async function command(executable, args, options = {}) {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const process = spawn(executable, args, { cwd: output, env, shell: false, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [], stderr = [];
    let bytes = 0, failure;
    const kill = () => { try { if (process.pid) globalThis.process.kill(-process.pid, 'SIGKILL'); } catch {} };
    const timer = setTimeout(() => { failure = 'timeout'; kill(); }, options.timeoutMs ?? 180_000);
    for (const [stream, chunks] of [[process.stdout, stdout], [process.stderr, stderr]]) {
      stream.on('data', chunk => { bytes += chunk.length; if (bytes > 32 * 1024 * 1024) { failure = 'output-limit'; kill(); } else chunks.push(chunk); });
    }
    process.on('error', error => { clearTimeout(timer); reject(error); });
    process.on('close', (exitCode, signal) => {
      clearTimeout(timer);
      resolve({ exitCode, signal, failure: failure ?? null, wallMs: performance.now() - started,
        stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') });
    });
  });
}
async function git(path, ...args) {
  const result = await command('git', ['-C', path, ...args], { timeoutMs: 15_000 });
  if (result.exitCode !== 0) throw new Error('git-check-failed');
  return result.stdout.trim();
}
async function artifact(name, value) {
  const text = JSON.stringify(value, null, 2) + '\n';
  const compressed = gzipSync(text);
  const path = `artifacts/${name}.json.gz`;
  await writeFile(join(output, path), compressed, { flag: 'wx', mode: 0o600 });
  return { path, uncompressedSha256: sha(text), compressedSha256: sha(compressed) };
}
function sourcePath(path, sourceRoot) {
  return isAbsolute(path) ? relative(sourceRoot, path).replaceAll('\\', '/') : path.replaceAll('\\', '/');
}
function normalize(raw, arm, sourceRoot) {
  const endpoints = (arm === 'agento' ? raw.endpoints : raw.endpoints ?? []).map(endpoint => arm === 'agento' ? {
    method: endpoint.method, path: endpoint.path,
    parameters: endpoint.parameters.map(item => ({ name: item.name, location: item.location })),
    sources: raw.evidence.filter(item => endpoint.evidenceIds.includes(item.id) && item.facts.observation === 'route' && item.source)
      .map(item => ({ file: sourcePath(item.source.file, sourceRoot), line: item.source.startLine })),
    handler: endpoint.handler ?? null,
  } : {
    method: endpoint.method, path: endpoint.url,
    parameters: (endpoint.params ?? []).map(item => ({ name: item.name, location: item.param_type })),
    sources: (endpoint.details?.code_paths ?? []).map(item => ({ file: sourcePath(item.path, sourceRoot), line: item.line ?? null })),
    handler: null,
  });
  if (endpoints.some(item => typeof item.path !== 'string' || typeof item.method !== 'string')) throw new Error('invalid-endpoint-output');
  return endpoints;
}
async function checkSources(endpoints, sourceRoot) {
  let validEndpoints = 0, validLocations = 0, invalidLocations = 0;
  const lines = new Map();
  for (const endpoint of endpoints) {
    let valid = false;
    for (const source of endpoint.sources) {
      if (source.file === '..' || source.file.startsWith('../') || isAbsolute(source.file)) { invalidLocations++; continue; }
      if (!lines.has(source.file)) {
        try { lines.set(source.file, (await readFile(join(sourceRoot, source.file), 'utf8')).split('\n').length); }
        catch { lines.set(source.file, 0); }
      }
      if (Number.isInteger(source.line) && source.line > 0 && source.line <= lines.get(source.file)) { valid = true; validLocations++; }
      else invalidLocations++;
    }
    if (valid) validEndpoints++;
  }
  return { endpointsWithValidLocation: validEndpoints, validLocations, invalidLocations,
    note: 'Existing file and line bounds only; semantic source accuracy needs manual review.' };
}

const version = await command(executable, ['--version']);
if (version.exitCode !== 0 || version.stdout.trim() !== '1.4.0') throw new Error('expected-noir-1.4.0');
const binarySha256 = sha(await readFile(executable));
if (binarySha256 !== '620e774f240be91b975ca0b2f04a5df568f0612ef1f74d182a43a25daf402001') throw new Error('official-binary-digest-mismatch');
const compiled = join(root, 'plugins/frameworks/express/dist');
const builtFiles = (await readdir(compiled)).filter(name => name.endsWith('.js')).sort();
const builtHashes = {};
for (const name of builtFiles) builtHashes[name] = sha(await readFile(join(compiled, name)));
const results = { schemaVersion: 1, generatedAt: new Date().toISOString(), scope: 'static-endpoint-inventory-comparison',
  runtimeRequests: 0, modelCalls: 0, repetitions: 3, concurrency: 1,
  platform: { os: platform(), architecture: arch(), nodeVersion: process.version, cpu: cpus()[0]?.model },
  noir: { version: '1.4.0', release: 'https://github.com/owasp-noir/noir/releases/tag/v1.4.0', binarySha256 },
  agentORevision: await git(root, 'rev-parse', 'HEAD'), agentOBuiltExtractorHashes: builtHashes,
  runnerSha256: sha(await readFile(fileURLToPath(import.meta.url))), scoringSha256: sha(await readFile(new URL('./endpoint-score.mjs', import.meta.url))),
  caseManifestSha256: sha(await readFile(manifestPath)), referenceManifestSha256: sha(await readFile(referencesPath)),
  measurement: 'GNU time peak RSS and subprocess wall time; extractor only, no Semgrep/discovery/planner; warm filesystem caches; arm order rotates.',
  matching: 'Exact method and path after placeholder spelling normalization; mount prefixes, names and trailing slashes remain significant.',
  cases: [] };
const auditSelection = [];
for (const [caseIndex, entry] of manifest.cases.entries()) {
  const checkout = join(repositories, entry.id), sourceRoot = join(checkout, entry.sourceRoot);
  if (await git(checkout, 'rev-parse', 'HEAD') !== entry.revision) throw new Error('revision-mismatch:' + entry.id);
  if (await git(checkout, 'status', '--porcelain', '--untracked-files=all')) throw new Error('checkout-not-clean:' + entry.id);
  const routeReferences = entry.id === 'flask' ? references.flaskRoutes : entry.routes;
  const parameterReferences = references.parameterReferences.filter(item => item.project === entry.id);
  for (const reference of [...routeReferences, ...parameterReferences]) {
    if (!(await readFile(join(sourceRoot, reference.file), 'utf8')).includes(reference.contains)) throw new Error('source-reference-mismatch:' + entry.id);
  }
  const row = { id: entry.id, repository: entry.repository, revision: entry.revision, sourceRoot: entry.sourceRoot, arms: {} };
  for (let repeat = 0; repeat < 3; repeat++) {
    const all = ['agento', 'noir-default', 'noir-framework'];
    const offset = (caseIndex + repeat) % all.length;
    const arms = [...all.slice(offset), ...all.slice(0, offset)];
    for (const arm of arms) {
      const stamp = `${entry.id}-${arm}-${repeat + 1}`;
      const metricsPath = join(output, 'private', `${stamp}.time.json`);
      const toolArgs = arm === 'agento' ? [process.execPath, fileURLToPath(new URL('./endpoint-worker.mjs', import.meta.url)), sourceRoot, entry.id]
        : [executable, 'scan', sourceRoot, '-f', 'json', '--no-log', '--no-color', '--no-spinner', '--strict', '--concurrency', '1',
          '--config-file', config, ...(arm === 'noir-framework' ? ['--only-techs', entry.id === 'flask' ? 'python_flask' : 'js_express'] : [])];
      const execution = await command('/usr/bin/time', ['-o', metricsPath, '-f', '{"peakRssKiB":%M,"elapsedSeconds":%e,"userSeconds":%U,"systemSeconds":%S,"exitCode":%x}', ...toolArgs]);
      await writeFile(join(output, 'private', `${stamp}.stderr`), execution.stderr, { mode: 0o600 });
      let metrics;
      try { metrics = JSON.parse((await readFile(metricsPath, 'utf8')).trim().split('\n').at(-1)); } catch { metrics = null; }
      let raw;
      try { raw = JSON.parse(execution.stdout); } catch { raw = null; }
      const success = !execution.failure && raw && Array.isArray(raw.endpoints) && [0, 2].includes(execution.exitCode);
      const run = { repeat: repeat + 1, exitCode: execution.exitCode, failure: execution.failure, wallMs: Math.round(execution.wallMs), metrics };
      row.arms[arm] ??= { runs: [] };
      row.arms[arm].runs.push(run);
      if (!success) { run.failure ??= 'no-valid-json-output'; console.log(`${stamp}: failed`); continue; }
      const endpoints = normalize(raw, arm, sourceRoot);
      run.inventoryDigest = inventoryDigest(endpoints);
      run.endpointCount = endpoints.length;
      run.diagnosticCount = arm === 'agento' ? raw.diagnostics.length : Array.isArray(raw.errors) ? raw.errors.length : Object.keys(raw.errors ?? {}).length;
      if (repeat === 0) {
        const record = row.arms[arm];
        record.rawArtifact = await artifact(`${entry.id}-${arm}-raw`, raw);
        record.inventoryArtifact = await artifact(`${entry.id}-${arm}-inventory`, endpoints);
        record.endpointCount = endpoints.length;
        record.uniqueMethodPathCount = new Set(endpoints.map(item => `${item.method} ${item.path}`)).size;
        record.diagnosticCount = run.diagnosticCount;
        record.routeReferences = scoreRoutes(endpoints, routeReferences);
        record.parameterReferences = scoreParameters(endpoints, parameterReferences);
        record.sourceLocations = await checkSources(endpoints, sourceRoot);
        record.technologies = arm === 'agento' ? ['express'] : [...new Set(raw.endpoints.map(item => item.details?.technology ?? 'unspecified'))].sort();
        if (arm === 'noir-framework') auditSelection.push({ project: entry.id, endpoints: systematicSample(endpoints) });
      }
      console.log(`${stamp}: ${endpoints.length} endpoints, ${run.wallMs} ms, ${metrics?.peakRssKiB ?? '?'} KiB`);
    }
  }
  row.sourceUnchanged = await git(checkout, 'status', '--porcelain', '--untracked-files=all') === '';
  for (const arm of Object.values(row.arms)) {
    arm.runs.sort((a, b) => a.repeat - b.repeat);
    const durations = arm.runs.map(run => run.wallMs).sort((a, b) => a - b);
    arm.medianWallMs = durations[1];
    arm.repeatableInventory = arm.runs.length === 3 && arm.runs.every(run => !run.failure && run.inventoryDigest === arm.runs[0].inventoryDigest);
  }
  results.cases.push(row);
  await writeFile(join(output, 'results.json'), JSON.stringify(results, null, 2) + '\n', { mode: 0o600 });
  await writeFile(join(output, 'audit-selection.json'), JSON.stringify(auditSelection, null, 2) + '\n', { mode: 0o600 });
}
if (results.cases.some(row => !row.sourceUnchanged || Object.values(row.arms).some(arm => arm.runs.some(run => run.failure)))) process.exitCode = 1;

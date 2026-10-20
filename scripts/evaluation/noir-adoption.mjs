import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { ExpressFrameworkAdapter } from '../../plugins/frameworks/express/dist/index.js';
import { isEndpointTestable } from '../../packages/core/dist/index.js';
import { buildApplicationSecurityModel, fromFrameworkAnalysis } from '../../packages/security-model/dist/index.js';
import { scoreRoutes, scoreParameters } from './endpoint-score.mjs';

const args = process.argv.slice(2);
if (args.length !== 4 || args[0] !== '--repos-dir' || args[2] !== '--output') {
  throw new Error('Usage: node scripts/evaluation/noir-adoption.mjs --repos-dir /pinned/clones --output /new/results');
}
const repos = resolve(args[1]), output = resolve(args[3]), run = promisify(execFile);
const corpus = JSON.parse(await readFile(new URL('./realworld-cases.json', import.meta.url)));
const references = JSON.parse(await readFile(new URL('./noir-references.json', import.meta.url)));
const adapter = new ExpressFrameworkAdapter();
await mkdir(output, { recursive: false });
await mkdir(join(output, 'artifacts'));
const results = { schemaVersion: 1, description: 'Production default integration checks; no target dependencies, target execution, model calls or target requests.',
  capturedAt: new Date().toISOString(), providerId: 'noir-endpoint-discovery', completeCoverage: false, projects: [] };
results.sourceHashes = {};
for (const path of ['plugins/frameworks/express/src/noir.ts', 'plugins/frameworks/express/src/adapter.ts',
  'plugins/frameworks/express/src/source-analyzer.ts', 'plugins/frameworks/express/src/repository.ts',
  'plugins/frameworks/express/src/routes.ts', 'packages/core/src/domain.ts', 'packages/core/src/contracts.ts',
  'packages/core/src/orchestrator.ts', 'packages/security-model/src/endpoints.ts', 'packages/test-planner/src/planner.ts',
  'plugins/cwe/src/candidates.ts', 'scripts/evaluation/noir-adoption.mjs']) {
  results.sourceHashes[path] = createHash('sha256').update(await readFile(new URL(`../../${path}`, import.meta.url))).digest('hex');
}
for (const entry of corpus.cases) {
  const checkout = join(repos, entry.id);
  const git = async (...command) => (await run('git', ['-C', checkout, ...command])).stdout.trim();
  if (await git('rev-parse', 'HEAD') !== entry.revision || await git('status', '--porcelain')) throw new Error(`Source revision mismatch: ${entry.id}`);
  const project = { id: entry.id, name: entry.id, mode: 'code-aware', repositoryPath: join(checkout, entry.sourceRoot),
    baseUrl: 'http://127.0.0.1:1', allowedOrigins: ['http://127.0.0.1:1'], languages: entry.id === 'flask' ? ['python'] : ['javascript', 'typescript'] };
  const supported = await adapter.supports(project);
  if (!supported) {
    if (entry.id !== 'flask') throw new Error(`Express source not recognized: ${entry.id}`);
    results.projects.push({ id: entry.id, revision: entry.revision, supported: false, status: 'unsupported-stack', endpointCount: 0 });
    continue;
  }
  const analysis = await adapter.extract(project);
  if (!['completed', 'partial'].includes(analysis.discovery?.status)) throw new Error(`Discovery failed: ${entry.id}`);
  const model = buildApplicationSecurityModel({ project, contributions: [fromFrameworkAnalysis(analysis)] });
  const serialized = JSON.parse(JSON.stringify(model));
  for (const endpoint of analysis.endpoints) {
    const canonical = serialized.endpoints.find(item => item.aliases.includes(endpoint.id));
    if (!canonical || !isEndpointTestable(endpoint) && isEndpointTestable(canonical)) throw new Error('Inventory execution guard was lost');
  }
  const verified = analysis.endpoints.filter(isEndpointTestable);
  const bytes = JSON.stringify(analysis, null, 2) + '\n';
  const artifact = `artifacts/${entry.id}.json.gz`;
  const compressed = gzipSync(bytes, { level: 9 });
  await writeFile(join(output, artifact), compressed);
  const row = { id: entry.id, revision: entry.revision, supported, discovery: analysis.discovery,
    endpointCount: analysis.endpoints.length, sourceCorroboratedCount: verified.length,
    candidateCount: analysis.endpoints.length - verified.length, modelEndpointCount: model.endpoints.length,
    referenceRoutes: scoreRoutes(analysis.endpoints, entry.routes), testableReferences: scoreRoutes(verified, entry.routes),
    referenceInputs: scoreParameters(analysis.endpoints, references.parameterReferences.filter(item => item.project === entry.id)),
    diagnostics: [...new Set(analysis.diagnostics.map(item => item.code))], artifact,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    compressedSha256: createHash('sha256').update(compressed).digest('hex') };
  results.projects.push(row);
  console.log(JSON.stringify({ id: row.id, status: row.discovery.status, inventory: row.endpointCount,
    corroborated: row.sourceCorroboratedCount, candidates: row.candidateCount,
    routeReferences: row.referenceRoutes.filter(item => item.matched).length,
    testableReferences: row.testableReferences.filter(item => item.matched).length }));
}
await writeFile(join(output, 'results.json'), JSON.stringify(results, null, 2) + '\n');

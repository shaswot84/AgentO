import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { inventoryDigest, scoreParameters, scoreRoutes } from './endpoint-score.mjs';
const hash = value => createHash('sha256').update(value).digest('hex');

export async function verifyComparison(directory) {
  const results = JSON.parse(await readFile(join(directory, 'results.json'), 'utf8'));
  const casesPath = new URL('./realworld-cases.json', import.meta.url), referencesPath = new URL('./noir-references.json', import.meta.url);
  const cases = JSON.parse(await readFile(casesPath, 'utf8')).cases;
  const references = JSON.parse(await readFile(referencesPath, 'utf8'));
  assert.equal(results.caseManifestSha256, hash(await readFile(casesPath)));
  assert.equal(results.referenceManifestSha256, hash(await readFile(referencesPath)));
  assert.equal(results.scoringSha256, hash(await readFile(new URL('./endpoint-score.mjs', import.meta.url))));
  assert.equal(results.runnerSha256, hash(await readFile(new URL('./noir-benchmark.mjs', import.meta.url))));
  assert.equal(results.noir.binarySha256, '620e774f240be91b975ca0b2f04a5df568f0612ef1f74d182a43a25daf402001');
  assert.equal(results.cases.length, cases.length);
  assert.equal(new Set(results.cases.map(row => row.id)).size, cases.length);
  assert.equal(results.modelCalls, 0); assert.equal(results.runtimeRequests, 0);
  async function artifact(record) {
    assert(!isAbsolute(record.path) && !record.path.split('/').includes('..'));
    const compressed = await readFile(join(directory, record.path));
    assert.equal(hash(compressed), record.compressedSha256);
    const text = gunzipSync(compressed);
    assert.equal(hash(text), record.uncompressedSha256);
    return JSON.parse(text);
  }
  for (const entry of cases) {
    const row = results.cases.find(item => item.id === entry.id);
    assert(row); assert.equal(row.revision, entry.revision); assert.equal(row.sourceUnchanged, true);
    assert.deepEqual(Object.keys(row.arms).sort(), ['agento', 'noir-default', 'noir-framework']);
    for (const arm of Object.values(row.arms)) {
      const raw = await artifact(arm.rawArtifact), inventory = await artifact(arm.inventoryArtifact);
      assert(Array.isArray(raw.endpoints)); assert.equal(inventory.length, arm.endpointCount); assert.equal(raw.endpoints.length, arm.endpointCount);
      assert.equal(arm.uniqueMethodPathCount, new Set(inventory.map(item => `${item.method} ${item.path}`)).size);
      assert.deepEqual(arm.routeReferences, scoreRoutes(inventory, entry.id === 'flask' ? references.flaskRoutes : entry.routes));
      assert.deepEqual(arm.parameterReferences, scoreParameters(inventory, references.parameterReferences.filter(item => item.project === entry.id)));
      assert.deepEqual(arm.runs.map(run => run.repeat), [1, 2, 3]);
      for (const run of arm.runs) {
        assert.equal(run.failure, null); assert([0, 2].includes(run.exitCode));
        assert.equal(run.endpointCount, inventory.length); assert.equal(run.inventoryDigest, inventoryDigest(inventory));
        assert(Number.isFinite(run.wallMs) && run.wallMs >= 0);
        assert(Number.isFinite(run.metrics.peakRssKiB) && run.metrics.peakRssKiB > 0);
      }
      assert.equal(arm.repeatableInventory, true);
      assert.equal(arm.medianWallMs, arm.runs.map(run => run.wallMs).sort((a, b) => a - b)[1]);
    }
  }
  return { projects: results.cases.length, timedRuns: results.cases.length * 9 };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await verifyComparison(resolve(process.argv[2] ?? 'docs/evaluation/noir'));
  console.log(`Verified ${result.projects} projects, ${result.timedRuns} timed runs, artifact digests and reference scores.`);
}

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyEvidenceBundle } from '../../packages/evidence/dist/index.js';
import { fromCoreEvidence } from '../../plugins/cwe/dist/index.js';
import { score, summarize } from './metrics.mjs';

const manifest = JSON.parse(readFileSync(new URL('./cases.json', import.meta.url), 'utf8'));

/** Check the full run matrix, labels, retained proof and recomputed metrics offline. */
export function verifyResults(result) {
  assert.equal(result.schemaVersion, 1);
  assert.deepEqual(result.manifest, manifest);
  assert(Number.isInteger(result.repeats) && result.repeats >= 1 && result.repeats <= 5);
  const expectedRuns = [];
  for (let repeat = 1; repeat <= result.repeats; repeat++) for (const mode of ['vulnerable', 'fixed']) {
    for (const [arm, slices] of [['agento', ['a01', 'a02', 'a05']], ['semgrep', ['a05']], ['scanners', manifest.baselineCaseIds]])
      for (const slice of slices) expectedRuns.push(`${arm}-${mode}-${repeat}-${slice}`);
  }
  assert.deepEqual(result.runs.map(run => run.id).sort(), expectedRuns.sort());
  for (const run of result.runs) {
    assert.equal(run.id, `${run.arm}-${run.mode}-${run.repeat}-${run.slice}`);
    const cases = manifest.cases.filter(item => run.arm === 'agento' ? item.slice === run.slice
      : run.arm === 'semgrep' ? manifest.baselineCaseIds.includes(item.id) : item.id === run.slice);
    assert.deepEqual(run.observations.map(item => item.id).sort(), cases.map(item => item.id).sort());
    for (const name of ['durationMs', 'httpRequests', 'testsExecuted', 'testsCompleted'])
      assert(Number.isSafeInteger(run[name]) && run[name] >= 0, name);
    assert(run.testsCompleted <= run.testsExecuted);
    for (const observation of run.observations) {
      const labelled = cases.find(item => item.id === observation.id);
      assert.equal(observation.cweId, labelled.cweId); assert.equal(observation.path, labelled.path);
      if (!observation.proof) { assert.equal(observation.prediction, 'unknown'); continue; }
      const proof = verifyEvidenceBundle(observation.proof);
      assert.equal(proof.finding.cweId, labelled.cweId);
      for (const id of [...observation.sourceEvidenceIds, ...observation.runtimeEvidenceIds])
        assert(proof.evidence.some(record => record.id === id), 'missing-cited-proof');
      if (run.arm === 'agento') {
        assert.equal(observation.status, proof.finding.status);
        assert.equal(observation.prediction, observation.status === 'CONFIRMED' ? 'positive'
          : observation.status === 'NOT_REPRODUCED' ? 'negative' : 'unknown');
        if (observation.prediction !== 'unknown') {
          assert(observation.sourceEvidenceIds.length > 0);
          assert(observation.runtimeEvidenceIds.length > 0);
          for (const id of observation.runtimeEvidenceIds) {
            const record = proof.evidence.find(record => record.id === id), runtime = fromCoreEvidence(record);
            assert(runtime && runtime.outcome === 'COMPLETED', 'missing-complete-runtime-proof');
            const segments = new URL(record.provenance.environment.targetUrl).pathname.split('/');
            const expected = labelled.path.split('/');
            assert.equal(segments.length, expected.length);
            assert(expected.every((segment, index) => segment.startsWith(':') ? !!segments[index] : segment === segments[index]), 'wrong-proof-target');
            const probe = { a01: 'authorization', a02: labelled.cweId === 'CWE-942' ? 'cross-origin' : 'cookie-security',
              a05: labelled.cweId === 'CWE-79' ? 'xss' : 'sql-injection' }[run.slice];
            assert.equal(runtime.probeId, probe);
          }
        }
        assert.equal(observation.dynamicallyVerified, observation.prediction === 'positive');
      } else {
        assert.equal(observation.dynamicallyVerified, false);
        assert.notEqual(proof.finding.status, 'CONFIRMED');
        if (observation.prediction !== 'unknown') {
          const staticRun = proof.evidence.find(record => record.facts.observation === 'static-analysis-run');
          const scannerRun = proof.evidence.find(record => record.facts.observation === 'scanner-run');
          assert(run.arm === 'semgrep' ? staticRun?.facts.status === 'completed' : !!scannerRun);
          const hasCandidate = run.arm === 'semgrep' ? observation.sourceEvidenceIds.length > 0
            : proof.evidence.some(record => record.facts.observation === 'scanner-candidate' && record.facts.cweIds.includes(labelled.cweId));
          assert.equal(observation.prediction, hasCandidate ? 'positive' : 'negative');
        }
      }
    }
    assert.deepEqual(run.metrics, score(cases.map(item => ({ id: item.id, vulnerable: run.mode === 'vulnerable' })), run.observations));
  }
  assert.deepEqual(result.summary, summarize(result.runs, manifest));
  assert.deepEqual(result.modelUsage, { mode: 'deterministic-recipes-no-model-provider', calls: 0, inputTokens: 0, outputTokens: 0, costUsd: 0 });
  return result;
}

export function verifySources(result) {
  const root = fileURLToPath(new URL('../../', import.meta.url));
  assert(Object.keys(result.sourceHashes).length > 0);
  for (const [path, expected] of Object.entries(result.sourceHashes)) {
    const absolute = resolve(root, path);
    assert(absolute.startsWith(root.endsWith(sep) ? root : root + sep));
    assert.equal(createHash('sha256').update(readFileSync(absolute)).digest('hex'), expected, `source-changed:${path}`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 && !(process.argv.length === 4 && process.argv[3] === '--check-sources'))
    throw new Error('Usage: node scripts/evaluation/verify.mjs /path/to/results.json [--check-sources]');
  const result = verifyResults(JSON.parse(readFileSync(resolve(process.argv[2]), 'utf8')));
  if (process.argv[3]) verifySources(result);
  console.log(`Verified ${result.runs.length} measurements, their evidence digests, labels, and metrics.`);
}

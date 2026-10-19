import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyResults, verifySources } from './verify.mjs';

const result = JSON.parse(readFileSync(new URL('../../docs/evaluation/results.json', import.meta.url), 'utf8'));

test('replays the recorded run matrix, source hashes, proof digests and metrics offline', () => {
  verifyResults(result); verifySources(result);
});

test('rejects lost or duplicated runs and changed ground-truth labels', () => {
  for (const mutate of [
    value => value.runs.pop(), value => value.runs.push(value.runs[0]),
    value => { value.manifest.labels.fixed = true; },
    value => { value.runs[0].mode = 'fixed'; },
  ]) {
    const changed = structuredClone(result); mutate(changed);
    assert.throws(() => verifyResults(changed));
  }
});

test('rejects rewritten metrics, predictions and evidence', () => {
  for (const mutate of [
    value => { value.summary.agento.metrics.tp++; },
    value => { value.runs[0].observations[0].prediction = 'negative'; },
    value => { value.runs[0].observations[0].proof.evidence[0].summary = 'changed'; },
    value => { value.runs[0].observations[0].proof = null; },
    value => { value.runs[0].httpRequests = -1; },
    value => { value.modelUsage.calls = 1; },
  ]) {
    const changed = structuredClone(result); mutate(changed);
    assert.throws(() => verifyResults(changed));
  }
});

test('requires complete runtime proof for each AgentO positive and negative verdict', () => {
  for (const mutate of [
    observation => { observation.runtimeEvidenceIds = []; },
    observation => { observation.runtimeEvidenceIds = observation.sourceEvidenceIds; },
    observation => { observation.dynamicallyVerified = false; },
  ]) {
    const changed = structuredClone(result);
    const observation = changed.runs.find(run => run.arm === 'agento' && run.mode === 'vulnerable').observations[0];
    mutate(observation); assert.throws(() => verifyResults(changed));
  }
});

test('rejects changed source hashes and paths outside the repository', () => {
  const changed = structuredClone(result);
  changed.sourceHashes['scripts/evaluation/run.mjs'] = '0'.repeat(64);
  assert.throws(() => verifySources(changed));
  changed.sourceHashes = { '../outside': '0'.repeat(64) };
  assert.throws(() => verifySources(changed));
});

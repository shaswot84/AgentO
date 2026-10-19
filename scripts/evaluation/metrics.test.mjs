import { test } from 'node:test';
import assert from 'node:assert/strict';
import { aggregate, score } from './metrics.mjs';

test('scores paired labels and deduplicates to a case, with explicit positive proof rate', () => {
  const result = score([
    { id: 'tp', vulnerable: true }, { id: 'fp', vulnerable: false },
    { id: 'tn', vulnerable: false }, { id: 'fn', vulnerable: true },
  ], [
    { id: 'tp', prediction: 'positive', dynamicallyVerified: true }, { id: 'fp', prediction: 'positive' },
    { id: 'tn', prediction: 'negative' }, { id: 'fn', prediction: 'negative' },
  ]);
  assert.deepEqual(result, { cases: 4, tp: 1, fp: 1, tn: 1, fn: 1, inconclusive: 0,
    precision: 0.5, recall: 0.5, coverage: 1, dynamicallyVerified: 1, dynamicVerificationRate: 0.5 });
});

test('counts missing vulnerable results as misses and missing secure results as inconclusive', () => {
  assert.deepEqual(score([{ id: 'v', vulnerable: true }, { id: 's', vulnerable: false }], []), {
    cases: 2, tp: 0, fp: 0, tn: 0, fn: 1, inconclusive: 2, precision: null, recall: 0,
    coverage: 0, dynamicallyVerified: 0, dynamicVerificationRate: null,
  });
  assert.equal(score([], []).recall, null);
});

test('rejects duplicate, unlabelled, invalid, or falsely verified observations', () => {
  const expected = [{ id: 'x', vulnerable: true }], item = { id: 'x', prediction: 'positive' };
  assert.throws(() => score(expected, [item, item]));
  assert.throws(() => score(expected, [{ ...item, id: 'other' }]));
  assert.throws(() => score(expected, [{ ...item, prediction: 'safe' }]));
  assert.throws(() => score(expected, [{ id: 'x', prediction: 'negative', dynamicallyVerified: true }]));
  assert.throws(() => score([...expected, ...expected], []));
});

test('compares the same subset without including unsupported CWEs or pooling duplicate repetitions', () => {
  const runs = ['vulnerable', 'fixed'].map(mode => ({ id: mode, mode, observations: [
    { id: 'injection', prediction: mode === 'vulnerable' ? 'positive' : 'negative', dynamicallyVerified: mode === 'vulnerable' },
    { id: 'cookie', prediction: 'unknown' },
  ] }));
  assert.deepEqual(aggregate(runs, ['injection']), { cases: 2, tp: 1, fp: 0, tn: 1, fn: 0,
    inconclusive: 0, precision: 1, recall: 1, coverage: 1, dynamicallyVerified: 1, dynamicVerificationRate: 1 });
});

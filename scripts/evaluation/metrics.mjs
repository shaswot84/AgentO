/** Case-level scoring. Missing execution never counts as a secure observation. */
export function score(expected, observations) {
  const labels = new Map(expected.map(item => [item.id, item.vulnerable]));
  if (labels.size !== expected.length || expected.some(item => typeof item.vulnerable !== 'boolean')) throw new Error('invalid-labels');
  const byId = new Map();
  for (const observation of observations) {
    if (!labels.has(observation.id) || byId.has(observation.id)
      || !['positive', 'negative', 'unknown'].includes(observation.prediction)
      || observation.dynamicallyVerified && observation.prediction !== 'positive') throw new Error('invalid-observations');
    byId.set(observation.id, observation);
  }
  let tp = 0, fp = 0, tn = 0, fn = 0, inconclusive = 0, dynamicallyVerified = 0;
  for (const [id, vulnerable] of labels) {
    const item = byId.get(id), prediction = item?.prediction ?? 'unknown';
    if (prediction === 'unknown') inconclusive++;
    if (prediction === 'positive') {
      if (vulnerable) tp++; else fp++;
      if (item.dynamicallyVerified) dynamicallyVerified++;
    } else if (vulnerable) fn++;
    else if (prediction === 'negative') tn++;
  }
  return { cases: labels.size, tp, fp, tn, fn, inconclusive,
    precision: ratio(tp, tp + fp), recall: ratio(tp, tp + fn),
    coverage: ratio(labels.size - inconclusive, labels.size), dynamicallyVerified,
    dynamicVerificationRate: ratio(dynamicallyVerified, tp + fp) };
}

export function ratio(numerator, denominator) { return denominator === 0 ? null : numerator / denominator; }

export function aggregate(runs, caseIds) {
  const selected = new Set(caseIds), expected = [], observations = [];
  for (const run of runs) {
    for (const item of run.observations.filter(item => selected.has(item.id))) {
      const id = `${run.id}:${item.id}`;
      expected.push({ id, vulnerable: run.mode === 'vulnerable' });
      observations.push({ ...item, id });
    }
  }
  return score(expected, observations);
}

export function summarize(runs, manifest) {
  return Object.fromEntries(['agento', 'semgrep', 'scanners'].map(arm => {
    const selected = runs.filter(run => run.arm === arm);
    const injectionRuns = selected.filter(run => run.arm !== 'agento' || run.slice === 'a05');
    const effort = group => ({ durationMs: group.reduce((sum, run) => sum + run.durationMs, 0),
      httpRequests: group.reduce((sum, run) => sum + run.httpRequests, 0),
      testsExecuted: group.reduce((sum, run) => sum + run.testsExecuted, 0),
      testsCompleted: group.reduce((sum, run) => sum + run.testsCompleted, 0) });
    return [arm, { metrics: aggregate(selected, arm === 'agento' ? manifest.cases.map(item => item.id) : manifest.baselineCaseIds),
      injectionMetrics: aggregate(selected, manifest.baselineCaseIds), ...effort(selected), injectionEffort: effort(injectionRuns) }];
  }));
}

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { verifyResults } from './verify.mjs';

if (process.argv.length !== 4) throw new Error('Usage: node scripts/evaluation/render.mjs results.json new-summary.md');
const result = verifyResults(JSON.parse(readFileSync(resolve(process.argv[2]), 'utf8')));
const percent = value => value === null ? 'N/A' : `${(value * 100).toFixed(0)}%`;
const names = { agento: 'AgentO', semgrep: 'Semgrep candidates', scanners: 'Dalfox/sqlmap candidates' };
const accuracy = metrics => [metrics.cases, metrics.tp, metrics.fp, metrics.tn, metrics.fn,
  metrics.inconclusive, percent(metrics.precision), percent(metrics.recall)].join(' | ');
const lines = [
  '# Recorded evaluation', '',
  `Captured at ${result.generatedAt}. ${result.repeats} repetitions of each mode.`, '',
  'This file is generated from [results.json](results.json). See [the evaluation method](../evaluation.md) for scope and limits.', '',
  '## All seven AgentO cases', '',
  '| Arm | Case observations | TP | FP | TN | FN | Inconclusive | Precision | Recall |',
  '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
  `| AgentO | ${accuracy(result.summary.agento.metrics)} |`, '',
  '## Matched injection comparison', '',
  'Each arm assesses CWE-79 at `/search` and CWE-89 at `/api/search` in both modes. Baseline positives are tool candidates; AgentO positives are confirmed findings.', '',
  '| Arm | Case observations | TP | FP | TN | FN | Inconclusive | Precision | Recall |',
  '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
  ...Object.entries(result.summary).map(([arm, value]) => `| ${names[arm]} | ${accuracy(value.injectionMetrics)} |`), '',
  '## Measured effort', '',
  'Totals include all repetitions. Jobs/probes exclude the reused cookie collection. Request counts include target-side browser assets and authentication.', '',
  '| Arm and scope | Duration (s) | HTTP requests | Jobs/probes executed | Completed | Independently verified positives |',
  '| --- | ---: | ---: | ---: | ---: | ---: |',
  ...[['agento', false], ['agento', true], ['semgrep', true], ['scanners', true]].map(([arm, injection]) => {
    const summary = result.summary[arm], effort = injection ? summary.injectionEffort : summary;
    const metrics = injection ? summary.injectionMetrics : summary.metrics;
    return `| ${names[arm]} (${injection ? 'injection' : 'all seven'}) | ${(effort.durationMs / 1000).toFixed(3)} | ${effort.httpRequests} | ${effort.testsExecuted} | ${effort.testsCompleted} | ${percent(metrics.dynamicVerificationRate)} |`;
  }), '',
  'Model calls: 0. Input tokens: 0. Output tokens: 0. Model cost: USD 0. These runs configure no model provider.', '',
  '## Per-run observations', '',
  '| Repetition | Mode | Arm/slice | TP | FP | TN | FN | Inconclusive | Requests | Duration (ms) |',
  '| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
  ...result.runs.map(run => `| ${run.repeat} | ${run.mode} | ${run.arm}/${run.slice} | ${run.metrics.tp} | ${run.metrics.fp} | ${run.metrics.tn} | ${run.metrics.fn} | ${run.metrics.inconclusive} | ${run.httpRequests} | ${run.durationMs} |`), '',
  '## Runtime versions', '',
  `Node ${result.environment.node}; ${result.environment.platform}/${result.environment.arch}; Playwright ${result.environment.playwright}.`, '',
  ...Object.entries(result.environment.tools).map(([name, version]) => `- ${name}: ${version}`), '',
  'The JSON records the base Git revision and source SHA-256 values, including local changes. An external real-world Express project was not tested.', '',
];
writeFileSync(resolve(process.argv[3]), lines.join('\n'), { flag: 'wx' });

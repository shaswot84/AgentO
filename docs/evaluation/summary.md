# Recorded evaluation

Captured at 2026-10-19T14:33:30.786Z. 2 repetitions of each mode.

This file is generated from [results.json](results.json). See [the evaluation method](../evaluation.md) for scope and limits.

## All seven AgentO cases

| Arm | Case observations | TP | FP | TN | FN | Inconclusive | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| AgentO | 28 | 14 | 0 | 14 | 0 | 0 | 100% | 100% |

## Matched injection comparison

Each arm assesses CWE-79 at `/search` and CWE-89 at `/api/search` in both modes. Baseline positives are tool candidates; AgentO positives are confirmed findings.

| Arm | Case observations | TP | FP | TN | FN | Inconclusive | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| AgentO | 8 | 4 | 0 | 4 | 0 | 0 | 100% | 100% |
| Semgrep candidates | 8 | 4 | 4 | 0 | 0 | 0 | 50% | 100% |
| Dalfox/sqlmap candidates | 8 | 2 | 0 | 4 | 2 | 0 | 100% | 50% |

## Measured effort

Totals include all repetitions. Jobs/probes exclude the reused cookie collection. Request counts include target-side browser assets and authentication.

| Arm and scope | Duration (s) | HTTP requests | Jobs/probes executed | Completed | Independently verified positives |
| --- | ---: | ---: | ---: | ---: | ---: |
| AgentO (all seven) | 27.045 | 431 | 24 | 24 | 100% |
| AgentO (injection) | 16.974 | 218 | 8 | 8 | 100% |
| Semgrep candidates (injection) | 8.495 | 0 | 4 | 4 | 0% |
| Dalfox/sqlmap candidates (injection) | 7.038 | 186 | 8 | 8 | 0% |

Model calls: 0. Input tokens: 0. Output tokens: 0. Model cost: USD 0. These runs configure no model provider.

## Per-run observations

| Repetition | Mode | Arm/slice | TP | FP | TN | FN | Inconclusive | Requests | Duration (ms) |
| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | vulnerable | semgrep/a05 | 2 | 0 | 0 | 0 | 0 | 0 | 2272 |
| 1 | vulnerable | scanners/reflected-script | 1 | 0 | 0 | 0 | 0 | 4 | 111 |
| 1 | vulnerable | scanners/sql-query | 0 | 0 | 0 | 1 | 0 | 41 | 1757 |
| 1 | vulnerable | agento/a01 | 2 | 0 | 0 | 0 | 0 | 47 | 2469 |
| 1 | vulnerable | agento/a02 | 3 | 0 | 0 | 0 | 0 | 6 | 304 |
| 1 | vulnerable | agento/a05 | 2 | 0 | 0 | 0 | 0 | 53 | 4342 |
| 1 | fixed | semgrep/a05 | 0 | 2 | 0 | 0 | 0 | 0 | 2099 |
| 1 | fixed | scanners/reflected-script | 0 | 0 | 1 | 0 | 0 | 7 | 88 |
| 1 | fixed | scanners/sql-query | 0 | 0 | 1 | 0 | 0 | 41 | 1608 |
| 1 | fixed | agento/a01 | 0 | 0 | 2 | 0 | 0 | 48 | 2237 |
| 1 | fixed | agento/a02 | 0 | 0 | 3 | 0 | 0 | 6 | 252 |
| 1 | fixed | agento/a05 | 0 | 0 | 2 | 0 | 0 | 56 | 4165 |
| 2 | vulnerable | semgrep/a05 | 2 | 0 | 0 | 0 | 0 | 0 | 2071 |
| 2 | vulnerable | scanners/reflected-script | 1 | 0 | 0 | 0 | 0 | 4 | 76 |
| 2 | vulnerable | scanners/sql-query | 0 | 0 | 0 | 1 | 0 | 41 | 1645 |
| 2 | vulnerable | agento/a01 | 2 | 0 | 0 | 0 | 0 | 47 | 2091 |
| 2 | vulnerable | agento/a02 | 3 | 0 | 0 | 0 | 0 | 6 | 282 |
| 2 | vulnerable | agento/a05 | 2 | 0 | 0 | 0 | 0 | 53 | 4308 |
| 2 | fixed | semgrep/a05 | 0 | 2 | 0 | 0 | 0 | 0 | 2053 |
| 2 | fixed | scanners/reflected-script | 0 | 0 | 1 | 0 | 0 | 7 | 94 |
| 2 | fixed | scanners/sql-query | 0 | 0 | 1 | 0 | 0 | 41 | 1659 |
| 2 | fixed | agento/a01 | 0 | 0 | 2 | 0 | 0 | 47 | 2229 |
| 2 | fixed | agento/a02 | 0 | 0 | 3 | 0 | 0 | 6 | 207 |
| 2 | fixed | agento/a05 | 0 | 0 | 2 | 0 | 0 | 56 | 4159 |

## Runtime versions

Node v22.23.2; linux/x64; Playwright 1.63.0.

- semgrep: 1.180.0
- dalfox: 3.2.4
- sqlmap: 1.10.10.8#dev

The JSON records the base Git revision and source SHA-256 values, including local changes. An external real-world Express project was not tested.

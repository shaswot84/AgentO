# Evaluation

AgentO has a reproducible, controlled benchmark for the seven supported CWEs.
It runs the actual Express storefront in vulnerable and fixed modes, retains
source and runtime proof, and compares the two injection cases with native tool
baselines. This measures the selected demo behaviors; it does not establish
accuracy on unfamiliar applications.

Separate [external project tests](realworld-testing.md) cover seven pinned
GitHub repositories. They expose source extraction gaps and include a live Flask
runtime test. Those results are not part of the controlled accuracy scores below.

The [recorded results](evaluation/summary.md) contain the measured numbers and
per-run timings. The [machine-readable record](evaluation/results.json) includes
case observations, immutable proof bundles, tool versions, and source hashes.

On 19 October 2026, two repetitions in each mode produced 14 true positives,
14 true negatives, zero false positives, and zero false negatives for AgentO.
Observed precision, recall, and dynamic verification rate were each 100% on
these seven controlled cases. AgentO executed 24 probe collections, sent
431 requests to the target, and took 27.045 seconds across the four complete scans.
The injection-only comparison was:

| Arm | TP | FP | TN | FN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AgentO confirmed findings | 4 | 0 | 4 | 0 | 100% | 100% |
| Semgrep candidates | 4 | 4 | 0 | 0 | 50% | 100% |
| Dalfox/sqlmap candidates | 2 | 0 | 4 | 2 | 100% | 50% |

The baselines cover two CWEs. Candidate scoring and the small, repeated demo
sample limit the interpretation of these numbers, as described below.

## Reproduce

Use Node.js 22.22.3 or a supported newer version, npm, Git, and OpenSSL. Install
the demo dependencies with `npm ci` in `demo-apps/demo-app-01`. Follow the
[injection assessment build order](../packages/a05/README.md#setup), then install
and build `packages/a01` and `packages/a02`. Install the native Semgrep, Dalfox,
sqlmap, and Chromium dependencies described in those package guides. Local
loopback listeners and browser child processes must be permitted.

Run from the repository root. Set executable paths when the native tools are
not on `PATH`; the sqlmap value can be an executable Python launcher. No model
credentials are needed. Choose output paths that do not exist.

```sh
AGENTO_SEMGREP_EXECUTABLE=/path/to/semgrep \
AGENTO_DALFOX_EXECUTABLE=/path/to/dalfox \
AGENTO_SQLMAP_EXECUTABLE=/path/to/sqlmap \
node --import ./demo-apps/demo-app-01/node_modules/tsx/dist/loader.mjs \
  scripts/evaluation/run.mjs --output /tmp/agento-evaluation-new.json --repeats 2

node scripts/evaluation/verify.mjs /tmp/agento-evaluation-new.json --check-sources
node scripts/evaluation/render.mjs /tmp/agento-evaluation-new.json /tmp/agento-evaluation-new.md
```

The default is two repetitions; `--repeats` accepts 1–5. Every repetition scans
both modes. The runner creates an in-memory database and local HTTP/HTTPS
servers, trusts its own temporary TLS certificate explicitly, and disposes of
servers, database, and certificate files. A02 uses HTTPS so the `Secure` check
has a valid transport. A01 uses fresh, isolated Chromium logins. Each assessment
gets a fresh evidence store. The configured policy permits these bounded tests
against this controlled loopback target. The command accepts no external URL.

The runner refuses an existing report path. Missing executables fail preflight;
failed or incomplete assessments produce unknown observations and a nonzero exit
code after saving results. A failure before server startup can leave an empty
reserved output file; use a fresh path after correcting the setup. Native logs,
credentials, request payloads, and response bodies are not exported. Review new
artifacts before publishing them, especially after modifying tools or fixtures.

Offline verification and regression checks need no native scanner or server:

```sh
node scripts/evaluation/metrics.test.mjs
node scripts/evaluation/verify.test.mjs
node scripts/evaluation/verify.mjs docs/evaluation/results.json
```

`verify.test.mjs` also checks the current source hashes against the recorded
snapshot. Changes to evaluated source require a fresh benchmark. Digest checks
detect damaged records; they are not signed attestations of who ran a scan.

## Ground truth and scoring

The [case manifest](../scripts/evaluation/cases.json) freezes seven units before
execution. Each unit is one CWE at one selected route and intended access or
configuration boundary. Vulnerable mode supplies seven positive labels; fixed
mode supplies seven negative labels. Both branches exist in the same source.
The demo's [18 existing tests](../demo-apps/demo-app-01/test/security.test.ts)
provide separate checks of these seeded behaviors and ordinary account access.
Cookie checks over HTTPS and script execution also have retained benchmark proof.

| Case | CWE | Selected behavior | Ground-truth source |
| --- | --- | --- | --- |
| order-owner | 639 | Bob reads Alice's private order | `src/routes/orders.ts` |
| admin-role | 862 | Customer reads administrator user list | `src/middleware/auth.ts` |
| cookie-httponly | 1004 | Sensitive cookie lacks HttpOnly | `src/middleware/auth.ts` |
| cookie-secure | 614 | Sensitive cookie lacks Secure over HTTPS | `src/middleware/auth.ts` |
| cors-origin | 942 | Untrusted Origin is reflected with credentials | `src/middleware/cors.ts` |
| reflected-script | 79 | Query value executes script in HTML | `src/routes/search.ts` |
| sql-query | 89 | Query input changes SQL result selection | `src/routes/search.ts` |

Source paths in this table are relative to `demo-apps/demo-app-01`. Labels refer
only to these selected behaviors. For example, fixed mode still allows an
explicit request override of its demonstration mode; it is not a hardened
production application. The CORS case tests a permissive credentialed policy;
it does not prove a browser can steal sensitive data across sites.

For AgentO, `CONFIRMED` is positive, `NOT_REPRODUCED` is a tested negative, and
all other states or absent results are unknown. A negative means this test did
not reproduce the seeded issue. It is not a general security verdict. A case
must map to exactly one decision at the labelled CWE and endpoint. Duplicate or
ambiguous decisions remain unknown. Several scanner matches at one unit count
as one positive. Unlabelled routes are outside the denominator.

- **TP:** A positive on a vulnerable label.
- **FP:** A positive on a fixed label.
- **TN:** A completed negative on a fixed label.
- **FN:** A vulnerable label without a positive, including an unknown result.
- **Inconclusive:** An unknown result on either label. This overlaps FN for
  vulnerable cases; it never increases TN for fixed cases.
- **Precision:** `TP / (TP + FP)`.
- **Recall:** `TP / (TP + FN)`.
- **Coverage:** Cases with positive or negative results divided by all cases.
- **Dynamic verification rate:** Positives with complete, cited runtime proof
  accepted by AgentO's verification judge divided by all reported positives.

Zero denominators are JSON `null`, displayed as N/A. A baseline's zero dynamic
verification rate means its candidates did not pass a separate AgentO judge;
it does not mean the native dynamic scanner sent no requests or made no checks.
Repeated runs show repeatability on the same units. They do not add independent
applications or justify statistical confidence intervals about general accuracy.

## Baseline comparison

The matched comparison uses only CWE-79 at `/search?q=SecureKey` and CWE-89 at
`/api/search?q=SecureKey`, in both modes:

| Arm | Inputs and decision rule |
| --- | --- |
| Semgrep alone | Bundled Express injection rules scan the same full source. Framework extraction attributes matches to routes. A mapped static signal is a candidate positive. No runtime test runs. |
| Dalfox/sqlmap alone | Native tools scan the same selected query parameters through the scoped gateway, without source, hypotheses, browser canary verification, or controlled AgentO response comparisons. A normalized tool candidate is a positive. |
| AgentO A05 | Source signals select query inputs, then existing probes run native scanners plus Chromium script checks or controlled SQL responses. The existing CWE rules and judge decide findings. |

Counting baseline candidates as positives measures the risk of accepting tool
output without further verification. Semgrep itself labels them as candidates;
the benchmark does not claim Semgrep asserts that every candidate is exploitable.
The same dual-mode source can flag a vulnerable branch even when the fixed branch
is active. AgentO can resolve that ambiguity against the running target.

All native dynamic calls use the existing adapters, one worker/thread, selected
parameters, at most 512 forwarded requests per tool invocation, bounded process
time, and fresh tool state. Dalfox uses the adapter's two-payload limit. sqlmap
uses boolean/error techniques with risk 1 and level 1. AgentO A05 adds its normal,
syntax-error, true/false, or browser controls. The default application policy
budget is 600 requests per execution. No crawling, data extraction, or arbitrary
external target is enabled. The scanner guides describe the exact fixed options.

The bounded scanner baseline can miss SQL injection that AgentO's explicit
response comparisons establish. This is a result for these options and seeded
query contexts. It does not show that unrestricted sqlmap cannot find the issue.
No ZAP-wide or full-site scanner comparison was performed. The five other CWEs
appear only in the seven-case AgentO result, with no baseline coverage claim.

## Performance and model use

Each row measures wall-clock time from assessment setup through evidence capture.
It includes source discovery, tool startup, authentication, browser startup, and
verification where that arm uses them. Version preflight, target/certificate
startup, output serialization, and the final offline check are excluded.
The server counts every received HTTP request, including browser assets and
login requests. Blocked requests, gateway-only traffic, and TLS handshakes are
not counted. Counters retain totals, without URLs or private HTTP values.

Jobs/probes executed count non-skipped native jobs or unique probe collections.
The two cookie CWEs share one collection, so AgentO executes six collections per
mode for seven verdicts. Completed counts require complete collection. Static
jobs and multi-request probes are different work units; the HTTP and timing
columns provide their cost context. Injection-only effort is reported separately
for a like-for-like comparison; the seven-CWE total has wider coverage.

Model calls, input/output tokens, and model cost are all zero because these
assessments use deterministic hypotheses and browser login recipes without a
model provider. Infrastructure cost and optional semantic LLM workflows are
unmeasured. Timings vary by hardware, OS, cache, tool version, and browser startup.
Arm order is fixed (static baseline, dynamic baseline, AgentO) and is not
randomized; these timings are descriptive, not a controlled speed ranking.

## What the proof supports and what remains

The JSON preserves the actual verdicts, case-level predictions, source/runtime
evidence IDs, digest-checked proof bundles, run counters, and all measured values.
The offline verifier checks the complete expected repetition/mode/arm matrix,
label bindings, target paths, probe types, record digests, complete runtime
observations, and recomputed tables. Source hashes identify both the original
Git revision and the local files used, including compiled package exports.

The observed benefit is more selective reporting: runtime verification can reject
static candidates in the inactive branch, Chromium distinguishes reflection from
script execution, controlled SQL responses add proof beyond console claims, and
declared user boundaries support multi-session authorization checks. These inputs
include known test accounts, private resource markers, sensitive cookie names,
and SQL response/context bindings. Their manual configuration cost is unmeasured.

This evaluation does not run an independent real-world Express application.
The JSON records that omission explicitly. Other gaps include malformed source,
alternate frameworks, unseeded vulnerabilities, stored/DOM-only XSS, time-based
SQL injection, production scale, remediation quality, and optional model cost.
Missing tools, denied policy, login failures, changed source, truncated proof,
timeouts, or unavailable browser dependencies must remain errors or inconclusive
coverage. The automated checks reject lost runs, rewritten scores, damaged proof,
and false secure results. An independent labelled project and a broader scanner
configuration are needed before making real-world accuracy claims.

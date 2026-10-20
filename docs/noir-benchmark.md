# Noir benchmark and adoption recommendation

**Decision: adopt Noir as the default static endpoint-inventory provider behind
AgentO's contracts. Keep AgentO's source validation, security-context analysis,
input attribution, policy and verification.**
Noir improves discovery substantially, but its output needs validation before
AgentO can use it to select executable tests. It is not a complete replacement
for the existing source adapter.

The benchmark originally recommended an optional prototype. The approved adoption
now makes Noir the default, with independent validation before planning or probe
execution. See the [implementation and validation checks](noir-adoption.md).
The measurements below remain the original comparison, not post-adoption scores.

Tested on **20 October 2026** using the official
[Noir v1.4.0 release](https://github.com/owasp-noir/noir/releases/tag/v1.4.0).
The downloaded Linux x86-64 binary matched the SHA-256 digest in GitHub's release
metadata: `620e774f240be91b975ca0b2f04a5df568f0612ef1f74d182a43a25daf402001`.
The benchmark records AgentO revision
`669ba82e713152dc511ce01a8dde6b15e6c7726e` and hashes its built extractor files.

## Route results

The comparison reused the [same seven pinned repositories](../scripts/evaluation/realworld-cases.json)
and all 15 original reviewed Express method/path references. Neither their
revisions nor the original reference denominator changed.

| Project | AgentO reference matches | Noir reference matches | AgentO endpoint count | Noir endpoint count |
| --- | ---: | ---: | ---: | ---: |
| NodeGoat | 0/2 | 2/2 | 0 | 20 |
| RealWorld Express API | 1/3 | 1/3 | 1 | 20 |
| Juice Shop | 1/3 | 3/3 | 1 | 124 |
| NodeBB | 0/2 | 2/2 | 5 | 580 |
| Express boilerplate | 0/2 | 2/2 | 0 | 15 |
| Hackathon Starter | 3/3 | 3/3 | 101 | 101 |
| **Express total** | **5/15** | **13/15** | **108** | **860** |
| Flask tutorial, separate control | Unsupported source stack | 5/5 | 0 | 12 |

These Noir figures use the framework-scoped configuration: `js_express` for the
six Express apps and `python_flask` for Flask. NodeBB counts include route
patterns and configuration-dependent paths. Juice Shop includes static assets.
Endpoint counts are output inventory sizes, not verified live-route counts.

On the original Express smoke references, observed match coverage increased
from **33.3% to 86.7%**. The reference set is small and exploratory. This is not
whole-application recall, vulnerability accuracy or a production security score.
The five Flask references are additional controls and are not pooled into the
original Express denominator.

## Important limits

**RealWorld loses its `/api` mount prefix.** Noir emits 19 non-root routes such
as `POST /users/login` and `GET /articles/feed`. The source mounts those controllers
under `/api`. Their proper request paths include that prefix. The existing
root route is the only correct match among that project's three original references.
A synthetic chained-router control reproduced the same failure: `/api/users`
became `/users`.

**Input discovery is still insufficient for precise Express security tests.**
The [input smoke set](../scripts/evaluation/noir-references.json) contains ten
reviewed Express route/input bindings. AgentO recovered zero; Noir recovered one:
the `userId` path parameter on NodeGoat's allocation route. Noir identified three
RealWorld input names, but attached them to paths missing `/api`, so those are not
correct route/input bindings. The other six reviewed Express inputs were absent,
including Juice Shop's search query `q` and imported-controller login inputs.
Noir recovered all five additional Flask form/path bindings.

**Route-table support depends on the source shape.** Noir correctly recovered
the real Express boilerplate `/v1/auth/login` and `/v1/auth/register` references.
It missed the prefix in a smaller control that combines a table with an arrow
callback and parent router mount. Support for one repository does not establish
support for every equivalent registration pattern.

**Source selection and provenance need host controls.** Juice Shop results
merged application source with training-code variants. Excluding
`data/static/codefixes/**` removed all training-source references and changed
its inventory from 124 to 123 entries. Its original three route references
remained present. Twelve entries in the unfiltered inventory point to static
asset files without code line numbers; those are legitimate asset-style
provenance, not evidence of erroneous routes. They must not be treated as
controller locations for injection attribution.

**Configuration placeholders and patterns need explicit handling.** NodeBB
includes a `/{name}/manage/groups/:slug` candidate where `name` comes from
mount configuration. Source does not establish it as a user-controlled path
parameter. Its inventory also includes Express wildcard/regular-expression-style
patterns. These are useful source observations but cannot be sent as literal URLs.

All timed Noir runs exited successfully with `--strict` and reported no analyzer
errors. The prefix and input gaps still existed. Successful process completion
does not establish complete route coverage.

## Output quality checks

A deterministic audit selected five evenly spaced unique method/path pairs per
project from the sorted framework-scoped output: **35 source-reviewed samples**.
The [audit record](evaluation/noir/source-audit.json) includes source locations,
review notes and conditions:

- 28 samples had supporting route declarations. Two Juice Shop samples also
  carried training-source references and require source-boundary filtering.
- Four RealWorld samples had incorrect mount prefixes.
- Two NodeBB samples were route patterns requiring pattern handling.
- One NodeBB sample retained an unresolved configuration placeholder.

This is a source audit, not a random precision sample or runtime validation.
The supported NodeBB declarations were reviewed under the default root mount;
runtime relative paths and plugin remounts remain unknown.

Four separate [synthetic controls](evaluation/noir/controls.json) checked specific
failure modes. Both extractors ignored deliberate Axios/outbound/fake-object
calls in a mixed-client source file. Noir also recovered a registration helper.
Both missed the correct chained-router and nested route-table paths; Noir emitted
an incorrect unprefixed route in each of those two cases. AgentO emitted no route
for those cases. None of the fixture application modules were executed.

Noir's optional `--include callee` and static `--ai-context` enrichment were
tested separately on all six Express apps. No model provider was configured.
Enrichment added context but left the reviewed route/input match results unchanged.
Those trials are retained in [the experiment records](evaluation/noir/experiments/results.json)
and are excluded from the main timing comparison.

## Time, memory and repeatability

There were **63 timed runs**: seven projects, three configurations, three
repetitions each. The configurations were AgentO extraction alone, Noir automatic
technology detection, and Noir restricted to the intended framework. The execution
order rotated across projects and repetitions. Noir used one worker.

| Express project | AgentO median | Scoped Noir median |
| --- | ---: | ---: |
| NodeGoat | 623 ms | 135 ms |
| RealWorld | 586 ms | 133 ms |
| Juice Shop | 1,992 ms | 295 ms |
| NodeBB | 3,735 ms | 715 ms |
| Express boilerplate | 659 ms | 122 ms |
| Hackathon Starter | 1,121 ms | 163 ms |
| **Sum of project medians** | **8,716 ms** | **1,563 ms** |

Scoped Noir used about **5.6 times less elapsed time** across these six project
medians. The largest measured peak resident memory was **56.6 MiB** for scoped
Noir and **359.7 MiB** for AgentO. GNU `time` measured subprocess peak RSS; wall
times include process startup and JSON serialization. These are local warm-cache
measurements, not universal performance guarantees or equal-completeness workloads.
AgentO timings exclude discovery, `supports()`, Semgrep, planning and runtime work,
so they are not compared to the older full-pipeline timings.

Each configuration produced the same normalized inventory fingerprint in all
three repetitions for every project. All source checkouts remained clean.
No target requests, application dependency installs or model calls were part of
the scans. Network access was used only to fetch the tool and pinned repositories.

Automatic technology detection intentionally includes other surface types.
For example, Flask's default 13-entry inventory includes its `init-db` CLI command;
framework-scoped output has 12 HTTP entries. NodeBB default output also includes
CLI and OpenAPI-derived entries. An AgentO adapter should select technologies
explicitly and preserve the origin/type of each observation.

## How AgentO should use it

1. Add an optional replaceable endpoint-inventory adapter around the pinned CLI.
   Use explicit technologies, an isolated configuration, bounded process/output
   limits, and deterministic static mode with model/probe/export features disabled.
2. Normalize its inventory into AgentO observations while preserving tool version,
   source identity, parameter location and unresolved route conditions.
3. Validate source boundaries, mount prefixes, route patterns and host configuration
   before using an inventory entry for execution. Keep known ambiguous entries blocked.
4. Retain focused source analysis for handler identity, middleware scope, sensitive
   configuration, input tracing and Semgrep-to-endpoint association.
5. Continue using AgentO's private input bindings, capability selection, policy,
   probes, evidence store, CWE rules and verification judge for security decisions.

The measured benefit justifies an adapter prototype. It does not justify deleting
the existing source analysis or treating every Noir path as an executable target.
The next custom-analysis work should address measured gaps such as router-prefix
resolution and imported-handler inputs, while reusing Noir's broader inventory.
This benchmark does not install a production adapter or change assessment behavior.

## Reproduce and verify

Restore the same pinned checkouts using the commands in
[external project testing](realworld-testing.md#repeat-the-external-checks).
Build the existing Express adapter and its local dependencies. This comparison
does not need Semgrep, a browser, application dependencies or model credentials.

Download the exact benchmark binary into a temporary directory:

```sh
mkdir -p /tmp/agento-noir-tools
curl -fL https://github.com/owasp-noir/noir/releases/download/v1.4.0/noir-v1.4.0-linux-x86_64 \
  -o /tmp/agento-noir-tools/noir
printf '%s  %s\n' 620e774f240be91b975ca0b2f04a5df568f0612ef1f74d182a43a25daf402001 \
  /tmp/agento-noir-tools/noir | sha256sum -c -
chmod +x /tmp/agento-noir-tools/noir

node scripts/evaluation/noir-benchmark.mjs \
  --repos /tmp/agento-realworld-repeat \
  --noir /tmp/agento-noir-tools/noir \
  --output /tmp/agento-noir-new-results

node scripts/evaluation/noir-controls.mjs \
  --noir /tmp/agento-noir-tools/noir \
  --output /tmp/agento-noir-new-controls

node scripts/evaluation/noir-verify.mjs
node scripts/evaluation/endpoint-score.test.mjs
node scripts/evaluation/noir-verify.test.mjs
```

The benchmark expects Linux GNU `/usr/bin/time`, Node.js and the exact verified
Noir binary. It refuses existing result directories, dirty target checkouts and
wrong source revisions. It provides a fresh empty Noir config and does not pass
ambient model credentials to child processes. Tool processes have a 180-second
deadline and a 32 MiB combined-output limit. Any source gap remains visible even
if the comparison command itself completes.

Full primary observations and normalized inventories are gzip-compressed beside
[the recorded results](evaluation/noir/results.json). Both compressed and original
JSON digests are recorded. Offline verification recomputes scores and checks
all 63 run records; it also checks that the current runner, scorer and reference
manifests match the recorded procedure. These are integrity checks, not signed
attestations or independent proof of vulnerability accuracy.

Validation for this change: the Express package passed typecheck/build and its
31 tests. Four scoring tests and five offline verification/tamper tests passed.
Production assessment code and the original external result snapshots were unchanged.

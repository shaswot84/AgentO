# AgentO Semgrep Static Analyzer

Read-only JS/TS analysis implementing the core `StaticAnalyzer` contract. Two
bundled taint rules produce **static candidates** for CWE-79 and CWE-89. A signal
can support a later security hypothesis; it never creates a vulnerability verdict,
confirmed finding, runtime test, or remediation by itself.

## Run independently

Requires Node.js 22 or later and Python 3.10 or later. Install the pinned Semgrep
Community Edition separately from npm. From the repository root:

```sh
python3 -m venv /tmp/agento-semgrep-venv
/tmp/agento-semgrep-venv/bin/python -m pip install -r plugins/tools/semgrep/requirements.txt
cd packages/core
npm ci
npm run build
cd ../../plugins/frameworks/express
npm ci
npm run build
cd ../../tools/semgrep
npm ci
npm run check
npm run analyze -- ../../../demo-apps/demo-app-01 --executable /tmp/agento-semgrep-venv/bin/semgrep
```

After building, run directly from the repository root:

```sh
node plugins/tools/semgrep/dist/cli.js demo-apps/demo-app-01 --executable /tmp/agento-semgrep-venv/bin/semgrep
```

Without `--executable`, the CLI uses `semgrep` on PATH. It prints only normalized
JSON, including status and diagnostics. Exit code 0 means completed analysis,
including a completed scan with candidates; code 1 means partial, failed, skipped,
or invalid CLI arguments. `--help` prints usage. No target application, database,
browser, scanner service, or LLM is needed. Output can be redirected to a file for
later use; persistent evidence storage is outside this adapter.

## Core integration and optional Express context

```ts
import { AgentOOrchestrator } from '@agento/core';
import { ExpressFrameworkAdapter } from '@agento/framework-express';
import { SemgrepAdapter } from '@agento/tool-semgrep';

const frameworkAdapter = new ExpressFrameworkAdapter();
const frameworkAnalysis = await frameworkAdapter.extract(project);
const staticAnalyzer = new SemgrepAdapter({
  executable: '/path/to/semgrep',
  frameworkAnalysis,
});
const analysis = await staticAnalyzer.analyze(project);
const report = await new AgentOOrchestrator({
  plugins: [],
  frameworkAdapter,
  staticAnalyzer,
}).run({ project, identities: [] });
```

`project` is the existing core `Project` with code-aware mode, repository path,
and JavaScript/TypeScript languages. Framework context is optional and must come
from the same project and source revision. Callers precompute it; this adapter
does not invoke framework providers or other tools. A single matching handler
range adds `endpointId`; repeated mounts retain all candidate `endpointIds` in
evidence rather than guessing one endpoint.

The result extends core `StaticAnalysis` with `status` and `diagnostics`. Every
result also contains normalized `static-analysis-run` evidence, so the core
orchestrator retains failure/partial-scan provenance even though its current
contract carries only signals and evidence. Consumers must check this run status
before interpreting an empty signal list as a completed scan.

## Rules and evidence

- `agento.express.request-to-html`: request query/body/path/header/cookie values
  reaching `send`, `write`, or `end` arguments. `res.json()` is not an HTML sink.
- `agento.express.request-to-sql`: request values reaching the SQL text argument
  of `prepare`, `query`, `execute`, or `exec`. Bound parameter arguments are not
  sinks, so constant SQL with placeholders remains unflagged.

Both rules use [Semgrep taint analysis](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/overview)
with exact sources. HTML sanitizers are assumptions for `DOMPurify.sanitize`,
`sanitizeHtml`, and `escapeHtml`; names do not prove that a custom sanitizer is
correct, imported from a trusted package, or appropriate for every output context.

Only bundled rule IDs map to CWEs. Provider messages, metadata, snippets, fixes,
fingerprints, error text, and raw JSON are discarded. Records contain stable
project-scoped IDs, producer, timestamp, repository-relative file and one-based
lines, and normalized source/sink facts. Evidence marks `runtimeVerified: false`
and `requiresRuntimeVerification: true`. IDs include a digest of selected source
bytes and distinguish multiple sinks on the same line; duplicate matches collapse.

The installed CE engine's JSON does not include source traces in the verified
run. A bounded TypeScript AST supplement follows local definitions,
destructuring, aliases, and preceding assignments around each matched sink. It
records candidate request-source locations, sink API/location, enclosing branch
locations, and observed content-type calls on the same response receiver.
`sourceResolution` labels bounded AST def-use analysis or partial/unavailable
context. These are possible syntax relationships, not proven execution paths.
The supplement adds context to Semgrep matches; it does not create independent
signals or certify data-flow reachability.

Verified demo output contains exactly two candidates in `src/routes/search.ts`:

| Candidate | Request source | Sink | Endpoint with Express context |
| --- | --- | --- | --- |
| CWE-89 | Line 21, query input | Line 49, `prepare` | `/api/search` |
| CWE-79 | Line 74, query input | Line 149, `send` | `/search` |

Both vulnerable and fixed branches remain in the demo source. A running fixed
mode still has those static candidates; selecting runtime mode does not rewrite
source or prove a finding. Separate fixed-only JS/TS controls produce no signals.

## Execution boundaries and limitations

The adapter reads source into a temporary snapshot and invokes the trusted
Semgrep executable with fixed arguments and no shell. It uses bundled local
rules, the OSS engine, disabled metrics/version checks, isolated settings/logs,
and an allowlisted environment without inherited Semgrep credentials. Target
manifests, ignore/config files, modules, tsconfig plugins, package scripts, and
databases are never loaded or executed. Snapshot scanning intentionally ignores
target `.semgrepignore` and `nosemgrep` suppressions. No autofix, remote rule
download, target HTTP request, browser workflow, or tool chaining runs. CLI flags
follow the [official Semgrep reference](https://docs.semgrep.dev/cli-reference).

Source inventory excludes hidden files, symlinks, dependency/build output,
test/fixture files, and declaration files. It is bounded to 20,000 entries,
1,000 source files, 40 directory levels, 1 MiB per source, and 16 MiB overall.
Unreadable/unparsable/oversized source yields diagnostics and partial analysis.
Repositories with symlink ancestors are rejected. Semgrep must report scanning
every selected source file; omissions produce partial-scan diagnostics.

Defaults are 120 seconds for the process, 5 seconds per Semgrep rule/file, one
worker, 8 MiB combined stdout/stderr, and 10,000 normalized matches. Trusted
backend options can change process timeout/output limits within fixed maxima.
Timeout/output-limit failures terminate the process group on POSIX and remove
the temporary snapshot. Windows termination applies to the direct process.
Stderr and thrown provider messages never enter the analysis result.

This initial rule set does not cover arbitrary frameworks/ORMs, DOM/stored XSS,
all sanitizer libraries, alias-aware package identification, whole-program taint,
cross-file helper flows, or path-sensitive branch feasibility. Header `get()`
sources recognize `req` and `request`; other request-property reads use structural
patterns. Structural source/sink names may match unrelated objects. AST context
is lexical, bounded, and deliberately conservative around conditional assignments;
response-format observations do not prove which branch actually executes. The
rules and supplement therefore feed hypotheses requiring later runtime probes.

## Verification

```sh
cd plugins/tools/semgrep
npm run check
AGENTO_SEMGREP_EXECUTABLE=/tmp/agento-semgrep-venv/bin/semgrep npm run test:integration
```

The default suite runs 31 tests covering normalization, provenance, AST, framework association,
repository isolation, redaction, malformed output, missing-tool, timeout, output
limit, core failure propagation, and CLI tests. Process-boundary tests use
`python3` (override with `AGENTO_TEST_PYTHON`); Semgrep integration tests are
explicitly skipped unless `AGENTO_SEMGREP_INTEGRATION=1` is set by the integration
script. The three integration tests run the installed tool against the real demo,
checks source/sink lines and Express endpoints through core orchestration, scans
unsafe/fixed-only JS/TS controls, proves target modules never execute, and verifies
the standalone CLI. Verified with Semgrep CE 1.180.0.

For direct property access such as `req.query.q`, source evidence includes
`parameterName` beside its request source kind. The targeted injection host uses
that attribution with model parameters to avoid testing unrelated route inputs.
Unresolved names remain absent; the adapter does not guess a parameter.

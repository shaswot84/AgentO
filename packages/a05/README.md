# A05 injection assessment

`@agento/a05` connects repository discovery and Semgrep source signals to targeted
CWE-79 and CWE-89 investigations:

```text
source → application model → grounded hypotheses → private input bindings
→ capability selection → execution policy → probes → retained evidence → verdicts
```

Only selected literal GET routes and query parameters attributed to a static
source signal are eligible. The runner does not crawl the application. The CWE
plugins make all security decisions; scanners supply observations.

## Setup

Use Node.js 22.22.3 or a supported newer version. Run `npm ci` and `npm run build` in these directories, in order:

```text
packages/core
packages/discovery
plugins/tools/e2e-browser
packages/runtime
plugins/frameworks/express
packages/security-model
plugins/cwe
packages/hypothesis-engine
packages/test-planner
packages/capability-registry
packages/policy-engine
packages/evidence
packages/verifier
plugins/tools/semgrep
plugins/tools/security-scanners
packages/a05
```

Install Noir with `npm run setup:noir --prefix plugins/frameworks/express` from
the repository root after dependency setup. The default source adapter uses Noir
inventory and AgentO validation; unvalidated routes cannot drive assessments.
See [endpoint discovery setup](../../plugins/frameworks/express/README.md).

Install [Semgrep](../../plugins/tools/semgrep/README.md),
[Dalfox and sqlmap](../../plugins/tools/security-scanners/README.md), and the
[Chromium runtime](../../plugins/tools/e2e-browser/README.md) separately. Native
executables are optional for unit tests and required for the live demonstration.
No model service is required.

```sh
cd packages/a05
npm run check
AGENTO_SEMGREP_EXECUTABLE=/path/to/semgrep \
AGENTO_DALFOX_EXECUTABLE=/path/to/dalfox \
AGENTO_SQLMAP_EXECUTABLE=/path/to/sqlmap npm run test:integration
```

The live tests start the actual storefront on loopback with an in-memory database,
scan its source, run both native scanners and Chromium, and compare vulnerable
and fixed modes. They also exercise the built JSON CLI. Unit tests cover missing
inputs, source attribution, unavailable tools, policy denial, cancellation,
request limits, private data and evidence replay after reopening the journal.

## CLI

Start an authorized target and copy [the example](examples/storefront.json) to a
private location. Set the repository path, exact target origin, selected routes,
private baseline inputs and fresh output paths. Relative paths resolve beside
the configuration file. The example assumes its original directory.

```sh
node packages/a05/dist/cli.js /private/a05-scan.json
```

Set `semgrepExecutable`, `dalfoxExecutable`, and `sqlmapExecutable` in that JSON
when tools are not on `PATH`. Use a command name or absolute executable path.
Environment variables shown above configure the integration tests; the CLI reads
its executable settings from JSON. A Python sqlmap installation needs an executable
launcher, as described in the scanner guide.

The example explicitly permits active tests by setting empty approval risk and
severity lists. Omit `approval` to keep the policy engine's default approval
requirement; the runner then skips those plans. This runner never issues approval
tokens. Origin, method, tool, rate, request and lifetime checks remain active.

The CLI supports anonymous public GET query investigations. For authenticated
routes, inject a guarded authentication manager through the API. The CLI refuses
existing evidence journals and report files, writes reports with mode `0600`, and
returns `0` for a completed scan, `2` for incomplete coverage or execution, and
`1` for configuration or scan errors. Confirmed findings do not change the exit
code by themselves.

## API

```ts
import { runA05Scan } from '@agento/a05';
import { FileEvidenceStore } from '@agento/evidence';
import { DalfoxAdapter, SqlmapAdapter } from '@agento/security-scanners';

const store = new FileEvidenceStore('/private/run-123/evidence', {
  expectedHeadDigest: null,
});
try {
  const report = await runA05Scan({
    project, allowAnonymous: true,
    targets: [
      { path: '/search', cweId: 'CWE-79', inputs: { q: 'SecureKey' } },
      { path: '/api/search', cweId: 'CWE-89', inputs: { q: 'SecureKey' },
        sqlBooleanContext: 'like-pattern', responseJsonPointer: '/results' },
    ],
    scanners: [new DalfoxAdapter().registration(), new SqlmapAdapter().registration()],
    evidenceStore: store,
    policy: {
      allowedOrigins: project.allowedOrigins, allowedMethods: ['GET'],
      tools: { 'a05-http': {}, 'a05-browser': {}, 'dalfox-adapter': {}, 'sqlmap-adapter': {} },
      approval: { risks: [], severities: [] },
    },
  });
  for (const decision of report.decisions) store.exportFinding(decision.finding);
} finally { store.close(); }
```

The API permits an injected framework adapter, static analyzer, browser,
authentication manager, HTTP transport and scanner registrations. Static adapters
must emit endpoint-bound signals and `sources` entries with `kind: 'request-query'`
and `parameterName` in their referenced evidence. Missing attribution produces a
coverage diagnostic and no dynamic test. Every plan needs an explicit private
baseline input for its selected parameter. Values remain outside plans and reports.

At most 32 route/category selections and 10 authenticated identities are accepted.
`maxScannerRequests` defaults to 128 and is bounded to 1–512 per probe; the total
execution and per-tool policy limits still apply. A missing required scanner skips
the plan. Failed scanners and incomplete responses remain visible as partial
coverage. A stronger independently observed positive can still establish a finding.

## Proof and limits

For XSS, Dalfox runs on the selected parameter. Chromium visits a single injected
URL containing a random canary element and a script that sets `window.name` to
that token. A narrow browser read checks that marker and the parsed element. It
accepts no executable code from the caller. Browser proof takes precedence over
scanner flags; reflection and visible text alone cannot confirm XSS. The canary
is read within an isolated, policy-bound session, and the handle expires afterwards.
This bounded reflected HTML check does not cover stored XSS or every script context.

For SQL, sqlmap runs boolean/error techniques against one selected parameter,
with extraction and command features absent from the invocation. The probe also
collects a baseline, syntax mutation and paired boolean controls. A trusted host
may choose `sqlBooleanContext: 'like-pattern'` for quoted LIKE patterns. Otherwise
the original quoted-string controls remain in use. These options do not infer or
certify an application's SQL grammar.

Responses that echo the query cannot be judged by whole-body differences alone.
An explicit `responseJsonPointer`, such as `/results`, hashes a structured JSON
result field separately. The true control must reproduce the baseline field and
the false control must change it; original response hashes are retained as well.
Missing, scalar, failed or truncated result fields cannot supply this proof.
The pointer must identify application result data. It is trusted host knowledge,
not a field chosen by a model or native scanner. Use a baseline that returns a
stable result; two empty controls do not establish injection. Database-specific
errors and the original full-body controlled comparisons remain supported.
Scanner claims and generic syntax errors alone cannot confirm SQL injection.

`decisions` links source evidence and normalized runtime records to each finding.
`plans`, `results`, and `audit` retain execution attribution. Reopen a file journal
and pass the report context, hypotheses, plans and results to `VerificationJudge`
for replay without target access. An injected store remains caller-owned.

Reports contain redacted URLs, hashes and normalized observations. They exclude
raw response bodies, native output and private baseline values. Keep configuration
and reports private: source locations and application details can be sensitive.
`NOT_REPRODUCED` describes the observed test, not a security guarantee. This package
provides the bounded backend/CLI slice; frontend scheduling and general report
formats are separate capabilities.

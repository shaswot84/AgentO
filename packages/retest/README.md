# Fix verification

`@agento/retest` applies a prepared repair in a temporary source copy, runs its
generated security and normal-use tests, and replays the original security probe.
It retains a comparison record and a separate fix status. The original confirmed
finding and its evidence stay unchanged.

| Status | Required observation |
| --- | --- |
| `FIX_VERIFIED` | Original exploit is blocked, security regression passes, and normal use passes |
| `FIX_FAILED` | The original probe still establishes the vulnerability |
| `FIX_INCONCLUSIVE` | Crash, unexpected response, missing or partial proof, failed/skipped tests, cancellation, timeout, or cleanup failure |

Fix verification describes the selected original probe and tested source revision.
It does not establish that the entire application is secure.

## Setup

Use Node.js 22.22.3 or a supported newer version. Install and build `core`,
`runtime`, `security-model`, `cwe`, `evidence`, and `remediation` with their local
dependencies first. Then run:

```sh
cd packages/retest
npm ci
npm run check
```

Tests also need the reporting package built. The opt-in live suite needs the
storefront dependencies, OpenSSL, Git, and the browser package's installed
`playwright-core` and Chromium:

```sh
npm run test:integration
```

The live suite starts separate loopback HTTPS servers with in-memory databases.
It verifies all seven reviewed Express repairs, an ineffective repair, and a
crashing repair. It checks journal reload and report exports. SQL uses the runtime
SQL probe and a small objective syntax adapter; XSS uses Chromium with a fixed
original script payload. Login-cookie and XSS replay are explicit host probes.
No native scanner or external target is required. Unit fixtures are synthetic.

## Connect the host

```ts
import { RetestEngine, LocalPatchEnvironment } from '@agento/retest';
import { buildSecurityReport } from '@agento/reporting';

const environment = new LocalPatchEnvironment({
  sourceDirectory: reviewedSourceDirectory,
  include: ['src', 'public', 'package.json', 'tsconfig.json'],
  dependencyDirectory: installedDevelopmentDependencies, // Optional.
  start: startIsolatedLoopbackServer,
  regression: runGeneratedSecurityAndNormalTests,
  replay: replaySavedOriginalProbe,
});
const retest = await new RetestEngine({
  evidenceStore: store, rules: [originalCWERule], environment, timeoutMs: 60_000,
}).run({ context, finding, plan, originalResult, remediation }, abortSignal);

const report = buildSecurityReport({
  context, findings: [finding], plans: [plan], results: [originalResult],
  remediation: [remediation], retests: [retest],
}, { evidenceStore: store });
```

The input `plan` is the saved `ProbeTestPlan`, including its original evaluation
scope. `originalResult` must cite completed, digest-checked normalized runtime
proof that the registered CWE rule can confirm. The prepared remediation must
reference the same confirmed finding and retained source records.

Host callbacks are explicit application integration ports:

- `start(directory, signal)` starts the copied application and returns
  `{ baseUrl, dispose }`. Bind only to `127.0.0.1` or `::1`. Clean up partially
  started processes on failure; `dispose` must stop the server and its children.
- `regression(directory, input, signal)` executes the generated test file and
  returns separate `security` and `normalFlow` outcomes. Require actual assertions
  and successful setup; an empty or skipped suite must return `NOT_RUN` or fail.
- `replay(target, plan, targetUrl, signal)` repeats the saved original probe with
  the same private request values, attack payloads, identities, and access policy.
  Only rebase the origin to `targetUrl`. Establish fresh isolated sessions against
  the copied target. Return normalized observations, not a fix verdict.

The engine checks public probe bindings, including XSS canary, authorization
resource/identities, origin test cases, and injection parameter. Retained evidence
redacts private values, so exact private payload replay remains a trusted host
responsibility. Save those bindings when executing the original assessment; do
not regenerate a plan or ask a model to choose replacement payloads.

Supply policy-guarded runtime ports in callbacks where policy is required.
Loopback scope alone is not a substitute for execution policy. This local copy
isolates source and test state; it is not an operating-system sandbox for untrusted
application code. Use trusted source, dependencies, startup, and test callbacks,
or supply a container-based `RetestEnvironment` for stronger process isolation.

## Evidence and limits

- No target execution occurs before original finding, plan, result, evidence,
  capability, project, origin, and remediation bindings pass.
- Local patch application checks every before/after source hash, ordinary unified
  hunk boundaries, and exact file membership. It rejects traversal, symlinks,
  binary/rename/mode patches, unexpected revisions, and test-file overwrites.
- Only explicitly included source paths are copied. Hidden files, `.env`, keys,
  databases, existing Git metadata, and `node_modules` are refused. Optional
  development dependencies are explicitly linked by the host. Source directories
  themselves must not resolve through symlinks.
- Defaults are 10,000 copied files, 32 MiB of source, 16 patch files, 1 MiB of
  patch/test text, and 60 seconds per run (configurable up to 300 seconds).
  Callbacks must honor cancellation, terminate their work, and settle promptly.
  Disposal must also be bounded by the host. No background callback is abandoned
  to race against directory cleanup.
- A successful negative CWE observation is required, together with both passing
  test classes and healthy normal responses. Paired SQL verification also accepts
  the disappearance of an original true/false result-set differential when both
  replayed controls return an empty result set, the original normal result set
  is unchanged, all requests succeed without DB
  errors, and the objective scanner reports no differential. Detection verdicts
  remain unchanged.
- Comparison records cite before/after records, original digests, plan, patch and
  regression-test hashes, outcomes, environment, and a fixed reason code. No raw
  callback output, source text, private payloads, or command errors are retained.
- Each attempt has unique evidence IDs. Reports accept one selected attempt per
  finding and embed its comparative proof. Older attempts remain in the store.
  Invalid original inputs throw fixed `RetestError` codes before execution;
  execution failures produce `FIX_INCONCLUSIVE`. Evidence-store failures throw
  rather than return an unretained verdict.

The package does not modify production branches, commit, push, install packages,
choose commands from prose, configure OpenCode, or wire the frontend automatically.

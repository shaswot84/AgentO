# Security hypothesis engine

`@agento/hypothesis-engine` turns the application security model and independently
registered CWE candidates into evidence-linked investigation questions. Every
result stays `HYPOTHESIS`, with a specific reason, supporting observations, original
evidence IDs and explicit limitations.

## Setup

Use Node.js 22.22.3 or a supported newer release. Build the local dependencies
first, running `npm ci` and `npm run build` in `packages/core`, `packages/runtime`,
and `packages/security-model`, in that order. For the included tests and examples,
also install and build `plugins/frameworks/express`, `plugins/tools/semgrep`, and
`plugins/cwe`. Then run these commands here:

```sh
npm ci
npm run check
```

The Semgrep executable is needed only for the opt-in source-tool integration tests.

## Generate hypotheses

```ts
import { SecurityHypothesisEngine } from '@agento/hypothesis-engine';
import {
  CWEPluginRegistry, CWE639Plugin, CWE862Plugin, CWE942Plugin,
  CWE1004Plugin, CWE614Plugin, CWE79Plugin, CWE89Plugin,
} from '@agento/cwe';

const registry = new CWEPluginRegistry()
  .register(new CWE639Plugin()).register(new CWE862Plugin())
  .register(new CWE942Plugin()).register(new CWE1004Plugin())
  .register(new CWE614Plugin()).register(new CWE79Plugin())
  .register(new CWE89Plugin());

const engine = new SecurityHypothesisEngine({
  plugins: registry.plugins(),
  sensitiveCookieNames: ['application_session'], // explicit application policy
  untrustedOrigins: ['https://untrusted.example'],
  // provider: configuredModelProvider, // optional @agento/core ModelProvider
});

const result = await engine.generate(applicationModel);
// result.hypotheses, result.diagnostics, result.review, result.usage
```

Supply a model assembled by `@agento/security-model`. A flat `AnalysisContext` is
also supported; it is normalized internally. Endpoint aliases retain their
original evidence references. The returned candidate IDs remain compatible with
the originating CWE plugins' `generateTests(context, hypothesis)` method.

For existing core orchestration, pass the same plugins to core and the engine,
and set `reasoning: engine`. Its `reviewHypotheses` implementation preserves the
core contract; use `generate` when review diagnostics and usage are needed.

## Grounding and reasoning

The default context rules cover all seven supported CWEs. They use linked static
signals, explicit sensitive/session cookie configuration, broad CORS observations,
resource ownership, conditional role guards, source/sink candidates and interpolated
SQL observations. Route declarations, arbitrary cookie names, and ordinary
parameterized queries alone do not create deterministic hypotheses.

Optional model review receives bounded observation statements, endpoint method,
authentication and parameter locations, plus opaque candidate/support/evidence
handles. It receives no raw source, response bodies, URLs, repository paths,
identity sessions, credentials, or arbitrary application text. Replies must match
the strict schema and select support handles supplied with that candidate.
AgentO constructs the final reasons from the selected observations.

The model can add qualified, context-only investigations, such as checking whether
request input reaches executable content. These carry `origin: 'model-assisted'`.
Deterministic candidates remain available even if review omits them or fails.
Neither origin establishes a vulnerability or a test verdict. Missing extraction
never establishes missing ownership or authorization enforcement.

Explicit safe observations reduce candidates where appropriate. An owner-bound
resource can still warrant an ownership test on a fixed application. Source trees
that contain both vulnerable and fixed branches retain both observations; switching
a server's runtime mode does not remove its source candidates.

## Limits and extension

Each invocation makes at most one model call, with no retry or shared run state.
Defaults: 200 candidates, 32 supports per candidate, 100 hypotheses, 32,000 input
characters, 16,000 output characters, 2,000 output tokens, 40,000 total tokens and
a 10-second model timeout. Configure these through `limits`. Coverage limits and
provider failures return diagnostics; transport failures without usable usage are
charged a conservative input/output allowance. Pass `{ signal }` to `generate`
for cancellation. Results are immutable JSON data.

When the full context exceeds the input budget, review prioritizes context-only
candidates and fits a subset into one request. `model-context-limit` reports the
partial review; deterministic output is retained independently of that subset.

Custom CWEs register a candidate plugin and a `HypothesisContextRule`. Supplying
`rules` replaces the defaults; extend `createDefaultHypothesisRules()` to retain
them. Context rules are trusted code and must return observational statements with
relevant evidence references. The engine validates references and endpoint binding.

This package does not collect evidence, make HTTP/browser requests, dispatch probes,
create test plans, or produce findings. Model adapters own their transport.

## Verification

```sh
npm run check
AGENTO_SEMGREP_EXECUTABLE=/path/to/semgrep npm run test:integration
```

The integration suite uses the repository's pinned Semgrep rules and real Express
extraction to cover all seven demo CWEs with explicit fixture ownership. Fixed-only
source controls check that safe HTML and parameterized SQL remove injection
hypotheses. Default tests cover grounding, fixed configuration, invalid references,
structured model replies, privacy, cancellation, budgets and core compatibility.
Model transport is mocked; a live external model or browser is not required.

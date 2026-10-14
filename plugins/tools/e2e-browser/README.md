# AgentO Browser Workflow Adapter

`TesterArmyE2EAdapter` implements the core `BrowserWorkflowDriver` with the
[TesterArmy e2e engine](https://github.com/tester-army/e2e), `@e2e-dev/web`, and
Chromium through Playwright. It starts isolated identity contexts, runs trusted
application recipes, reuses verified authentication state, and returns normalized
browser and HTTP evidence. It produces no security signals or vulnerability verdicts.

## Install and verify

Use Node.js **22.22.3 or later in the 22 series, or 24.8.0 or later**. The browser
stack is pinned to `e2e@0.20.0`, `@e2e-dev/web@0.14.0`, and `playwright-core@1.63.0`.
From the repository root:

```sh
npm ci --prefix packages/core
npm run build --prefix packages/core
npm ci --prefix plugins/tools/e2e-browser
cd plugins/tools/e2e-browser
npx playwright-core install chromium
npm run check
```

Linux also needs Chromium's system libraries; on a development machine where
installing OS packages is appropriate, Playwright supplies
`npx playwright-core install-deps chromium`. Browser installation is an explicit
setup step. Workflows do not automatically download browsers or install packages.

`check` typechecks, builds JavaScript/declarations into `dist/`, and runs **25 unit
tests** without launching a browser or target. The **15 opt-in integration tests**
use the real controlled storefront, an in-memory database, ephemeral loopback
ports, and a second local server that must receive zero forbidden requests:

```sh
# From the repository root, install the controlled target's dependencies first.
npm ci --prefix demo-apps/demo-app-01
cd plugins/tools/e2e-browser
npm run check
npm run test:integration
```

Integration covers all three identities, actual UI order API calls, memory and
file session reuse, stale-cookie recovery, rejected credentials, masked screenshots,
the standalone CLI, allowed redirects, and denied redirects, redirect chains,
fetches, popups, frames, automatic navigation, and WebSockets. The suite closes its
servers and browsers and removes its temporary session/screenshot files.

## Demonstrate independently

Start the controlled application in a separate terminal:

```sh
cd demo-apps/demo-app-01
npm start
```

Then run from this package:

```sh
npm run observe -- \
  --url http://127.0.0.1:3000 \
  --allow-origin http://127.0.0.1:3000 \
  --identity alice \
  --goal "Login as Alice and open her newest order."
```

The CLI is deliberately restricted to the local controlled demo and its seeded
test credentials. It prints normalized JSON and exits with `0` on completion,
`1` on workflow failure or refusal, and `2` on invalid CLI arguments. Repeat with
`bob` or `admin` and `--goal "open newest order"`. The seeded UI requests are
`GET /api/orders/102` for Alice, `/201` for Bob, and `/301` for Admin. Observations
include full redacted endpoint URLs, request methods, response status codes,
identity references, and producer/timestamp provenance.

Add `--session-dir .agento-browser` to save state between CLI invocations. This
package ignores that directory; custom storage locations should be outside the
repository. Saved state contains real session credentials. The directory must
have mode `0700`, and files have mode `0600`. Remove it to discard saved sessions.

Pass `--output <file.json>` to write the formatted observation record directly to
a file in addition to stdout.

## Core registration

```ts
import { AgentOOrchestrator } from '@agento/core';
import { TesterArmyE2EAdapter, DEMO_IDENTITIES, demoBrowserOptions } from '@agento/tool-e2e-browser';

const browser = new TesterArmyE2EAdapter(demoBrowserOptions());
const orchestrator = new AgentOOrchestrator({ plugins: [], browser });
const report = await orchestrator.run({
  project: {
    id: 'storefront', name: 'Storefront', mode: 'black-box',
    baseUrl: 'http://127.0.0.1:3000', allowedOrigins: ['http://127.0.0.1:3000'],
    languages: [],
  },
  identities: DEMO_IDENTITIES,
  workflows: [{ id: 'alice-orders', identityId: 'alice', goal: 'open newest order' }],
});
```

Core remains free of browser imports. The adapter uses e2e's public engine
lifecycle, live context, and state restoration APIs; bounded actions use that
context's Playwright surface. AgentO owns the orchestration, policy, and evidence.
The e2e test runner, model agent, trace cache, and raw reports are not invoked.

## Configure another authorized application

Use the library API with trusted backend configuration:

- `resolveGoal(context, workflow)` returns an application-specific action recipe.
  Demo recipes recognize `login as <identity>`, `open orders`, `open newest order`,
  and the matching combined login/order phrases. Unknown goals are refused before
  browser launch. There is no free-form model or script execution.
- `credentials(identity, project)` resolves username/password from your backend
  credential store. Credentials never belong in `AnalysisContext` or frontend data.
- `authentication` declares the login URL, field/submit selectors, expected login
  response, optional success URL, and an identity verification function. Verification
  navigates to an approved JSON endpoint and checks the configured identity field,
  before reuse and after the workflow. Cookies or a successful login status alone
  do not prove the requested identity.
- `runtime` is the adapter-local replaceable browser seam for mocks or another
  implementation. It is not a core contract or a scanner dependency.

Recipes support `navigate`, `fill`, `click`, `wait-url`, and `wait-visible`.
`navigate` and `click` optionally wait for an exact response URL, method, and status;
a trailing `*` on the expected URL matches a prefix. Waiters start before the
action so fast API responses are captured. No arbitrary JavaScript action exists.

`execute(context, plan)` supports the same structured actions. Parameters use
`url`, `selector`, or `value` as appropriate; navigate/click steps may include
`response: { url, method?, status? }`. A single-identity plan selects that
identity automatically; multi-identity steps require `parameters.identityId` from
the plan's declared identities. All steps and URLs are validated before execution.
Contiguous steps for one identity share a context; switching identities opens an
isolated context and can restore its verified snapshot. Unsupported actions or
capabilities produce `SKIPPED`, and execution failures produce `FAILED`.

## Scope, evidence, and session boundaries

`Project.allowedOrigins` must explicitly contain `baseUrl`'s origin. Comparisons
use exact **scheme, hostname, and port**. Wildcards, URL credentials, non-HTTP(S)
schemes, paths in allowlist entries, and implicit same-site/subdomain expansion
are rejected. HTTP requests pass an AgentO route guard; its HTTP client fetches
one hop only and checks redirect destinations. A Chromium request-stage guard
checks subsequent browser redirect hops, including frames, before network dispatch.
Service workers are blocked. Secondary pages/popups, worker requests without a
page frame, and WebSockets are refused because this version supports primary-page
REST workflows. Blocked traffic is recorded, and the workflow fails even if the
main page otherwise finishes. This is an application origin guard, not an OS
network sandbox; broader rate, risk, method, and scanner policies remain separate.

Evidence contains no request/response bodies, headers, cookie values, storage
state, raw exception text, or goal prose. All URL query values, fragments, and
known credential/session values are redacted. Endpoint authentication remains
`unknown` unless associated with existing framework context; observing an
authenticated request does not establish authorization requirements or ownership.
Evidence and observations are deeply frozen with unique IDs for each run.

Default sessions live only in a private `MemorySessionStore`. `FileSessionStore`
is opt-in, with atomic private writes, bounded reads, and validation. Session keys
bind project, base URL, allowed origins, identity, authentication type, and roles.
Snapshots expire after 30 minutes, are checked for approved cookie hosts/storage
origins, and are reverified on reuse. A failed verification deletes the old
snapshot and performs a new login in a fresh context. Use
`browser.forgetSession(project, identity)` for explicit invalidation. The file
store relies on local filesystem permissions and does not encrypt snapshots.

Screenshots are off by default. Opt in with
`screenshot: { directory, maskSelectors }`; all inputs/textareas plus your
application-specific selectors are masked, and screenshot files have mode `0600`.
For the demo, include `#cookie-status-display`. Other visible private content
requires app-specific masks; screenshots cannot provide general text redaction.

Defaults are a 60-second budget per identity workflow, 500 network records,
and at most 100 actions. Options `timeoutMs`, `maxNetworkRecords`, and
`sessionTtlMs` have bounded validation. Timeouts close the browser; truncated
observations fail with an explicit diagnostic. Calls on one adapter are serialized
to avoid session races. Failures return sanitized diagnostics with any collected
evidence and do not declare a finding verdict. The frontend still uses scan fixtures;
this package is a backend capability and standalone demonstration.

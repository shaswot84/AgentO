# AgentO Browser Workflow Adapter

`TesterArmyE2EAdapter` implements core `BrowserWorkflowRuntimeDriver` using
[TesterArmy e2e](https://github.com/tester-army/e2e), `@e2e-dev/web`, and Chromium.
Target profiles supply personas, authentication, approved origins, and workflow
hints. Trusted recipes or workflow orchestration drive the same browser engine;
model calls live in [the optional workflow layer](../../../packages/workflow/README.md).
Results contain normalized, immutable evidence and no vulnerability verdicts.

## Install and verify

Use Node.js **22.22.3 or later in the 22 series, or 24.8.0 or later**.
Dependencies are pinned to `e2e@0.20.0`, `@e2e-dev/web@0.14.0`, and
`playwright-core@1.63.0`. From the repository root:

```sh
npm ci --prefix packages/core
npm run build --prefix packages/core
npm ci --prefix packages/workflow
npm run build --prefix packages/workflow
npm ci --prefix plugins/tools/e2e-browser
npm ci --prefix demo-apps/demo-app-01
cd plugins/tools/e2e-browser
npx playwright-core install chromium
npm run check
npm run test:integration
```

Linux needs Chromium's system libraries; Playwright supplies
`npx playwright-core install-deps chromium` when OS package installation is
appropriate. Workflows never install packages or download browsers themselves.

`check` runs typecheck, build, and **58 unit tests**. The **53 opt-in real-browser
tests** cover the storefront, JWT SPA, portal, edge SPA, and semantic-planning
fixtures on ephemeral loopback ports.
They cover equivalent workflows, all configured personas, private file session
reuse and isolation, stale-state recovery, identity/role mismatch, screenshots,
structured form submission, configured CLI targets, scope escape paths, and
fake-model planning/credential/prompt-injection regressions. A forbidden
server must receive zero requests. Tests remove temporary files and close browsers.

## Try both targets

Start the storefront in a separate terminal with
`npm start --prefix demo-apps/demo-app-01`, then run from this package:

```sh
npm run observe -- --url http://127.0.0.1:3000 \
  --allow-origin http://127.0.0.1:3000 --identity alice \
  --goal "Login as Alice and open her newest order."
```

For the second fixture, start `node test/fixtures/purchases.mjs` from this package:

```sh
npm run observe -- --target purchases --url http://127.0.0.1:3100 \
  --allow-origin http://127.0.0.1:3100 --identity buyer-one \
  --goal "open newest order"
```

For the SSR Multi-Page Portal fixture (`demo-apps/demo-app-03`):

```sh
npm run observe -- --target portal --url http://127.0.0.1:3300 \
  --allow-origin http://127.0.0.1:3300 --identity analyst \
  --goal "open latest report"
```

For the Modern Edge-Case SPA fixture (`demo-apps/demo-app-04`):

```sh
npm run observe -- --target edge-spa --url http://127.0.0.1:3400 \
  --allow-origin http://127.0.0.1:3400 --identity operator \
  --goal "open latest telemetry"
```

The CLI uses local controlled targets and seeded credentials. `--target`
defaults to `storefront`; production targets use the library API. JSON is printed
to stdout; exit codes are `0` for completion, `1` for workflow failure/refusal,
and `2` for invalid arguments. `--output <file.json>` also writes the observation
to disk. `--session-dir .agento-browser` enables private saved sessions between
invocations; this directory is ignored by Git. Custom session directories belong
outside source control.

| Target | Personas | Authentication | Workflow API / Verification |
| --- | --- | --- | --- |
| Storefront (`demo-app-01`) | alice, bob, admin | HTML form and session cookies | `/api/orders/102`, `/201`, `/301` |
| Purchases SPA (`purchases.mjs`) | buyer-one, buyer-two, manager | Distinct form; signed JWT in localStorage; bearer fetches | `/api/v1/purchases/BUY-302`, `/BUY-711`, `/MGR-900` |
| SSR Portal (`demo-app-03`) | analyst, admin | HTML form with CSRF and 302/303 redirect; session cookies | `/reports/REP-501`; server-rendered DOM `#user-display` |
| Edge SPA (`demo-app-04`) | operator, supervisor | Multi-step auth sequence; signed JWT in `sessionStorage` | `/api/telemetry/TEL-900`; `#user-account` |

Fixtures and target profiles live in `src/targets/`; `src/demo.ts` preserves older imports.
Switching target configuration requires no change to `adapter.ts`, `runtime.ts`, or scope enforcement.

### Verified Architectural Scenarios & Boundaries

1. **Multi-Page App (MPA) 302/303 Form Redirects (`demo-app-03`)**: Form login correctly preserves hidden CSRF tokens and tracks 302 redirects to server-rendered dashboards, verified via DOM text matching without JSON APIs.
2. **Multi-Step Authentication (`demo-app-04`)**: Proves that single-step `FormLoginStrategy` cannot complete modern multi-step login flows (e.g. identifier lookup followed by dynamic password reveal). Demonstrates how declarative custom `AuthenticationStrategy` handles multi-step preparation sequences.
3. **`sessionStorage` State Boundary (`demo-app-04`)**: Proves that Playwright's `context.storageState()` does not serialize `window.sessionStorage`. Sessions for SPAs using `sessionStorage` tokens cannot be reused across fresh browser contexts and require re-authentication.
4. **Strict Scope Enforcement (`demo-app-04`)**: Real-time WebSockets (`/escape/websocket`) and unapproved external CDN resources (`/escape/cdn`) are actively intercepted and blocked (`websocket-unsupported`, `origin-scope`), failing the workflow with `scope-denied`.

## Register with core

```ts
import { AgentOOrchestrator } from '@agento/core';
import { TesterArmyE2EAdapter, storefrontBrowserOptions } from '@agento/tool-e2e-browser';

const origin = 'http://127.0.0.1:3000';
const options = storefrontBrowserOptions([origin]);
const browser = new TesterArmyE2EAdapter(options);
const report = await new AgentOOrchestrator({ plugins: [], browser }).run({
  project: {
    id: 'storefront-project', name: 'Storefront', mode: 'black-box',
    baseUrl: origin, allowedOrigins: [origin], languages: [],
  },
  identities: options.target!.personas!,
  workflows: [{ id: 'newest', identityId: 'alice', goal: 'open newest order' }],
});
```

Core exports `TargetApplicationProfile`, `Persona`, `AuthenticationStrategy`,
`BrowserAction`, `BrowserPageInspection`, and `WorkflowPlanner` without importing
browser SDKs. An identity ID selects a configured persona. If the profile omits
personas, the adapter uses discovered context identities. When both declare a
persona, authentication type and roles must agree.

## Optional semantic planning

Wrap this deterministic driver with `BrowserWorkflowOrchestrator` from
`@agento/workflow`; provide a target profile, optional trusted recipe/planner,
`LLMWorkflowPlanner(modelProvider)`, and a deterministic completion predicate where
available. Register the wrapper as core's browser provider. Known recipes can run
with zero model calls; semantic planning can start from the approved project base
URL without a fixture-specific starting route.

`OpenAIModelProvider` lives in a separate optional package and requires a selected
model and backend API-key resolver. [Workflow setup](../../../packages/workflow/README.md)
and [provider setup](../../models/openai/README.md) describe registration and limits.
Ordinary tests use fake model responses and make no paid API calls.

The workflow layer sends bounded, explicitly untrusted page models with opaque
control IDs. Local selectors and native state guards remain private. Each proposal
is validated against the latest page and runtime scope. Credential references need
an explicit policy, are resolved privately, and are rechecked after resolver delay.
Native link clicks preserve query parameters while model URLs stay redacted.
The browser adapter contains no model SDK imports or model API calls.

## Configure an authorized application

Pass trusted backend configuration through `TesterArmyE2EOptions`:

- `target`: profile ID and explicit `baseOrigins`, with optional personas,
  authentication strategies, workflow hints, metadata, and `scope.allowedOrigins`.
  The target allowlist intersects `Project.allowedOrigins`; it cannot broaden it.
- `credentials(persona, project)`: resolve `persona.credentialsRef` through your
  backend credential store. Profiles and core context hold opaque references.
- `FormLoginStrategy`: configurable routes, selectors, response expectations,
  optional success URL, and persona verification. Verification checks either a
  JSON identity path or rendered page selector, with an optional exact role check.
- `StoredSessionStrategy`: verify and reuse an independently provisioned private
  snapshot. Missing, expired, or invalid state is refused when no login is supplied.
  Custom strategies return bounded declarative authentication actions; no SDK
  object or executable script crosses the boundary.
- `resolveGoal(context, workflow)`: optional deterministic recipe. Existing
  `demoBrowserOptions()` and the `authentication` shorthand remain compatible.
- `workflowPlanner.next(input)`: when no recipe resolves, inspect the page, choose
  one action, execute it, and inspect again until the planner reports completion.
  Input contains a bounded visible-control view, persona, goal, target ID/origins,
  workflow hints, and action count; it excludes credentials and authentication
  strategies. The planner must be trusted backend code. Page text is untrusted.

Actions are `navigate`, `fill`, `click`, `submit`, `wait-url`, and `wait-visible`.
`submit` uses standard HTML form submission. Navigate/click/submit can await a
response URL, method, and status; a trailing `*` matches a URL prefix. Every action
is validated before execution. `execute(context, plan)` retains the same safe
structured grammar and preflights the entire plan. Multi-persona steps specify
`parameters.identityId`; each persona runs in an isolated browser context.

## Compatibility contract

Initially supported: Chromium web applications, standard HTML forms, JavaScript
SPAs, configurable personas, session cookies, and JWT-backed web sessions where
the application login stores the token in localStorage and renders a verifiable
identity. HTTP network observations are framework independent. Stored snapshots
and declarative custom authentication provide an extension boundary.

CAPTCHA, passkeys/WebAuthn, complex MFA, enterprise OAuth/SAML/SSO, native mobile
or desktop apps, and arbitrary token/cookie injection are not implemented.
The built-in deterministic planners are fixture examples. Optional semantic planning
requires a configured model provider and trusted target/authentication policy;
workflow completion depends on the visible controls and configured verification.

## Scope, evidence, and sessions

Scope uses exact **scheme, hostname, and port**. Wildcards, credentials in URLs,
non-HTTP(S) schemes, paths in origin entries, and implicit subdomain expansion are
refused. HTTP routing checks destinations before dispatch, including redirect
chains through a Chromium request-stage guard. Service workers are disabled.
Secondary pages/popups, worker requests without a page frame, and WebSockets are
blocked by this single-page HTTP workflow capability. Blocked traffic fails the
workflow, even when the primary page finishes.

Evidence records redacted URLs, origin, method, status, resource type, initiating
page when available, persona, timestamps, and producer/session references. Only
normalized content type and `x-content-type-options: nosniff` response headers
are selected; bodies, authentication headers, cookie values, raw state, errors,
and provider objects are withheld. Query values, fragments, and known credential
and storage values are removed. Page inspection excludes field values and full
HTML; arbitrary visible private text still requires care in a trusted planner.
Observing a request does not establish authorization, resource ownership, or a
security finding.

Private `MemorySessionStore` is the default. Opt-in `FileSessionStore` uses atomic
writes, mode `0700` directories and `0600` files, and bounded validated reads.
Bindings include project, base URL, approved origins, persona, authentication type,
roles, target ID, credential reference, and strategy ID. Snapshots expire after
30 minutes and are verified before reuse and after workflow execution. Failed
verification deletes stale state; an available login starts a fresh context.
Use `browser.forgetSession(project, persona)` to invalidate a matching snapshot;
pass the target as its third argument when orchestration supplies a separate profile.
Snapshots contain credentials and are not encrypted.

Screenshots are off by default. `screenshot: { directory, maskSelectors }` masks
inputs/textareas plus configured selectors and writes mode `0600` files. For the
storefront include `#cookie-status-display`; other visible private content needs
target-specific masks.

Defaults: 60 seconds, 500 network records, and at most 100 workflow actions.
`timeoutMs`, `maxNetworkRecords`, `sessionTtlMs`, and `maxWorkflowActions` have
bounded validation. Nonterminating planners, timeouts, and truncated observations
fail explicitly. Calls on one adapter are serialized. The frontend remains a
separate client with scan fixtures; this package is a backend capability.

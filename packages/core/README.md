# AgentO Core

Tool-independent TypeScript contracts and a small orchestration skeleton. This
package has **no runtime dependencies** and imports no scanner, browser, framework,
model SDK, or remediation tool. Adapters depend on `@agento/core`.

## Run independently

Requires Node.js 22 or later and npm.

```sh
cd packages/core
npm install
npm run check
```

`check` typechecks both the source and typed fakes, builds JavaScript and declarations
to `dist/`, and runs the unit tests. Tests use synthetic data; no application,
credentials, browser, external host, or security tool is needed.

## Public API

Import types and `AgentOOrchestrator` from `@agento/core`. `src/index.ts` exports:

| Contract | Responsibility |
| --- | --- |
| `StaticAnalyzer` | Produce normalized signals and evidence from a supplied project |
| `FrameworkAdapter` | Declare support and extract normalized application structure |
| `BrowserWorkflowDriver` | Observe identity-specific workflows and execute browser plans |
| `TargetApplicationProfile` / `Persona` | Declare target origins, personas, authentication, and workflow hints |
| `AuthenticationStrategy` | Supply persona verification and optional bounded login actions |
| `WorkflowPlanner` | Choose actions iteratively from normalized page inspections |
| `ModelProvider` | Generate bounded structured data through a provider-independent API |
| `PageModel` / `PlannedAction` / `WorkflowHistoryEntry` | Exchange untrusted page data, opaque action references, and bounded progress |
| `BrowserWorkflowRuntimeDriver` | Expose a guarded backend capability session for workflow orchestration |
| `CredentialPolicy` | Authorize persona, destination, and field references before private resolution |
| `SecurityScanner` | Execute a structured plan and return normalized results |
| `CWEPlugin` | Detect candidates, generate tests, and evaluate supplied evidence |
| `ReasoningModel` | Review hypotheses with structured, evidence-referenced output |
| `RemediationProvider` | Suggest fixes and regression tests without applying changes |

Domain types include `Project`, `Component`, `Endpoint`, `Identity`, `Resource`,
`SecuritySignal`, `SecurityHypothesis`, `SecurityTestPlan`, `SecurityTestResult`,
`Evidence`, and `Finding`. Supporting exchange types are also exported.

`WorkflowPlanner` supports separate typed inputs for trusted deterministic recipes
and semantic planning. Semantic planners receive `PageModel`, never native selectors
or browser objects. [The workflow package](../workflow/README.md) implements planner
selection and action validation above [the browser driver](../../plugins/tools/e2e-browser/README.md).
The [optional model adapter](../../plugins/models/openai/README.md) contains API-specific
request/response handling; core imports no model SDK.

Evidence carries producer, timestamp, normalized facts, and optional source,
endpoint, identity, and artifact references. Evidence and domain fields are
readonly at compile time. Adapters must redact sensitive facts and keep raw tool
output and provider session objects private. `Identity.sessionRef` is an opaque
adapter handle, never a credential.

Signals remain observations; hypotheses always have `HYPOTHESIS` status. Tool
outcomes (`COMPLETED`, `FAILED`, `SKIPPED`) are distinct from finding verdicts.
The seven MVP CWE identifiers are exported as `MVP_CWES`; `CWEId` remains extensible
so fake or future plugins do not require an orchestrator change.

## Orchestration skeleton

```ts
import { AgentOOrchestrator } from '@agento/core';
import type { CoreProviders, ScanRequest } from '@agento/core';

async function scan(providers: CoreProviders, request: ScanRequest) {
  return new AgentOOrchestrator(providers).run(request);
}
```

Providers are injected. The skeleton optionally extracts framework structure and
static signals in code-aware mode, runs explicitly requested browser observations,
asks registered plugins for candidates, optionally reviews them through reasoning,
then delegates test generation, execution, and evaluation. A plan selects the
browser or scanner interface and declares capabilities. Missing execution providers
or capabilities produce `SKIPPED`; execution exceptions produce `FAILED` and allow
subsequent plans to continue. Error messages from providers are not forwarded.
Other provider failures and malformed contract output reject the run, making
configuration or contract errors explicit.

The core checks hypothesis/plan/result/finding associations, evidence references,
and duplicate IDs for evidence, hypotheses, plans, and findings. Evidence is
appended without merging; conflicting IDs fail rather than overwrite provenance.
Remediation runs only when explicitly requested and only for confirmed findings.
`test/fakes.ts` implements all seven interfaces, and `test/orchestrator.test.ts`
demonstrates the complete wiring with mocks, including tool replacement and a fake
CWE outside the MVP set.

## Boundaries

This is an architecture demonstration, **not a production scanning entry point**.
The core itself treats `allowedOrigins` as declared scope. The implemented
[browser adapter](../../plugins/tools/e2e-browser/README.md) enforces exact origins
for its browser workflows and returns normalized evidence through these contracts.
CWE detection rules live in [the independent rule package](../../plugins/cwe/README.md).
That package implements the existing plugin lifecycle without changing this orchestrator.
Repository discovery and mode selection
are available in [the discovery package](../discovery/README.md). Endpoint merging, capability
selection across multiple tools, cross-tool policy enforcement, runtime evidence
immutability/storage/redaction, and substantive verification remain later phases.
The skeleton requires evidence for a confirmed finding, but the injected evaluator
is responsible for the verdict; this phase does not prove vulnerability validity.

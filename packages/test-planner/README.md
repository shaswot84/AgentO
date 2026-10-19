# Security test planner

`@agento/test-planner` converts evidence-linked hypotheses into immutable JSON test
plans for all seven supported CWEs. Plans declare a probe, capabilities, identities,
request inputs, ordered actions and structured verification criteria.

## Setup

Use Node.js 22.22.3 or a supported newer release. Install and build `packages/core`,
`packages/runtime` and `packages/security-model`, in that order. For the tests,
also install and build `plugins/cwe` and `packages/hypothesis-engine` and their
development dependencies. Then run here:

```sh
npm ci
npm run check
```

The planner has no transport or tool dependencies. Tests use synthetic application
observations, hypothesis generation and injected providers.

## Create a plan

Use the same configured CWE plugins that produced the hypotheses. Application
policy belongs in those rules: sensitive cookie names, explicitly untrusted
origins, and resource/owner/attacker access policies must be declared rather than
guessed from labels or successful HTTP responses.

```ts
import { SecurityTestPlanner } from '@agento/test-planner';

const planner = new SecurityTestPlanner({ plugins: registeredRules });
const result = await planner.plan(applicationModel, hypothesis, {
  inputs: [
    { name: 'id', location: 'path', valueRef: 'owner-order-key' },
  ],
});

for (const plan of result.plans) {
  console.log(plan.probeId, plan.readiness, plan.prerequisites);
  // Serialize the plan; resolve private input references only in the execution host.
}
```

Accepts `ApplicationSecurityModel` or a flat core `AnalysisContext`. Hypotheses
must reference a known endpoint and relevant project evidence. Original rule plan
IDs are preserved so collected results remain compatible with `evaluateEvidence`.
Added hypothesis fields cannot override the target or the rule's policy.

`inputs` contains opaque references, never parameter values. Every path placeholder,
required request parameter and tested injection parameter needs a binding. An
optional injection parameter still needs a baseline value. For body injection,
declare `bodyEncoding: 'json-body'` or `'form-body'`; the execution host maps the
generic body parameter to the probe's corresponding input location.

`identityId` may narrow the rule's selected identities for non-authorization
collection. `allowAnonymous: true` records an explicit anonymous choice when an
endpoint's authentication requirement is unknown. Neither option overrides a
declared authentication or role requirement.

## Plans and prerequisites

| CWE | Probe | Verification observations |
| --- | --- | --- |
| 639 | `authorization` | Successful owner baseline; forbidden identity receives owner-marked content or is denied |
| 862 | `authorization` | The same resource requested as owner, attacker and anonymous; compare declared forbidden controls |
| 942 | `cross-origin` | Preflight plus actual response headers for explicitly untrusted origins |
| 1004 | `cookie-security` | Applicable, live, declared sensitive cookies and their `HttpOnly` attributes |
| 614 | `cookie-security` | The same cookie checks for `Secure`, in an HTTPS context |
| 79 | `xss` | Baseline, injected canary and attributed execution or DOM-sink observations |
| 89 | `sql-injection` | Successful baseline, syntax mutation and balanced boolean controls |

Steps have stable IDs, typed actions, structured parameters, explicit predecessor
dependencies and an inconclusive failure transition. The final `verify` action
references the plan's typed criteria and delegates the verdict to the CWE rule.
Missing execution observations never become a secure result. Reflection alone
does not establish XSS; timing changes alone do not establish SQL injection.
Credentialed wildcard CORS responses establish configuration risk; browser data
disclosure requires separate proof.

`READY` means planning prerequisites are present. `BLOCKED` drafts expose missing
inputs, access policy, distinct authenticated principals, evidence of ownership,
cookie sensitivity, untrusted origins or HTTPS context. Required capabilities use
the runtime's existing names, such as `request-executor`,
`authentication-manager` and `response-comparator`, plus `probe:<id>`. Optional
browser/scanner ports are listed separately. All plans conservatively declare
active risk because authentication and requests can change application state.

## Core integration and boundaries

Pass the planner as `testPlanner` to `AgentOOrchestrator`, alongside the same
plugins. The core calls `generateTests(context, hypothesis)`, which returns only
ready plans. The original plugin planning path remains available when the optional
provider is absent. Use `plan()` to inspect blocked drafts and diagnostics.

For targets needing private inputs, supply an application-specific `TestPlanner`
wrapper that calls `plan()` with trusted bindings and returns only ready plans.
The default core method supplies no bindings and therefore withholds those drafts.

Readiness does not approve execution, check installed tools or enforce runtime
scope. Hosts must resolve input references privately, validate the resulting exact
origin and request, enforce execution policy, and explicitly provide probe-capable
execution providers. A URL with placeholders is a template, not a finished request.
Plans contain no session handles, cookie values, resource keys, raw evidence or
source bodies. Treat them as backend planning data, not sanitized public reports.

Pass a ready plan to the [capability registry](../capability-registry/README.md)
to select available adapter ports. Selection does not execute the plan or approve
requests; the execution host must still enforce its policy and scope limits.

The planner makes no network requests, establishes no sessions, collects no proof
and produces no findings. It does not select vendor adapters, schedule execution
or integrate the frontend. Unsupported methods, invalid associations and provider
failures return sanitized diagnostics. Each invocation returns at most 64 plans
by default; configure `maxPlans` from 1 to 1,000. A `plan-limit` diagnostic signals
partial coverage. Trusted rule plugins own their planning callback lifetime.

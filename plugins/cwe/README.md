# CWE rules

Seven independently registered rules interpret normalized probe evidence. Rules
contain no HTTP, browser, authentication, scanner invocation or cookie parsing.
They produce candidates, declarative probe plans and evidence-linked verdicts.

## Setup and verification

Requires Node.js 22.22.3 or later supported by the package. Local dependencies are
`@agento/core`, `@agento/runtime` and `@agento/security-model`; rebuild their `dist/`
outputs in that order after changing their source.

```sh
cd plugins/cwe
npm ci
npm run check
npm run test:integration
```

The default suite uses synthetic normalized observations and a fake execution
provider. Integration tests open a temporary loopback HTTP server, collect all
five probe families and compare vulnerable/fixed behavior. They use test identity
headers, no browser or concrete scanner. HTTPS cookie semantics and XSS execution
proof are covered with normalized fixtures; the HTTP integration cannot establish
either. Optional scanner absence remains visible as partial coverage.

## Register and plan

```ts
import { CWE1004Plugin, CWE614Plugin, CWEPluginRegistry } from '@agento/cwe';
import type { ApplicationSecurityModel } from '@agento/security-model';

async function plan(model: ApplicationSecurityModel) {
  const policy = { sensitiveCookieNames: ['auth_token'] };
  const registry = new CWEPluginRegistry()
    .register(new CWE1004Plugin(policy))
    .register(new CWE614Plugin(policy));
  const plugin = registry.get('CWE-1004');
  const hypotheses = await plugin.detectCandidates(model);
  return Promise.all(hypotheses.map(hypothesis => plugin.generateTests(model, hypothesis)));
}
```

Each class implements the existing core `CWEPlugin` lifecycle, plus `metadata()`
and direct `evaluate(evidence, scope)`. Concrete classes also accept
`generateTests(hypothesis)` for their enriched `CWEHypothesis` output. The
context-based form reconstructs scope and policy from current application facts.
The registry accepts custom implementations; adding a new CWE does not require
editing core or probe code. `EvidenceCWEPlugin` supplies the shared lifecycle for
rules using an existing probe family.

Detection accepts the full application model or the core analysis context.
It uses endpoint-bound signals, ownership, parameters and configuration; facts
remain candidate context. Exact origins, canonical endpoint aliases and evidence
references are preserved. SQL checks require a signal, database observation or
matching data-flow fact. Parameterless signals remain hypotheses with no runnable
injection plan. Cookie sensitivity comes from explicit policy or a cookie model
fact with `sensitive: true`; the rule does not infer it from a cookie name.

Plans declare `probeId`, `scope` and capability names, with no vendor, payload or
selector. Existing core uses its generic `scanner` execution port for these plans;
a host must explicitly provide a compatible probe execution provider. Absent
providers yield `SKIPPED` and an unconfirmed verdict. This package does not wire
runtime execution into the frontend or implement scheduling. Current collection
supports read methods for cookie/CORS/authorization and GET/POST for injection;
unsupported methods receive no executable plan. Hosts must bind concrete resource
URLs, request bodies, personas and optional capabilities before collecting probes.
Cookie rules can consume the same collected record without repeating the probe.
Authenticated collection declares identity IDs and the additional authentication
and cookie-inspection capabilities it needs.

## Evaluate collected observations

```ts
import { CWE1004Plugin } from '@agento/cwe';
import type { CookieSecurityEvidence } from '@agento/runtime';

async function assess(evidence: CookieSecurityEvidence) {
  return new CWE1004Plugin().evaluate([evidence], {
    projectId: evidence.projectId,
    targetUrl: 'https://shop.example/account',
    method: 'GET',
    sensitiveCookieNames: ['auth_token'],
  });
}
```

The evaluation scope is trusted application policy. Injection scopes include the
parameter name and query/body location. CORS scopes declare `untrustedOrigins`.
Authorization scopes require the resource ID, owner/attacker IDs, and explicit
`attackerIsUnauthorized` / `anonymousIsUnauthorized` expectations. Constructor
options supply policy to detected hypotheses; direct evaluation takes its policy
from the supplied scope. Resource ownership alone does not establish that sharing
is forbidden.

| Rule | Evidence | Confirmation requirement |
| --- | --- | --- |
| `CWE79Plugin` | `XSSEvidence` | Attributable script execution; reflection or a sink hint alone is insufficient |
| `CWE89Plugin` | `SQLInjectionEvidence` | Database-specific error after a successful baseline, or baseline-preserving true and differing false controls |
| `CWE639Plugin` | `AuthorizationEvidence` | Forbidden second identity receives complete owner-marker content for the same resource |
| `CWE862Plugin` | `AuthorizationEvidence` | Forbidden anonymous or unprivileged identity receives the protected owner-marker content |
| `CWE942Plugin` | `CrossOriginEvidence` | Authenticated response permits an explicitly untrusted origin with credentials, or declares wildcard plus credentials |
| `CWE1004Plugin` | `CookieSecurityEvidence` | Applicable, live, declared sensitive cookie lacks `HttpOnly` |
| `CWE614Plugin` | `CookieSecurityEvidence` | Same cookie requirement, observed in HTTPS context, lacking `Secure` |

The wildcard CORS verdict confirms configuration only. Browsers reject credentialed
wildcard reads; this record does not establish data disclosure. See
[MDN's credentialed CORS explanation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS/Errors/CORSNotSupportingCredentials).
The taxonomy follows [MITRE CWE](https://cwe.mitre.org/); OWASP metadata uses the
2025 category identifiers.

`CONFIRMED` requires positive observations. `REJECTED` requires completed negative
checks in the relevant scope. `NOT_REPRODUCED` covers missing evidence, incomplete
checks, unrelated targets and unestablished policy. Positive direct proof may
survive unrelated partial collection; missing optional scanners cannot become
negative proof. Generic SQL errors, timing deltas and equal authorization response
bodies are insufficient. Verdicts include referenced evidence IDs and limitations.

## Core evidence bridge

`toCoreEvidence(probe, endpointId)` creates an immutable core evidence envelope
with an explicit public projection, redacted query values and no raw headers,
cookie values or response bodies. `fromCoreEvidence` validates its schema and
matching provenance. The core lifecycle consumes only completed, correctly bound
result records; static configuration, failed/skipped execution and unrelated plans
cannot confirm a finding. Conflicting duplicate evidence IDs are excluded.

Callers must supply trusted observations and identity policy. Schema validation
does not authenticate an imported JSON record or create cryptographic provenance.
Persistence, execution scheduling and a broader verification judge are separate
host responsibilities.

### SQL responses with reflected inputs

CWE-89 also accepts `projectedControls` from a trusted probe context with a declared
JSON result pointer. A successful, complete baseline and true control must have
matching result-field hashes, while the false control must differ. Original
response hashes remain in the evidence. These fields do not promote scanner
claims or generic error messages to proof. The host must select application result
data; see the [injection assessment limits](../../packages/a05/README.md#proof-and-limits).

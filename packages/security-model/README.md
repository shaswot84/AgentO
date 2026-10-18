# Application Security Model

`@agento/security-model` merges normalized source, browser, and runtime knowledge
into one immutable, JSON-serializable `ApplicationSecurityModel`. It executes no
target requests and produces no vulnerability verdicts.

## Setup and checks

Use Node.js 22.22.3 or a compatible newer release. Build the local dependencies
first, then install and check this package:

```sh
(cd packages/core && npm ci && npm run build)
(cd packages/runtime && npm ci && npm run build)
(cd plugins/frameworks/express && npm ci && npm run build)
cd packages/security-model
npm ci
npm run check
```

The Express dependency is used only by integration tests. Production source
imports core contracts and public runtime projection types; framework and tool
implementations stay outside this package.

## Assemble observations

```ts
import {
  buildApplicationSecurityModel, fromFrameworkAnalysis, fromStaticAnalysis,
  fromBrowserObservation, fromRuntimeSnapshot, resolveEndpoint,
} from '@agento/security-model';

// project, identities and providers come from the caller's configuration.
const framework = await frameworkAdapter.extract(project);
const initial = buildApplicationSecurityModel({ project, identities,
  contributions: [fromFrameworkAnalysis(framework)] });
const browser = await browserDriver.observe(initial, workflow);
const analysis = await staticAnalyzer.analyze(project);

const model = buildApplicationSecurityModel({ project, identities, contributions: [
  fromFrameworkAnalysis(framework),
  fromStaticAnalysis(analysis),
  fromBrowserObservation(browser),
  fromRuntimeSnapshot(project, {
    producerId: 'backend-runtime', capturedAt: response.timings.startedAt,
    responses: [responseCollector.evidence(response)],
    headers: [await headerAnalyzer.analyze(response)],
    cookies: await cookieAnalyzer.analyze(response),
  }),
] });

const order = resolveEndpoint(model, framework.endpoints[0]!.id);
```

The model extends core `AnalysisContext`, so existing provider and plugin
interfaces can consume it directly. The core orchestrator continues to expose its
existing flat context; callers assemble this richer model explicitly.
`fromAnalysisContext(context)` also accepts an existing context, labelling its
mixed observations `declared` because their original ingestion channels are
unavailable. Preserve separate contributions when channel provenance matters.

## Model contents

| Collection | Contents |
| --- | --- |
| `components`, `endpoints`, `parameters` | Application parts, canonical routes, parameter locations and requirements |
| `identities`, `userRoles`, `authenticationRequirements` | Caller-supplied identities, role associations, individual authentication claims |
| `resources`, `resourceTypes`, `observedOwnership` | Resource declarations and explicitly evidenced ownership observations |
| `sourceHandlers`, `dataFlows`, `databaseOperations` | Handler locations, source/sink candidates and database metadata |
| `cookies`, `corsConfigurations` | Separate configuration observations, including conditional and dynamic values |
| `evidence`, `runtimeObservations`, `signals` | Original evidence, runtime observations and candidate signals |
| `endpointAliases`, `diagnostics` | Provider-ID lookup and unresolved/conflicting claims |

Each projected fact carries its knowledge source, canonical endpoint references,
original evidence IDs, and normalized `details`. Existing normalized observation
names such as `database-operation`, `cookie`, `cors`, and `static-candidate`
populate these views. Other adapters can supply `ModelContribution.facts` with
the same framework-neutral fact kinds. Unknown details remain in original
evidence; this model does not parse framework syntax or infer missing defaults.

## Merge and provenance rules

- Endpoint identity includes project, exact origin, HTTP method and path. Relative
  source paths bind to the project's base origin; observed HTTP evidence and
  `endpointOrigins` can bind other contributions explicitly.
- Query values and fragments do not identify routes. Simple `:id` and `{id}`
  segments match concrete observed paths only when one template fits. A declared
  literal route takes precedence. Ambiguous observations remain separate with a
  diagnostic. Optional, wildcard, and regex syntax is kept opaque.
- Duplicate provider routes combine parameters, roles, evidence and aliases.
  Distinct origins/methods remain separate. All original endpoint observations
  and source handlers remain available.
- Evidence objects retain their original producer, timestamp, source location,
  endpoint ID, identity and facts. `resolveEndpoint` follows aliases without
  rewriting those evidence objects. Resource and signal endpoint links use
  canonical IDs.
- Conflicting authentication claims summarize as `unknown`; individual claims
  remain available. Parameter requiredness is `null` when declarations disagree
  or only runtime presence is known. Core-compatible endpoint parameters use
  `false` for unknown requiredness; use `model.parameters` for that distinction.
- Identity/session observations do not establish endpoint authentication
  requirements or resource ownership. Ownership requires explicit resource and
  identity association supported by evidence; competing owners are retained with
  diagnostics. Static source/sink observations remain candidates with their
  original resolution and conditional metadata.
- Identical evidence IDs deduplicate; different payloads sharing an evidence ID,
  cross-project entities, ambiguous provider IDs and dangling references fail
  assembly. Output is detached and deeply frozen; caller inputs remain mutable.

## Runtime boundary and limits

`fromRuntimeSnapshot` accepts only public `HttpResponseEvidence`, `HeaderEvidence`,
`CookieEvidence`, and `NetworkEvidence` projections. It excludes raw HTTP bodies,
freeform headers and private session state, forces cookie values to `[REDACTED]`,
and removes URL credentials/fragments while replacing query values. Only completed,
unblocked network records create endpoints. CORS and cookies retain their public
metadata without policy evaluation. Runtime response IDs must identify one
consistent response within a snapshot.

Source and browser adapters must supply their existing redacted `Evidence`
contracts. Arbitrary text in caller-provided evidence is preserved, so this
package is not a general secret scrubber. Resource keys and identity IDs are also
caller-supplied public identifiers. No live browser or scanner is needed for the
checks: integration tests use actual demo source extraction and normalized
browser/runtime observations.

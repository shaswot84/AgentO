# Verification judge

`@agento/verifier` binds existing CWE rules to immutable evidence and completed
probe results. It correlates the original source suspicion with retained runtime
proof. A static signal, scanner verdict, HTTP 200, or model assertion cannot
confirm a vulnerability by itself.

## Setup

Use Node.js 22.22.3 or a supported newer version. Install and build these packages
in order: `packages/core`, `packages/runtime`, `packages/security-model`,
`plugins/cwe`, and `packages/evidence`. Each package provides `npm ci` and
`npm run build`. Then:

```sh
cd packages/verifier
npm ci
npm run check
npm run test:integration
```

The optional integration command also needs the installed dependencies of
`demo-apps/demo-app-01` and OpenSSL. It starts only a loopback HTTPS server,
creates a temporary certificate and in-memory database, and removes its temporary
files. It requires no browser, model service, or scanner executable.

## Core integration

```ts
import { AgentOOrchestrator } from '@agento/core';
import { CWE614Plugin } from '@agento/cwe';
import { FileEvidenceStore } from '@agento/evidence';
import { VerificationJudge } from '@agento/verifier';

const plugins = [new CWE614Plugin({ sensitiveCookieNames: ['auth_token'] })];
const evidenceStore = new FileEvidenceStore('/private/agento/run-123');
const verifier = new VerificationJudge({ plugins, evidenceStore });
try {
  const report = await new AgentOOrchestrator({
    ...executionProviders, plugins, evidenceStore, verifier,
  }).run(request);
  // executionProviders must explicitly provide discovery/source and probe execution.
  // Export a finding with evidenceStore.exportFinding(report.findings[0]).
} finally {
  evidenceStore.close();
}
```

Use the same configured rules for hypotheses, planning, and verification. Hosts
supply sensitivity declarations, untrusted origins, and resource/identity access
policies through the existing rule options. Inject the same store into core and
the judge; plain, unretained evidence is rejected. Core's default capture uses the
`default` environment. A host that captures evidence directly can set a distinct
`environmentId` both during capture and in the judge options. Use a separate store
for each run; a store/environment label does not establish evidence freshness.

For a direct or offline decision, call
`judge.judge({ context, hypothesis, plans, results }, optionalModelAssessment)`.
Context and result evidence must contain the exact records returned by capture
or restored from the journal. `judge.verify(context, hypothesis, plans, results)`
returns only the `Finding` and implements core's `VerificationEngine` port.

## Decision rules

- Recompute record integrity and resolve every context and hypothesis reference.
  Wrong projects, missing records, changed content, and duplicate context IDs
  reject the decision with a fixed error code.
- Rebind the hypothesis through its CWE rule. Check plan identity, target origin
  and path, identities, and required capabilities. Only completed results without
  execution errors can contribute runtime proof.
- Accept normalized probe records for the expected probe, endpoint, environment,
  plan target, and capabilities. Every recorded response must match the planned
  path. Query values stay private. Duplicate results, repeated proof IDs, scanner
  claims, and malformed observations do not count as proof.
- Delegate security interpretation to the existing CWE evaluator. XSS needs
  attributable execution; SQL injection needs database-specific error or valid
  controlled comparisons; authorization needs a policy and owner markers. The
  judge contains no HTTP execution or vulnerability payloads.
- Conflicting positive and safe observations in the same environment produce
  `NOT_REPRODUCED`. Safe runtime controls also produce `NOT_REPRODUCED`, preserving
  the original static suspicion and runtime evidence together. Missing, skipped,
  failed, and insufficient tests stay unconfirmed with low confidence.

A probe with partial coverage can still supply sufficient direct positive proof
under its CWE rule. Missing optional scanners or browsers never supply negative
proof. `NOT_REPRODUCED` describes the available investigation; it does not assert
that the target is secure. Decisions include sorted evidence IDs and diagnostics,
and the result is deeply frozen. Retained context, plans, and results allow the
same judgment after reopening the evidence journal, without rerunning tools.

## Optional model claims

A host may pass a structured model explanation:

```json
{
  "status": "CONFIRMED",
  "claims": [
    { "text": "The observed cookie lacks Secure.", "evidenceIds": ["probe-record-id"] }
  ]
}
```

Every claim needs at least one unique evidence ID used in this decision. Unknown,
unrelated, missing, or uncited IDs reject the whole explanation. Extra free-form
fields and disagreement with the deterministic verdict are also rejected. The
schema permits at most 32 claims and 4,000 characters per claim. Rejection adds
`model-assessment-rejected`; it never changes the deterministic finding.

Citation validation establishes traceability, not the truth of arbitrary prose.
Treat accepted model text as an untrusted explanation. It cannot supply proof,
promote a verdict, execute actions, or override a rule. This package makes no
model calls; hosts provide already generated, public, structured explanations.

## Verification scope

Unit tests cover all seven CWEs, positive and static-only cases, failed/skipped
execution, bad lineage, altered records, conflicting observations, scanner-only
claims, generic SQL errors, and model citation checks. Core tests cover delegation
before remediation and invalid verifier output.

The real storefront integration tests all seven CWEs in vulnerable and fixed
modes over certificate-validated loopback TLS, including real login sessions and
cookie attributes. Fixed mode produces zero confirmed findings. Vulnerable mode
confirms both access-control cases, CORS, and both cookie attributes. XSS remains
unconfirmed without execution evidence. This demo's SQL response exposes a generic
syntax error and reflects queries, so it does not satisfy the existing SQL rule's
fingerprint or controlled-comparison requirements. Valid SQL proof is covered by
deterministic fixtures. Every demo decision is replayed after journal reopen.

The store and host remain trusted capture boundaries. Hashes detect changed
content; they do not authenticate a producer or prove that a probe ran. This
package does not schedule executions, configure frontend runtime testing, apply
fixes, or generate reports.

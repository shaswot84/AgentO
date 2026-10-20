# A01 access control assessment

`@agento/a01` runs selected CWE-639 (IDOR) and CWE-862 (missing authorization)
investigations through the existing discovery, model, hypothesis, planning,
runtime, policy, evidence, and verification packages.

Each test logs in the authorized owner and a forbidden second identity in
separate Chromium contexts. Their session cookies stay in separate HTTP jars.
The authorization probe requests the same resource as the owner, the attacker,
and an anonymous client. The CWE rules require successful, complete responses
with matching private resource markers before they confirm disclosure. HTTP 200
or equal response bodies alone do not establish a vulnerability. Fixed controls
that deny forbidden access produce `NOT_REPRODUCED` through the verification judge.

## Setup and checks

Use Node.js 22.22.3 or a supported newer version. Run `npm ci` and `npm run build`
in these directories, in order:

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
packages/a01
```

Install Noir with `npm run setup:noir --prefix plugins/frameworks/express` from
the repository root after dependency setup. The default source adapter uses Noir
inventory and AgentO validation; unvalidated routes cannot drive assessments.
See [endpoint discovery setup](../../plugins/frameworks/express/README.md).

Install the [Chromium runtime](../../plugins/tools/e2e-browser/README.md) and
the demo application's dependencies for live tests. No scanner or model service
is required.

```sh
cd packages/a01
npm run check
npm run test:integration
```

Unit tests cover access policies, private input validation, source role
requirements, failure handling, request budgets, redaction, and stored-proof
replay. Live tests run the actual storefront twice in each security mode. They
check independent owner and attacker cookies, anonymous requests, both verdicts,
retained proof, and the built CLI.

## CLI

Start an authorized target. Copy [the example](examples/storefront.json) to a
private location and configure its repository path, exact origin, accounts,
login selectors, access policies, and resource markers. Relative paths resolve
beside that configuration file. Choose fresh proof and output paths.

Supply each account's username and password through the environment variables
named in `accounts`. The CLI verifies the logged-in identity and role through
the configured JSON endpoint before it transfers cookies. Passwords, cookie
values, and resource markers are excluded from reports and retained proof.
Concrete resource URL paths are visible in proof; use public, opaque resource
IDs and do not place secrets in paths.

```sh
node packages/a01/dist/cli.js /private/a01-scan.json
```

The example permits active tests with empty approval risk and severity lists.
Omit `approval` to keep the policy engine's default approval requirement. The
runner then skips the plans. This runner does not issue approval tokens.
`a01-http` controls anonymous requests and response processing. `a01-auth`
controls browser login, verification, and authenticated HTTP requests. Both
tools share the execution request budget; include GET and POST in the policy
when the login form uses POST.

The command refuses existing proof journals and report files, writes the report
with mode `0600`, and returns `0` for complete execution, `2` for incomplete
coverage or execution, and `1` for invalid configuration or scan errors.

## API

```ts
import { runA01Scan } from '@agento/a01';
import { FileEvidenceStore } from '@agento/evidence';

const store = new FileEvidenceStore('/private/fresh-a01-proof');
try {
  const report = await runA01Scan({
    project, targets, policy, evidenceStore: store,
    target: applicationProfile,
    credentials: async persona => privateCredentialStore.load(persona.credentialsRef),
  });
  console.log(report.findings);
} finally {
  store.close();
}
```

`target` is the existing `TargetApplicationProfile`, with session-cookie personas
and trusted authentication strategies. `credentials` is a private host callback.
For another browser provider, inject `browserDriver` or a guarded `browser`
controller. There is no vendor logic in the probe, model, or CWE rules.

Each target declares a source GET route, an opaque `resourceId`, two distinct
identities, forbidden access controls, private `ownerMarkers`, and any `pathValues`
for ordinary `:name` segments. The host's expected owner is recorded as declared
knowledge in the model; it is not a runtime ownership discovery claim. The
authorized response supplies the runtime content baseline. Markers must identify
private content of that exact object or privileged response, rather than generic
success text. Access policy errors or weak markers can invalidate the assessment.

The runner tests only selected GET routes and supplied resource keys. It does
not enumerate objects, infer ownership from an ID, test state-changing privileged
actions, or discover credentials. Missing source support, failed authentication,
partial responses, and denied execution cannot confirm a finding. Results apply
to the supplied resources and environment. Stored decisions can be replayed with
the same access policies through `VerificationJudge` without contacting the target.

# A02 assessment

`@agento/a02` runs the complete cookie and CORS investigation for CWE-1004,
CWE-614 and CWE-942:

```text
repository discovery → application model → hypotheses → test plans
→ capability selection → execution policy → probes → evidence store
→ deterministic verification → JSON report
```

The existing CWE plugins own all security decisions. A cookie collection runs
once per matching endpoint, method, identity set and capability set within one
scan. Both cookie rules use the same retained evidence ID with their own plan
and result links. Collections never carry over to another scan.

## Setup and checks

Use Node.js 22.22.3 or a supported newer version. Run `npm ci` and
`npm run build` in these directories, in order:

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
packages/a02
```

Then run in `packages/a02`:

```sh
npm run check
npm run test:integration
```

The optional integration suite also requires the installed dependencies of
`demo-apps/demo-app-01` and OpenSSL. It discovers the actual storefront source,
starts certificate-validated loopback HTTPS with an in-memory database, logs in,
and runs both vulnerable and fixed modes. Vulnerable mode confirms all three
CWEs; fixed mode confirms none. No browser, scanner executable, or model service
is needed at runtime. Unit tests also reopen the evidence journal and replay the
same decisions without target access.

## Run a scan

Copy [the JSON example](examples/storefront.json) to a private location. Set the
repository path, live HTTPS base URL and exact allowed origin. Repository paths
and output paths resolve beside the configuration file. The example's relative
repository path assumes the file stays in its original directory.

Supply login fields through the named environment variables, then run from the
repository root:

```sh
export AGENTO_A02_USERNAME=alice
read -rs AGENTO_A02_PASSWORD
export AGENTO_A02_PASSWORD
node packages/a02/dist/cli.js packages/a02/examples/storefront.json
```

For a private certificate authority, use Node's `NODE_EXTRA_CA_CERTS` setting.
Keep TLS certificate validation enabled. The target must already be running;
the CLI never starts or modifies it. Use a fresh evidence directory and report
filename for every run. The CLI refuses to append to an existing evidence journal
or overwrite a report. Reports use file mode `0600`.

The example explicitly permits active testing for its selected target by setting
empty approval risk/severity lists. Scope, method, tool, rate and request limits
still apply. Remove the `approval` field to retain the policy engine's default
approval requirement; these plans then appear as skipped with `approval-required`.
This runner never issues an approval token. Its process exit codes are `0` for
completed investigations, `2` for incomplete coverage/execution, and `1` for a
configuration or scan failure. A confirmed finding does not itself cause an error
exit code.

## API

```ts
import { runA02Scan, HttpCookieAuthenticationManager } from '@agento/a02';
import { FileEvidenceStore } from '@agento/evidence';
import { DeterministicRequestExecutor } from '@agento/runtime';

const executor = new DeterministicRequestExecutor({
  baseUrl: project.baseUrl, allowedOrigins: project.allowedOrigins,
});
const authentication = new HttpCookieAuthenticationManager({
  executor,
  login: async identity => resolvePrivateLoginRequest(identity),
});
const evidenceStore = new FileEvidenceStore('/private/run-123/evidence', {
  expectedHeadDigest: null,
});
try {
  const report = await runA02Scan({
    project, paths: ['/api/auth/me'], identities,
    sensitiveCookieNames: ['auth_token'],
    untrustedOrigins: ['https://unapproved.invalid'],
    authentication, evidenceStore,
    policy: {
      allowedOrigins: project.allowedOrigins,
      allowedMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
      tools: { 'a02-http': {}, 'a02-auth': {} },
      approval: { risks: [], severities: [] }, // Explicit host authorization.
    },
  });
  for (const decision of report.decisions) {
    const proof = evidenceStore.exportFinding(decision.finding);
    // Render the verdict with its staticEvidenceIds, runtimeEvidenceIds and proof.
  }
} finally {
  evidenceStore.close();
  await authentication.close();
}
```

`project.repositoryPath` is required. Discovery must find a supported source
adapter. Express is provided by default; hosts may inject an existing
`FrameworkAdapter`. Only explicitly selected, discovered, literal `GET` routes
are eligible, with at most 32 paths and 10 identities. Private parameter binding,
route templates and mutation endpoints are outside this runner's scope.
For an unknown authentication requirement without identities, the host must
explicitly set `allowAnonymous: true`. An authentication requirement or role
declaration still blocks an anonymous plan.

The optional HTTP login adapter supports same-origin `POST` logins that return
cookies. It uses the runtime's bounded cookie jar, keeps cookies private, creates
fresh sessions for each guarded execution, and closes them afterwards. Login
requests count against policy limits and need explicit `POST` permission. It has
no redirect login, bearer-token, browser, MFA, or CSRF form workflow. Hosts can
instead inject an existing guarded `AuthenticationManager`, including the runtime
browser session manager. Credential callbacks must honor the execution lifetime.

## Read the report

- `hypotheses` and `plans` retain the original evidence and rule plan IDs.
- `executions` identifies a shared collection, reuse, failure, or skipped plan.
- `results` binds normalized records to each plan; shared records are retained
  only once in `context.evidence`.
- `decisions` links each verdict to both source observations and runtime proof.
  Every finding evidence ID resolves in `context.evidence`.
- `diagnostics` exposes missing policy declarations, absent source hypotheses
  and incomplete discovery/model/planning coverage. `audit` records policy effects.

Use the same rule options and retained context/plans/results with
`VerificationJudge` to replay a decision after reopening a file store. The caller
owns an injected store; an omitted store uses memory only for that invocation.

Missing proof, failed login, unavailable capabilities, policy denial, cancelled
work and blocked plans cannot confirm a finding. `NOT_REPRODUCED` describes the
tested observations, not a claim that the application is secure. A route without
a grounded hypothesis is listed through a diagnostic, not reported as secure.
The Secure-cookie check requires HTTPS. CORS checks establish response-policy
configuration; they do not demonstrate browser data disclosure.

JSON includes normalized, redacted evidence and body hashes, never raw response
bodies, login requests or cookie values. Configuration, source adapters, capture
stores and injected ports remain trusted host inputs; this report is not a general
sanitizer for arbitrary caller-supplied text. Keep reports private as source
locations and application configuration can be sensitive. This package provides
the bounded backend/CLI assessment; frontend scheduling and general report formats
are separate work.

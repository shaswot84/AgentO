# Express remediation

`@agento/remediation` implements the core `RemediationProvider` interface. It
returns a root-cause explanation, an applicable unified diff, and an automated
security regression test for a supplied **confirmed** finding. Generation reads
host-supplied source snapshots and retained evidence. It has no file, Git,
network, execution, or verification port.

## Supported repairs

The initial reviewed catalog supports the current TypeScript Express storefront
in `demo-apps/demo-app-01`. Each recipe checks the complete source revision,
endpoint, and HTTP method. This is a bounded template provider; arbitrary Express
applications, JavaScript variants, other source revisions, and black-box findings
are refused with fixed error codes. A host can replace this provider through the
same core interface.

| CWE | Repair | Regression checks |
| --- | --- | --- |
| 89 | Bind both SQLite `LIKE` values with prepared-statement placeholders | SQL syntax cannot expand results; ordinary searches still work |
| 79 | Use the existing HTML encoder at the search text node | Markup is encoded; ordinary text and product results still render |
| 639 | Always enforce the existing owner-or-administrator policy | A second user is denied; owners and administrators retain access |
| 862 | Always enforce the administrator role in shared middleware | Customers and anonymous callers are denied; administrators retain access |
| 1004 | Set HttpOnly in both cookie issuers, session defaults, and overrides | Both cookies have the flag; HTTPS login and session reuse work |
| 614 | Set Secure in both cookie issuers, session defaults, and overrides | Both cookies have the flag; HTTPS login and session reuse work |
| 942 | Use the existing exact-origin allowlist and `Vary: Origin` | Untrusted and null origins get no grant; trusted and same-origin requests work |

The SQL binding follows the [better-sqlite3 statement API](https://github.com/WiseLibs/better-sqlite3/blob/master/docs/api.md).
Cookie options follow the [Express response API](https://expressjs.com/en/5x/api.html#res.cookie).
HTML text encoding does not cover attributes, scripts, styles, or URLs. CORS
repairs do not claim that the original configuration disclosed private data.
Review the demo origin allowlist for the intended deployment. Secure cookies
require HTTPS; a TLS proxy needs an explicit, trusted application configuration.

## Setup and checks

Use Node.js 22.22.3 or a supported newer version. Install and build
`packages/core` and `packages/evidence` first. Then run:

```sh
cd plugins/remediation
npm ci
npm run build
```

`npm run check` also needs the installed and built `packages/reporting` package,
the installed dependencies of `demo-apps/demo-app-01`, Git, OpenSSL, and permission
to listen on loopback HTTPS ports. Tests create temporary repositories on a
`remediation-fixture` branch. They copy the real demo source, run each generated
test before and after `git apply`, and typecheck the patched application. They
remove the copies afterward. Original demo sources and repository history remain
unchanged. Finding inputs in these tests are explicitly synthetic; the HTTPS
application and generated regression tests are real.

## Generate a suggestion

Use an assessment's original evidence store. The authorized host reads source
files and retains their hashes as separate source records. These extra source
citations do not change the original finding or its proof:

```ts
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { SourceSnapshot } from '@agento/remediation';
import {
  EXPRESS_STOREFRONT_SOURCE_PATHS, ExpressRemediationProvider, sourceDigest,
} from '@agento/remediation';

// scan and store come from the same completed assessment; secrets stay on the host.
const finding = scan.findings.find(item => item.status === 'CONFIRMED');
if (!finding) throw new Error('No confirmed finding to repair');
const repositoryPath = scan.context.project.repositoryPath;
if (!repositoryPath) throw new Error('Source repository required');
const sources: SourceSnapshot[] = [];
const extraEvidence = [];
for (const path of EXPRESS_STOREFRONT_SOURCE_PATHS) {
  const content = await readFile(join(repositoryPath, path), 'utf8');
  const hash = sourceDigest(content);
  const id = `remediation-source:${randomUUID()}`;
  const records = store.capture([{
    id, projectId: finding.projectId, kind: 'source-location',
    producerId: 'host-source-snapshot', capturedAt: new Date().toISOString(),
    summary: 'Source revision for a repair suggestion',
    source: { file: path, startLine: 1 }, facts: { sourceSha256: hash },
  }], { project: scan.context.project, capabilityIds: ['source-snapshot'] });
  extraEvidence.push(...records);
  sources.push({ path, content, sha256: hash, evidenceIds: [id] });
}
const context = { ...scan.context, evidence: [...scan.context.evidence, ...extraEvidence] };
const provider = new ExpressRemediationProvider({ evidenceStore: store, sources, secrets });
const suggestion = await provider.suggest(context, finding);
// suggestion.patch: unified diff; suggestion.regressionTest: complete test source.
// suggestion.files: before/after SHA-256 values; suggestion.validation: NOT_RUN.
```

Register the provider as `CoreProviders.remediation` and set
`ScanRequest.suggestRemediation` to use the existing orchestrator. The context
must include the snapshot records when the provider is called. Alternatively,
call it after an assessment as above and pass the extended context and
`remediation: [suggestion]` to `buildSecurityReport`. Suggestions cite original
finding evidence; `sourceEvidenceIds` separately identify the revision records.

## Review and run the generated test

The patch and test are suggestions. Review them and create an isolated branch or
worktree. Check that every `beforeSha256` still matches before applying the diff.
Patches target their original revision independently; overlapping suggestions
need review together. Generation neither applies nor commits anything.

Save `regressionTest` at `regressionTestPath` in the isolated application copy.
The generated file uses Vitest's Jest-compatible test lifecycle and Node
assertions, matching the demo's existing runner. It starts an HTTPS server on a
random loopback port, uses an in-memory database, and uses only public seeded demo
accounts. Supply a local certificate with a `127.0.0.1` subject alternative name:

```sh
AGENTO_TEST_TLS_KEY=/private/test-key.pem \
AGENTO_TEST_TLS_CERT=/private/test-cert.pem \
npx vitest run test/remediation-cwe-89.test.ts
```

Each generated test contains a security case and a normal-use case. The package
tests establish that the security case fails before the patch and both cases
pass afterward. A generated suggestion always retains `validation: NOT_RUN`;
these development checks do not rerun an assessment's original probe or create a
fix-verification verdict.

## Trust and limits

- The host supplies trusted confirmed findings. Record hashes, project and origin
  bindings, source checksums, endpoint bindings, and runtime references are checked.
  This provider does not judge vulnerability semantics or promote findings.
- Source snapshots are copied. Suggestions are deeply frozen and deterministic.
  A failed generation leaves the input finding and evidence unchanged.
- Unrecognized source revisions require a reviewed recipe update. No fuzzy match,
  prose-to-code execution, model service, automatic repair loop, or OpenCode
  installation is included.
- Paths must be repository-relative JavaScript or TypeScript paths. Source limits
  are 16 files and 1 MiB in total. Patch and test output defaults to 256 KiB;
  `maxPatchBytes` can set a limit up to 1 MiB.
- Supply private secrets, including values that might occur in source context.
  Unsafe patch output is refused instead of redacted, so patch bytes remain valid.
  Host source content is never emitted wholesale. Errors contain fixed codes.
- Source reads, patch application, test execution, production changes, commits,
  pushes, frontend integration, and original-probe retesting remain host concerns.

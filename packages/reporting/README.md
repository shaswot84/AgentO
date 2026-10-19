# Reporting

`@agento/reporting` turns retained security assessments into JSON and Markdown
reports. It accepts core, A01, A02, and A05 scan reports directly. It reads the
evidence store without contacting targets or executing test plans.

## Setup

Use Node.js 22.22.3 or a supported newer version. Build `packages/core` and
`packages/evidence` first, then run:

```sh
cd packages/reporting
npm ci
npm run build
```

For `npm run check`, install and build the A01, A02, and A05 packages and their
dependencies as described in their READMEs. Reporting tests reuse their controlled
adapter fixtures. They cover all seven CWEs in vulnerable and fixed modes; they
do not run native scanners, real browsers, or external targets.

## Export an assessment

Use the same evidence store for assessment and reporting:

```ts
import { writeFile } from 'node:fs/promises';
import { MemoryEvidenceStore } from '@agento/evidence';
import { runA01Scan } from '@agento/a01';
import { buildSecurityReport, reportToJSON, reportToMarkdown } from '@agento/reporting';

const secrets = [resolvedPassword]; // Resolve private values on the host.
const store = new MemoryEvidenceStore({ secrets });
try {
  const scan = await runA01Scan({ ...scanOptions, evidenceStore: store });
  const report = buildSecurityReport(scan, { evidenceStore: store, secrets });
  await writeFile('security-report.json', reportToJSON(report), { flag: 'wx', mode: 0o600 });
  await writeFile('security-report.md', reportToMarkdown(report), { flag: 'wx', mode: 0o600 });
} finally {
  store.close();
}
```

Use `FileEvidenceStore` with a trusted checkpoint to report from a previously
retained run. Keep the saved scan output and its original evidence store together.
Reporting refuses ordinary mutable observations and missing or damaged records.
See the [evidence retention guide](../evidence/README.md).

## Report contents

| Field | Behavior |
| --- | --- |
| Classification | Preserve OWASP, CWE, state, severity, and confidence from the supplied finding |
| Root cause | Include supplied assessment prose with retained evidence IDs; omit uncited prose |
| Endpoint and source | Include cited method, route, file, and line; report missing citations explicitly |
| Proof | Embed original immutable records, SHA-256 digests, timestamps, and provenance |
| Test plans | Include ordered actions, expected observations, capabilities, identities, and redacted targets |
| Execution | Show completed, failed, and skipped tests separately from finding states |
| Remediation | Include supplied explanation, patch, and regression test with finding evidence citations |
| Retest | Default to `NOT_RUN`; supplied fix attempts include status and linked before/after proof |

Unassessed hypotheses appear as `HYPOTHESIS`, with no assigned severity,
confidence, or established root cause. All five core finding states are supported.
Severity uses the core lowercase values, including `info`. Summary severity counts
include confirmed findings only. An empty report does not establish security.

`contextEvidenceIds` identify extra source records used to cite a handler location.
They remain separate from the assessment's static and runtime proof. Markdown
evidence links resolve to embedded records, so developers do not need debug logs.
Source paths are displayed as recorded. The project's `repositoryPath` field is
excluded; a source record can still contain a full file path if its producer used one.

## Include a fix verification result

Supply `retests: [result]` from `@agento/retest` when building the report. Select
one attempt per finding. Reporting checks the retained comparison, original
record digests, project/finding/plan bindings, and before/after references. It
embeds the comparative proof in both formats. The original assessment state and
severity counts remain unchanged; `finding.retest.status` carries the fix state.
Without an explicit retest result, the status stays `NOT_RUN`.

## Trust, privacy, and limits

- Supply trusted assessment results. Reporting checks references and record hashes;
  it does not decide whether cited facts logically establish a vulnerability. Use
  the verification judge before supplying a finding as confirmed.
- Confirmation requires a completed, linked test with cited runtime evidence.
  A supplied judge decision must match the finding. Reporting never promotes a
  scanner claim or changes a supplied verdict.
- Plan parameters, private input references, adapter messages, credentials, raw
  response bodies, and external artifact paths are excluded. Retained normalized
  request/response metadata and body hashes remain available. Reporting cannot
  reconstruct private requests or payloads; the authorized host supplies bindings.
- Supply private secrets to both retention and reporting. The shared
  `EvidenceRedactor` removes standard credentials and secret encodings. If a new
  secret would change stored proof, reporting fails with `unsafe-evidence` rather
  than changing its digest. Source file names remain part of cited source records.
- Remediation is presentation of supplied suggestions. Patch generation, applying
  changes, and fix verification belong to separate providers.
- Outputs are copied, deeply frozen, deterministically ordered, and size bounded.
  Set `generatedAt` for repeatable exports. Defaults: 1,000 findings, 10,000 evidence
  records, and 32 MiB of formatted JSON. Override with `maxFindings`, `maxEvidence`,
  and `maxReportBytes`. Invalid input and failures return fixed `ReportingError` codes.
- Exporters accept builder output or an unchanged JSON copy. Report digests detect
  accidental edits; they are not signatures or proof of the caller's identity.
  Markdown escapes report prose and uses safe evidence anchors and code fences.

Run `node examples/generate.mjs` after building to create the clearly labelled
[synthetic JSON](examples/report.json) and [Markdown](examples/report.md) examples.

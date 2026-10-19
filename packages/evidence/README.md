# Evidence

`@agento/evidence` stores immutable, redacted security observations. It implements
the core `EvidenceStore` port with memory and local file stores. It uses Node.js
built-ins and core types; it does not run tools or decide vulnerability verdicts.

## Setup

Use Node.js 22.22.3 or a supported newer version. Build core first:

```sh
cd packages/core
npm ci
npm run build
cd ../evidence
npm ci
npm run check
```

Integration tests also use the built runtime, CWE, security model, and security
scanner packages. Run `npm ci` and `npm run build` in those packages before
`npm run check` here. The scanner test uses a loopback HTTP gateway and a mock
process runner. It requires no scanner executable or external service.

## Store and retrieve proof

```ts
import { AgentOOrchestrator } from '@agento/core';
import { FileEvidenceStore, verifyEvidenceBundle } from '@agento/evidence';

// Resolve private values on the host before capture. Never send them to a model.
const store = new FileEvidenceStore('/private/agento/run-123/evidence', {
  secrets: [resolvedPassword, resolvedSessionToken],
});
try {
  const report = await new AgentOOrchestrator({ ...providers, evidenceStore: store }).run(request);
  const finding = report.findings.find(item => item.status === 'CONFIRMED');
  if (finding) {
    const proof = store.exportFinding(finding);
    const restored = verifyEvidenceBundle(JSON.parse(JSON.stringify(proof)), proof.digest);
    // restored.evidence contains the recorded facts and provenance, without a new scan.
  }
  // Keep this checkpoint outside the journal if deletion/rewrite detection is required.
  const checkpoint = store.headDigest;
} finally {
  store.close();
}
```

Use a new store directory for each scan. Evidence IDs are unique within a store;
repeated IDs fail, even if their facts match. To reopen a recorded run, use
`new FileEvidenceStore(directory, { expectedHeadDigest: trustedCheckpoint })`.
`null` requires an empty journal. Use `MemoryEvidenceStore` for temporary retention.

For direct capture, call `store.capture(items, { project, capabilityIds, probeId,
environmentId, targetUrl })`. Only `project` and a nonempty `capabilityIds` array
are required. The producer ID supplies the default probe ID; `probe:` prefixes
are removed. The default environment ID is `default` and its target is the
project base URL. Pass the actual producing capabilities and environment when
calling this API directly. Core supplies provider capabilities for source and
browser observations, and required plan capabilities for execution results.

| API | Result |
| --- | --- |
| `capture(items, context)` | Validate, redact, copy, hash, and deeply freeze a batch |
| `get(id)` | Read one immutable record |
| `list(filter)` | Filter by project, kind, producer, or probe |
| `forFinding(finding)` | Resolve every evidence ID and check project ownership |
| `exportFinding(finding)` | Export a frozen JSON proof bundle with a digest |
| `verifyEvidenceBundle(value, expectedDigest?)` | Validate record hashes and finding references offline |
| `close()` | Release a file writer and stop further operations |

All existing core kinds are supported. Dedicated kinds also cover headers,
cookie security, cross-origin observations, and authorization comparisons.
Source snippets and AST observations stay in normalized facts. Existing probe
projections keep their schema, response hashes, cookie flags, comparisons, and
coverage diagnostics. Scanner severity and confidence remain reported claims.

## Privacy and integrity

`EvidenceRedactor` is also exported for report prose and other public projections.
Its `text`, `url`, and `json` methods use the same policy as evidence retention.
Pass host secrets at construction. Applying redaction to an existing record would
change its digest; reporting checks for this and refuses to rewrite stored proof.

The store removes standard credential fields, authorization headers, cookie
values, private keys, JWTs, credential assignments, and URL credentials, query values,
and fragments. It also removes host-supplied secrets and common encoded forms
from strings and property names. A secret-bearing reference ID fails capture
instead of silently changing its links. Source snippets retain sanitized text.
JSON bodies are sanitized as structured facts; opaque bodies, raw process output,
encoded payloads, DOM text, logs, and image bytes are removed. Preserve response
hashes, lengths, parsed metadata, and probe comparisons at the adapter boundary.
Structured DOM slices and console events keep metadata while text and input values
are removed. Raw `Set-Cookie` headers are removed; parsed cookie flags remain.

Automatic pattern matching cannot identify every unlabeled secret. The trusted
host must supply its private values before capture; adapters must continue to
project public facts. External `artifactRef` links are omitted because their
files can change independently. Screenshot records retain normalized metadata
and hashes only. The store does not capture images or mask pixels.

Each stored item adds a schema version, probe and capability provenance, target
environment, and a SHA-256 digest of its sanitized content. Returned objects,
nested facts, source locations, and collection views are frozen. No update or
delete API exists. Batches fail validation before any record is retained.

The file store uses a private directory, a single-writer lock, and a private
append-only JSON journal. Each batch links to the previous batch digest. Writes
are flushed before records become visible in memory. Corrupt and partial journals
fail closed; failed writes stop use of the handle. A crash can leave the writer
lock behind. Stop the owning process and inspect the journal before a host removes
that stale lock. The store never repairs, truncates, or discards evidence silently.

Hashes detect content changes; they do not authenticate who captured a fact.
A trusted external head digest detects a deleted tail or a fully rewritten journal.
The filesystem owner can still replace files. Integrity is checked when reopening;
the store does not monitor external file changes continuously.

Defaults are 10,000 records, 1 MiB per record, and 64 MiB per store. Limits apply
to both capture and reopen; journal envelope bytes also count toward disk limits.

Core freezes evidence and finding references even without a store. Inject this
port to add central redaction, provenance, and retention. This package does not
connect the frontend scheduler, store credentials, execute tests, or implement a
verification judge. Recorded facts let a reviewer inspect a finding; the existing
CWE evaluator remains responsible for its verdict.

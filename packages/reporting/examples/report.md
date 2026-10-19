# Security report: Synthetic report example \(not a live scan\)

Project: synthetic-example · Target: https://example.invalid

Generated: 2026-10-19T10:02:00Z · Report SHA-256: 2af565007bbadbf88226641d2337ba89807dfbe7d14c4ed1f091e4b7871d1b33

## Assessment summary

| State | Count |
| --- | ---: |
| HYPOTHESIS | 1 |
| LIKELY | 0 |
| CONFIRMED | 0 |
| NOT\_REPRODUCED | 0 |
| REJECTED | 0 |

Severity counts include confirmed findings only.

| Severity | Confirmed |
| --- | ---: |
| info | 0 |
| low | 0 |
| medium | 0 |
| high | 0 |
| critical | 0 |

## CWE-639 hypothesis

ID: hypothesis:example:ownership · Hypothesis: example:ownership

**HYPOTHESIS** · A01:2025 · CWE-639 · Severity: not assessed · Confidence: not assessed

Assessment: A caller-selected order identifier needs an ownership check. Runtime verification is pending. Evidence: [example:source](#evidence-2b167c4c694e9877ed78eedd28b96e236cd021b745df219c13e5ac7138d28785)

Endpoint: GET /api/orders/:id. Evidence: [example:source](#evidence-2b167c4c694e9877ed78eedd28b96e236cd021b745df219c13e5ac7138d28785)

Source: src/routes/orders.ts:24–28. Evidence: [example:source](#evidence-2b167c4c694e9877ed78eedd28b96e236cd021b745df219c13e5ac7138d28785)

### Root cause

Not established by cited evidence.

### Proof

Static evidence: [example:source](#evidence-2b167c4c694e9877ed78eedd28b96e236cd021b745df219c13e5ac7138d28785)

Runtime evidence: No retained evidence.

Assessment source: hypothesis.

Report diagnostics: no-runtime-proof, root-cause-unverified.

### Reproduction and test plans

Plan: example:authorization-plan · browser · active

Target: https://example.invalid/api/orders/:id

Identities: owner, second-user

Required capabilities: authentication-manager, request-executor, response-comparator

Basis: [example:source](#evidence-2b167c4c694e9877ed78eedd28b96e236cd021b745df219c13e5ac7138d28785)

1. Read an owned order as the owner — Collect a complete successful baseline.
2. Read the same order as an unauthorized second user — Compare status, response hashes, and private owner markers.

Private request values must be supplied by the authorized host. Retained proof below contains redacted requests, response metadata, and normalized observations where available.

### Suggested remediation

No remediation was supplied.

Retest status: NOT\_RUN.

## Immutable evidence

Each record retains its original digest and provenance. Evidence IDs in the report link to these records.

<a id="evidence-2b167c4c694e9877ed78eedd28b96e236cd021b745df219c13e5ac7138d28785"></a>

### example:source

source-location · 2026-10-19T10:00:00Z · Producer: documentation-fixture

Synthetic source observation for the order handler.

Record SHA-256: 6d8a97312197f036c98c8273d037062886b9d455965afd05998ccf5116a95fa2

```json
{
  "id": "example:source",
  "projectId": "synthetic-example",
  "kind": "source-location",
  "producerId": "documentation-fixture",
  "capturedAt": "2026-10-19T10:00:00Z",
  "summary": "Synthetic source observation for the order handler.",
  "facts": {
    "operation": "order.lookup",
    "input": "id",
    "fixture": true
  },
  "source": {
    "file": "src/routes/orders.ts",
    "startLine": 24,
    "endLine": 28
  },
  "endpointId": "orders",
  "schemaVersion": 1,
  "provenance": {
    "probeId": "documentation-fixture",
    "capabilityIds": [
      "framework-analysis"
    ],
    "environment": {
      "id": "synthetic",
      "baseUrl": "https://example.invalid",
      "targetUrl": "https://example.invalid"
    }
  },
  "digest": "6d8a97312197f036c98c8273d037062886b9d455965afd05998ccf5116a95fa2"
}
```

## Limits

- Finding states come from the supplied assessment. Reporting does not execute tests or independently verify vulnerabilities.
- A hypothesis is unverified. NOT\_REPRODUCED describes this assessment and does not prove that an application is secure.
- Proof contains retained, redacted observations. Private input values, credentials, raw bodies, and external artifacts are not reconstructed.
- Test steps describe the assessment. Private bindings must be supplied by the authorized host to reproduce it.
- Remediation is included only when supplied with evidence references. Retest has not run.

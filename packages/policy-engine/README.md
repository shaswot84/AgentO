# Execution policy

`@agento/policy-engine` sits between a generated plan or probe request and its
selected runtime capabilities. `review()` reports policy readiness. `run()`
creates a temporary binding and enforces policy before target access.

## Setup and checks

Use Node.js 22.22.3 or a supported newer release. Install and build `packages/core`,
`plugins/tools/e2e-browser`, `packages/runtime`, and `packages/capability-registry`
in that order. For the test suite, also build `packages/security-model`,
`plugins/cwe`, and `packages/test-planner`. Then run here:

```sh
npm ci
npm run check
npm run test:integration
```

The default tests use injected adapters and deterministic application models.
The optional integration suite starts local loopback servers and the installed
Chromium browser. It does not contact an external target or model service.

## Policy defaults

| Control | Default |
| --- | --- |
| Targets | Explicit HTTP(S) origins, intersected with the project declaration |
| Execution scope | One plan target origin; an adapter cannot add another origin |
| Tools | Explicit IDs in `tools`; unlisted tools cannot execute |
| Methods | `GET`, `HEAD`, `OPTIONS`; `CONNECT` and `TRACE` always refused |
| Request rate | 60 outgoing exchanges per rolling 60 seconds across this engine |
| Execution budget | 100 requests per execution; 1,000 per tool within that execution |
| Lifetime | Five minutes, cancellation, or callback completion |
| Approval | Active tests and high/critical operational severity require approval |
| Approval lifetime | Five minutes, one execution, with explicit revocation |
| Audit | 10,000 immutable records; stop if the log or configured sink fails |

Network-facing capabilities raise understated risk to `active`, with at least
`medium` operational severity. A supplied severity can raise this classification.
This describes the proposed test's impact, not a vulnerability verdict. A policy
can refuse all active tests through `maxRisk: 'passive'`.

Origins include protocol, host, and port. Wildcards, URL credentials, non-HTTP
schemes, and malformed URLs are refused. CORS `Origin` header values do not add
navigation destinations. HTTP clients remain single-hop clients. Browser policy
checks apply to document loads, subresources, fetches, forms, and redirect hops.
Popups, workers, and WebSockets retain the browser adapter's existing restrictions.

## Review and execute an existing plan

The host owns the capability registry, project context, plan, and probe registry.
Tool IDs below must match the IDs used during adapter registration.

```ts
import { PolicyEngine } from '@agento/policy-engine';

const policy = new PolicyEngine({
  allowedOrigins: ['https://shop.example'],
  tools: {
    runtime: { allowedMethods: ['GET', 'HEAD', 'OPTIONS'], maxRequests: 30 },
    'scanner-port': { capabilities: ['sql-scanner'], maxRequests: 8 },
  },
  rateLimit: { maxRequests: 30, windowMs: 60_000 },
  maxRequestsPerExecution: 40,
});

const resolution = await registry.resolvePlan(plan);
const request = { project: context.project, plan, severity: 'medium' as const };
const decision = policy.review(request, resolution.report);
```

If the decision is `DENY`, stop. If it is `APPROVAL_REQUIRED`, show the actual plan,
target, selected tools, and decision to the authorized reviewer. Only after the
reviewer accepts that request may the trusted host issue approval:

```ts
const approvalId = policy.approve(decision.id, reviewerId);

const evidence = await policy.run(request, resolution, async execution => {
  const project = { ...context.project, allowedOrigins: execution.allowedOrigins };
  return sqlProbe.execute({
    project,
    capabilities: execution.capabilities,
    signal: execution.signal,
    request: privateRequest,
    parameter: { name: 'q', location: 'query' },
  });
}, { approvalId, signal: scanAbortSignal });
```

Resolve `privateRequest` from the plan's private input references on the host.
Do not pass these values to the reviewer log or a model.

For `ALLOW`, call `run()` without an approval ID. `approval: { risks: [],
severities: [] }` disables the human approval requirement when the trusted host
explicitly selects that policy. It does not disable scope, tool, method, or budget
checks. Approval cannot override a denial. `revokeApproval(approvalId)` removes a
pending grant. Changes to the plan, project scope, severity, or selection report
invalidate the grant. Starting an execution consumes its grant, including runs
that subsequently fail or are cancelled.

For a direct probe request, provide a `plan` object with `id`, `targetUrl`, `risk`,
`probeId`, and `requiredCapabilities: ['probe:<id>']`. Pass the matching result from
`registry.resolveProbe()`. A request method can be declared with
`request: { method: 'POST' }` for policy review before any execution starts.

## Runtime bindings and adapter contract

Always execute probes with the capabilities returned inside `run()`. The original
resolution contains private, unguarded ports. A successful registry selection or
policy review alone grants no access. Callbacks must await their target work.
Escaped capabilities become unusable when the callback completes, fails, times
out, or is cancelled. Authentication bindings use fresh managers and close their
sessions after execution. Request abort signals reach HTTP and browser clients.

HTTP executors must implement the runtime's single-exchange contract. Scanner
adapters must use the supplied `ScannerRequest.executor`; it carries policy and
the existing probe restrictions. The policy keeps scanner restrictions active
through asynchronous calls, while counting an outgoing exchange once. Optional
tools are checked too. Disable or remove an unsupported optional port before
resolution if it is not needed.

Browser controllers and authentication managers must implement `withGuard()` and
return a fresh binding. Missing support causes `guard-unsupported` before the
callback runs. The provided `WorkflowBrowserController`,
`RuntimeAuthenticationManager`, and browser adapter implement this contract.
Custom browser runtime implementations must enforce the supplied guard on every
outgoing exchange, including authentication and redirect hops.

In the built-in browser's policy mode, Chromium intercepts each request before
dispatch. This avoids an auxiliary HTTP client that could miss policy checks on
redirects. Runtime code depends only on the core `ExecutionGuard` interface;
policy rules and scanner vendor names stay outside runtime and probe logic.

Adapter code, registration data, approval calls, and the host are trusted. The
engine controls access through its bound capabilities; it is not an operating
system sandbox for an adapter that creates its own sockets or processes.
Standalone runtime APIs still require explicit policy binding. This package does
not add automatic frontend execution, a scheduler, scanner vendor integrations,
or vulnerability judgments.

## Audit and storage

`policy.audit()` returns an immutable JSON-safe snapshot. Records include a
sequence number, UTC time, decision, risk, severity, execution ID, selected tool,
and origin and method when applicable. A SHA-256 fingerprint links the
review, approval, and execution to the exact request and selection. Approval
records include the review ID and a hash of the reviewer ID.

Paths, queries, headers, bodies, selectors, credential references, adapter objects,
and raw errors are excluded. Approval tokens stay private. Records remain in
memory unless the host supplies a trusted synchronous `auditSink` in the second
constructor argument. The sink must store each record before returning. A sink
failure or full log stops subsequent effects. Use one engine per policy authority
to share rate limits; separate processes need a host-level shared limiter.

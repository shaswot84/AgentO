# Security scanner adapters

Nuclei, ZAP, Dalfox, and sqlmap run behind AgentO's scanner contracts. Each adapter returns a frozen `SecurityTestResult` with canonical `Evidence[]`. A scanner claim remains a candidate that requires independent verification.

| Adapter | Capability ports | Supported execution |
| --- | --- | --- |
| `NucleiAdapter` | `security-scanner` | GET requests with trusted local HTTP templates. The bundled template records a response; it does not detect a vulnerability. |
| `ZapAdapter` | `security-scanner` | A dedicated command-mode instance sends the selected request, runs passive rules, and exports a JSON report. |
| `DalfoxAdapter` | `security-scanner`, `xss-scanner` | Reflected XSS scanning of one GET query parameter. |
| `SqlmapAdapter` | `security-scanner`, `sql-scanner` | Boolean and error tests on one query, form, or JSON parameter. No data extraction or system commands. |

## Setup

Use Node.js 22.22.3 or later, or 24.8.0 or later. Install and build the local core, runtime, capability registry, and policy packages first. Then run:

```sh
cd plugins/tools/security-scanners
npm ci
npm run check
```

Install native tools separately. They are optional and are not npm dependencies. Supply an absolute executable path or put the command on `PATH`.

| Tool | Native version verified | Installation reference |
| --- | --- | --- |
| Nuclei | 3.11.1 | [Official releases](https://github.com/projectdiscovery/nuclei/releases) |
| ZAP | 2.17.0, Java 21 | [Official downloads](https://www.zaproxy.org/download/). Include the Automation Framework, passive scanner, passive rules, and report add-ons. Put a compatible Java executable on `PATH`. |
| Dalfox | 3.2.4 | [Official releases](https://github.com/hahwul/dalfox/releases). This adapter uses the v3 `scan` command. |
| sqlmap | 1.10.10.8 development build | [Official installation](https://github.com/sqlmapproject/sqlmap/wiki/Download-and-update). Use an executable launcher for a Python source installation. |

The adapter starts no shell. A Python launcher must forward its arguments with `"$@"`. Do not supply shell commands as the `executable` option. Native dependencies, including Java and Python, must be available on `PATH`.

## Register and execute

The host supplies the project, approved plan, private request, and executor. Registry availability is separate from execution approval.

```ts
import { CapabilityRegistry } from '@agento/capability-registry';
import { PolicyEngine } from '@agento/policy-engine';
import { DeterministicRequestExecutor } from '@agento/runtime';
import { SqlmapAdapter } from '@agento/security-scanners';

const registry = new CapabilityRegistry()
  .register(new SqlmapAdapter({ executable: 'sqlmap' }).registration());

// project and plan come from the host's retained model and test planner.
// The plan requests the generic "security-scanner" capability.
const resolution = await registry.resolvePlan(plan);
const policy = new PolicyEngine({
  allowedOrigins: project.allowedOrigins,
  tools: { 'sqlmap-adapter': { maxRequests: 64 } },
});
const review = policy.review({ project, plan }, resolution.report);
// Show review to the user. Obtain an approval grant through the host's approval UI.

async function executeApproved(approvalId: string) {
  const executor = new DeterministicRequestExecutor({
    baseUrl: project.baseUrl, allowedOrigins: project.allowedOrigins,
  });
  return policy.run({ project, plan }, resolution, execution =>
    execution.capabilities.get('security-scanner').run({
      project, planId: plan.id, cweId: plan.cweId,
      request: { url: plan.targetUrl, method: 'GET' },
      parameter: { name: 'q', location: 'query' },
      executor, maxRequests: 64, signal: execution.signal,
    }), { approvalId });
}
```

Use the raw host executor in this example: the policy-bound scanner port wraps it with the selected scanner's guard. For authenticated tests, supply the host's private session executor. The loopback bridge adds trusted authorization and cookie headers on the host. It does not let native tools replace them.

Every adapter also implements the core `SecurityScanner.execute(context, plan)` contract. Configure `resolveInput` to resolve private bindings and return an approved executor. The adapter checks the project, plan, CWE, target, and identity references. It does not interpret action prose, acquire approval, select other adapters, or schedule probes. Without a resolver, core execution returns `SKIPPED`.

Dalfox and sqlmap registrations also fit the existing XSS and SQL probe ports. Failure or disablement produces incomplete coverage diagnostics. Dalfox labels do not prove browser execution or a reached DOM sink. sqlmap console claims do not prove a controlled response difference. These values stay `null` until independent observation establishes them. No probe or core code selects a tool by vendor name.

Set `enabled: false` to disable an adapter. Register a mock or another implementation under the same capability to replace it. Adapters share process and normalization helpers; they never invoke another scanner.

## Execution and evidence boundaries

- Each invocation has a private temporary home and working directory. Request files use mode `0600`. Ambient API keys, proxy settings, tool configuration, and session caches are not inherited. `PATH` is retained for native dependencies.
- A temporary IPv4 loopback gateway maps the selected path and method to the original target through the injected executor. HTTPS target traffic remains the executor's responsibility. Query, form, and JSON injection stays on the selected parameter; other parameters cannot change.
- Dalfox's HEAD preflight becomes a counted GET to the approved endpoint. The gateway returns its real response headers without a body. The target method and the existing probe executor contract stay GET.
- Scope changes, CONNECT tunnels, WebSocket upgrades, and excess requests stop the invocation. Redirect destinations are withheld from native tools. Every forwarded exchange consumes the local request budget and any installed policy budget and rate limit.
- The native runner uses an argument vector, no shell, a fresh process group, cancellation, a wall-clock deadline, and a combined stdout/stderr byte limit. It kills the process group and removes temporary files after execution. General calls permit 1–1024 requests; existing probes retain their smaller budgets. A budget too small for an engine produces incomplete coverage.
- Public evidence contains fixed labels, hashes, response status, byte counts, supported CWE labels, reported severity/confidence, and links to collected response evidence. It omits raw requests, responses, payloads, template text, URLs, credentials, native logs, and error messages. All scanner claims carry `verified: false`.
- `COMPLETED` means the engine inspected the endpoint and returned a supported report. It does not mean the target is safe. Missing or disabled tools return `SKIPPED`; invalid output, failed processes, cancellation, and limits return `FAILED`. One failure does not stop later core plans.

Native engines see an HTTP loopback origin. This mode does not assess target TLS, virtual-host behavior, browser execution, cross-origin browser policy, crawling, stored XSS, external resources, or out-of-band callbacks. Nuclei templates must use the exact selected endpoint, such as `{{BaseURL}}`; attempts to visit another path fail. ZAP uses passive rules only. No arbitrary CLI options or automation plans are accepted.

Executables and local templates are trusted host code. The gateway and configured proxy enforce this integration's traffic contract; they are not an operating-system network sandbox for a modified executable or template that opens its own sockets. Direct `run()` calls require the host to supply its intended policy executor. Production hosts should use the policy-bound capability as shown above.

## Verification

```sh
npm run check

# Optional: all four installed tools against a controlled loopback server.
# Set these paths for installations that are not on PATH.
AGENTO_NUCLEI_EXECUTABLE=/path/to/nuclei \
AGENTO_ZAP_EXECUTABLE=/path/to/zap.sh \
AGENTO_DALFOX_EXECUTABLE=/path/to/dalfox \
AGENTO_SQLMAP_EXECUTABLE=/path/to/sqlmap \
npm run test:integration
```

The normal suite uses output fixtures, actual child processes, local HTTP traffic, unchanged probes, registry replacement, policy bindings, and core failure isolation. It tests scope expansion, private-data projection, malformed and incomplete reports, limits, cancellation, temporary-file cleanup, and concurrent runs. The optional suite requires installed native tools and does not silently skip a missing executable.

Interface references: [Nuclei execution](https://docs.projectdiscovery.io/opensource/nuclei/running), [ZAP requestor](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-requestor/), [ZAP reports](https://www.zaproxy.org/docs/desktop/addons/report-generation/automation/), [Dalfox CLI](https://dalfox.hahwul.com/reference/cli/), and [sqlmap usage](https://github.com/sqlmapproject/sqlmap/wiki/Usage).

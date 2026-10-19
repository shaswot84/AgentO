# Capability registry

`@agento/capability-registry` matches plan and probe requirements to registered
adapter ports. Several tools can offer the same capability. Selection uses
declared protocol, CWE support, risk, priority and current availability.

## Setup

Use Node.js 22.22.3 or a supported newer release. Install and build `packages/core`
and `packages/runtime`, in that order. For tests, also install and build
`packages/security-model`, `plugins/cwe` and `packages/test-planner`, in that order,
with their development dependencies. Then run here:

```sh
npm ci
npm run check
```

Tests use synthetic target responses and injected scanner ports. No installed
scanner, running target, browser or model service is required.

## Register ports and resolve a probe

```ts
import { CapabilityRegistry } from '@agento/capability-registry';
import {
  DeterministicRequestExecutor, NormalizedResponseCollector,
  NormalizedResponseComparator, ProbeRegistry, SQLInjectionProbe,
} from '@agento/runtime';

const probe = new SQLInjectionProbe();
const probes = new ProbeRegistry().register('sql-injection', probe);
const registry = new CapabilityRegistry({ probes });
registry.register({
  metadata: {
    id: 'http-runtime',
    capabilities: ['request-executor', 'response-collector', 'response-comparator'],
    supportedCwes: 'all', protocols: ['http', 'https'], risk: 'active',
  },
  capabilities: {
    'request-executor': new DeterministicRequestExecutor({
      baseUrl: project.baseUrl, allowedOrigins: project.allowedOrigins,
    }),
    'response-collector': new NormalizedResponseCollector(),
    'response-comparator': new NormalizedResponseComparator(),
  },
});

const resolution = await registry.resolveProbe('sql-injection', {
  cweId: 'CWE-89', targetUrl: project.baseUrl, risk: 'active',
});
console.log(resolution.report); // JSON-safe selection data, not probe evidence.
```

`resolution.capabilities` is the existing runtime `CapabilityRegistry` populated
with selected private ports. A host can pass it to the unchanged probe after its
execution policy permits the operation. Missing required ports or probe
implementations produce `null`, so a partial required binding is never exposed.
The package registry selects tools; the runtime registry holds one bound instance
per capability. Both classes retain their separate responsibilities.

The SQL probe above can collect its built-in observations without a scanner.
Its optional `sql-scanner` and `authentication-manager` ports have explicit
diagnostics when absent. Add a scanner using the objective runtime `SQLScanner`
contract. No vendor imports or scanner-specific conditions belong in the probe:

```ts
registry.register({
  metadata: {
    id: 'local-sql-adapter', capabilities: ['sql-scanner'],
    supportedCwes: ['CWE-89'], protocols: ['http', 'https'], risk: 'active', priority: 10,
  },
  capabilities: { 'sql-scanner': configuredSqlAdapter },
  executable: configuredExecutablePath, // Absolute path or bare command on PATH.
  checkAvailability: async signal => configuredSqlAdapter.isConfigured(signal),
});
```

Configuration, executable paths and availability callbacks are trusted host
inputs. Register another adapter under a different ID to provide fallback.
Browser adapters offer `browser-controller` through the existing
`WorkflowBrowserController`; authentication adapters offer
`authentication-manager`. Hosts compose runtime services and keep credentials,
personas and session configuration private. New typed capabilities can extend
the runtime `CapabilityCatalog` by declaration merging.

## Plans and preflight

`resolvePlan(plan, { signal })` accepts the core plan fields plus optional
`probeId`, `optionalCapabilities` and `readiness`. It accepts structured planner
output directly, including a JSON round trip. It expands requirements from the
registered probe, merges them with plan requirements, and validates the
`probe:<id>` marker. Conflicting probe identifiers are rejected. Blocked planner
drafts do not start availability checks.

`lookup({ capability, cweId, protocol })` returns all matching public metadata in
selection order without checking availability. `preflight({ signal })` checks
every registered adapter. Resolution checks only compatible tools offering a
requested capability, once per tool per call. Availability is checked again on
each operation; an earlier preflight is not a durable guarantee.

| Report status | Meaning |
| --- | --- |
| `READY` | Every required capability and declared probe is available |
| `UNAVAILABLE` | A required capability or probe is missing |
| `BLOCKED` | The request is invalid or planning prerequisites are missing |
| `CANCELLED` | The caller cancelled selection; no binding is returned |

Missing optional capabilities keep `READY` status and add `optional-unavailable`
diagnostics. Each selection includes candidate IDs, risk and rejection reasons.
Reports exclude target URLs, planner inputs, adapter objects, private paths and
raw callback errors. Metadata and reports are immutable. Binding maps snapshot
the selected port references without freezing the injected adapter instances.

## Selection and limits

Compatible available adapters with passive risk come first. Within one risk
class, higher priority wins; lexical tool ID breaks ties. This order is stable
across registration order. The report retains active plan risk and raises risk
for active selected tools. All probe resolutions carry active risk because
requests and authentication can change application state. Risk is descriptive;
selection never grants permission to execute.

Executable checks inspect regular files and execute permission. They do not run
commands or query versions. Bare commands use absolute entries in `PATH`; empty
or relative entries are skipped. Explicit relative paths and command arguments
are rejected. The file checker uses POSIX execution semantics; a host with other
installation rules can provide a custom availability callback instead.

Adapter checks have a two-second timeout by default, configurable from 1 to
30,000 milliseconds. At most eight checks run concurrently. Missing files,
unconfigured adapters, callback failures and timeouts yield fixed codes and allow
another compatible adapter to be selected. Cancellation aborts pending checks
and withholds bindings. Custom callbacks must honor their signal; JavaScript
cannot forcibly stop a callback that ignores cancellation. Callbacks must stay
local and must not start sessions, probe targets or run scans.

The registry does not validate project allowlists, redirects, request rates,
private input values or scanner output. Those checks remain with the execution
host and scoped runtime adapters. Adapter authors must declare accurate support
and risk metadata. Availability can change after selection, so hosts must still
handle execution failures. This package does not execute plan steps, schedule
work, produce verdicts, add vendor integrations or enable frontend runtime tests.
The core orchestrator still requires an explicitly supplied execution provider.

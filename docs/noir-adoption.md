# Default static endpoint discovery

Noir 1.4.0 is AgentO's default static endpoint-inventory provider. The core owns
the tool-independent `EndpointDiscoveryProvider` contract. The Express framework
adapter runs Noir, normalizes its output immediately, then uses AgentO's existing
source analysis for validation, mounted paths, inputs, middleware and security
context. Default frontend, discovery and A01/A02/A05 compositions use this adapter.

Noir cannot select or execute probes. Candidate routes carry explicit validation
metadata that survives model merging and JSON serialization. The planner, CWE
rules, assessment runners and core execution reject unvalidated inventory.
Corroborated source routes still require normal scope, input, identity, capability,
policy and runtime proof checks. Authentication, ownership and vulnerability
verdicts never come from Noir tags.

Install the tool after the adapter's dependencies:

```sh
npm run setup:noir --prefix plugins/frameworks/express
```

The Linux x64 installer verifies the pinned official release checksum. Other
hosts can install Noir 1.4.0 separately and set `AGENTO_NOIR_EXECUTABLE`. The tool
is already installed locally in this checkout's ignored adapter dependencies.
See the [adapter guide](../plugins/frameworks/express/README.md) for configuration,
source selection, process limits and alternative normalized providers.

## Adoption checks

The [recorded integration run](evaluation/noir-adoption/results.json) uses the
same seven pinned repositories as the [historical benchmark](noir-benchmark.md).
It records source hashes, normalized artifact digests, reference matches and
whether validation survives application-model construction and serialization.
It installs no target dependencies and sends no requests to those applications.

| Project | Inventory | Source-corroborated | Blocked candidates | Reviewed routes found | Reviewed routes corroborated |
| --- | ---: | ---: | ---: | ---: | ---: |
| NodeGoat | 20 | 0 | 20 | 2/2 | 0/2 |
| RealWorld Express | 20 | 1 | 19 | 1/3 | 1/3 |
| Juice Shop | 111 | 1 | 110 | 3/3 | 1/3 |
| NodeBB | 537 | 5 | 532 | 2/2 | 0/2 |
| Express boilerplate | 15 | 0 | 15 | 2/2 | 0/2 |
| Hackathon Starter | 101 | 101 | 0 | 3/3 | 3/3 |
| **Express total** | **804** | **108** | **696** | **13/15** | **5/15** |
| Flask tutorial | Unsupported framework adapter | — | — | — | — |

These are static records, not verified deployed endpoints. Source corroboration
does not establish every input or handler, authentication enforcement, policy
approval or a security verdict. The larger inventory improves visibility; it does
not by itself increase the number of routes eligible for automatic assessment.

Counts differ from raw Noir's historical 860-entry benchmark because production
scans select bounded JS/TS application source, omit known training snippets and
static asset files, and reject unsafe URL forms or invalid source references.
NodeBB reports partial discovery. RealWorld's unresolved `/api` mount remains a
known gap. Function registration, imported controllers and route tables still
need focused validation/enrichment. Flask remains an explicit unsupported-stack
control; the earlier standalone Noir Flask result did not add Python assessment.

On the controlled demo, AgentO corrects Noir's missing prefixes from independently
resolved mount chains and retains all **19 routes**, source-derived inputs,
authentication, cookie, CORS and database observations. Missing or failed Noir
produces explicit status with no silent legacy fallback. The frontend retains
partial scan state and diagnostics even if Semgrep completes successfully.

Verification covered provider normalization, source containment, private data,
version checks, missing tools, malformed output, strict partial runs, cancellation,
time/output/record limits, mount repair, model serialization and execution guards.
Core, framework, model, discovery, rules, planning, assessments, frontend,
hypothesis, static analysis, reporting, repair and retest checks passed. Existing
live A01 authorization tests and A02 cookie/CORS tests also passed in vulnerable
and fixed demo modes. Native A05 scanner integrations were not rerun in this
adoption check; its source, planning and execution unit suite passed.

To repeat the external source checks with the pinned clones already present:

```sh
node scripts/evaluation/noir-adoption.mjs \
  --repos-dir /path/to/pinned/clones \
  --output /tmp/new-noir-adoption-run
AGENTO_NOIR_INTEGRATION=1 npm run check --prefix plugins/frameworks/express
```

The external runner refuses changed revisions, dirty checkouts, failed discovery
and model merges that remove candidate guards. It writes compressed normalized
artifacts to a new output directory. The historical benchmark retains its custom
extractor arm through the explicitly named `ExpressSourceAnalyzer`.

![AgentO Security Scanning Pipeline](assets/Neon%20AI%20Security%20Scanning%20Pipeline.png)

# AgentO

> **Autonomous, code-aware application security testing and verification platform.**

Traditional application security tools typically operate in isolation:
- **Static analysis (SAST)** flags potential issues in source code but generates high volumes of false positives because it lacks runtime context.
- **Dynamic scanning (DAST)** tests running applications from the outside but lacks code visibility and struggles with authenticated workflows, stateful business logic, and multi-user access control.

**AgentO** bridges this gap. It acts as an agentic security orchestrator that pairs static code understanding with multi-identity runtime verification to hypothesize, execute, and confirm real vulnerabilities with verifiable evidence.

---

## What AgentO Solves

1. **Context-Aware Vulnerability Discovery**  
   Extracts application routes, authentication handlers, database queries, and authorization models from source code to target security tests precisely rather than blindly fuzzing.

2. **Multi-User Access Control Verification**  
   Automates multi-persona tests (e.g., comparing user identities and permissions) to reliably detect and reproduce complex flaws like **IDOR** and **Missing Authorization** that traditional scanners miss.

3. **Evidence-Backed Verification**  
   Every reported finding must trace directly to concrete proof: dynamic HTTP exchanges, browser interactions, or verified scanner outputs. No hallucinated vulnerabilities.

4. **Tool-Agnostic Core Architecture**  
   The core engine relies on pure contracts and adapters, allowing static analyzers, dynamic scanners, browser automation drivers, and reasoning models to be swapped or upgraded without changing core orchestration logic.
5. **Language- & Framework-Agnostic Design**  
   The core reasoning and orchestration engine is completely decoupled from specific stacks. While Node.js and Express.js serve as the initial pilot integration, AgentO's adapter contract system is designed to support any programming language, web framework, or REST/GraphQL API ecosystem.

---

## Core Vulnerability Scope

AgentO focuses on high-impact OWASP Top 10 categories:

- **Broken Access Control (A01)**
  - Authorization Bypass Through User-Controlled Key / IDOR (`CWE-639`)
  - Missing Authorization on Protected Endpoints (`CWE-862`)
- **Security Misconfiguration (A02)**
  - Permissive Cross-Domain Policy / CORS (`CWE-942`)
  - Sensitive Cookies Without `HttpOnly` (`CWE-1004`)
  - Sensitive Cookies Without `Secure` (`CWE-614`)
- **Injection (A05)**
  - Cross-Site Scripting / XSS (`CWE-79`)
  - SQL Injection / SQLi (`CWE-89`)

---

## Repository Structure

```text
AgentO/
├── apps/
│   └── frontend/      # Application context, hypotheses, test plans, and evidence
├── packages/
│   ├── a01/           # Access control assessment with isolated user sessions
│   ├── a02/           # Complete cookie and CORS assessment with shared runtime proof
│   ├── a05/           # Targeted injection assessment with source and runtime proof
│   ├── core/          # Tool-independent contracts, domain types, and orchestrator
│   ├── capability-registry/ # Adapter metadata, availability and capability selection
│   ├── discovery/     # Repository metadata, stack detection, and mode selection
│   ├── evidence/      # Immutable, redacted proof with local retention and export
│   ├── hypothesis-engine/ # Evidence-grounded hypotheses and optional structured reasoning
│   ├── policy-engine/ # Target and tool policy, approvals, request limits and audit
│   ├── reporting/     # Evidence-linked developer reports in JSON and Markdown
│   ├── retest/        # Isolated patch checks and original-probe replay
│   ├── runtime/       # Scoped capabilities and reusable security investigations
│   ├── security-model/ # Evidence-preserving source, browser and runtime application model
│   ├── test-planner/  # Structured probe plans, prerequisites and verification criteria
│   ├── verifier/      # Runtime proof checks, deterministic verdicts, and model citations
│   └── workflow/      # Recipe-first and optional semantic planning with action validation
├── plugins/
│   ├── cwe/           # Independent vulnerability rules consuming normalized probe evidence
│   ├── frameworks/
│   │   └── express/   # Express routes, middleware, configuration, and source evidence
│   ├── models/
│   │   └── openai/    # Optional bounded structured-generation provider
│   ├── remediation/  # Source-bound Express repair suggestions and regression tests
│   └── tools/
│       ├── semgrep/   # Normalized static XSS/SQLi candidates and source/sink evidence
│       ├── security-scanners/ # Scoped Nuclei, ZAP, Dalfox, and sqlmap adapters
│       └── e2e-browser/ # Portable target profiles, persona workflows, and browser evidence
├── demo-apps/
│   ├── demo-app-01/   # Controlled e-commerce target app (dual-mode: vulnerable / fixed)
│   ├── demo-app-02/   # Fastify + JWT + PostgreSQL + Redis microservice for discovery robustness
│   ├── demo-app-03/   # Server-rendered portal with form redirects and CSRF
│   └── demo-app-04/   # SPA with multi-step authentication and sessionStorage tokens
└── LICENSE            # Apache 2.0 License
```

- **`apps/frontend`**: React + TypeScript workspace for discovery, application models, browser workflows, source scans, hypotheses, test plans, and finding evidence. Plans show readiness, missing inputs, and rule coverage. Results are saved locally; demo examples are labelled synthetic. Runtime test execution remains unconfigured. See [frontend setup and boundaries](apps/frontend/README.md).
- **`packages/core`**: Contains the decoupled domain model (`Project`, `Endpoint`, `Identity`, `Evidence`, `Finding`), provider interfaces, and the core pipeline orchestrator.
- **`packages/a01`**: Tests selected resources as an owner, a forbidden second user, and an anonymous client. Uses isolated browser logins, declared access policies, private content comparisons, stored proof, and verification for CWE-639 and CWE-862. Provides an API and JSON-report CLI. See [access control setup and limits](packages/a01/README.md).
- **`packages/a02`**: Runs discovery, hypotheses, planning, guarded cookie/CORS probes, retained evidence, and verification for CWE-1004, CWE-614, and CWE-942. Both cookie rules share one collection. Provides an API and JSON-report CLI. See [assessment setup and usage](packages/a02/README.md).
- **`packages/a05`**: Connects Semgrep input locations to targeted XSS and SQL probes, Dalfox/sqlmap adapters, browser execution proof, retained evidence, and verification. Provides an API and private JSON-report CLI. See [injection assessment setup and limits](packages/a05/README.md).
- **`packages/evidence`**: Stores immutable, redacted observations with probe, capability, and target provenance. Supports a local append-only journal and portable finding proof bundles. See [evidence setup, retention, and integrity limits](packages/evidence/README.md).
- **`packages/verifier`**: Checks retained runtime proof before accepting CWE verdicts. Binds completed tests to their hypothesis, target, environment, and capabilities. Validates citations for optional model explanations. See [judge setup and verification limits](packages/verifier/README.md).
- **`packages/reporting`**: Exports developer reports in JSON and Markdown with immutable evidence links, source locations, test steps, supplied remediation, and explicit finding states. See [report setup and examples](packages/reporting/README.md).
- **`packages/retest`**: Applies reviewed repairs in temporary source copies, runs security and normal-use tests, and replays the original probe. Records before/after proof with separate fix statuses. See [fix verification and host integration](packages/retest/README.md).
- **Evaluation**: Repeats all seven controlled demo cases in vulnerable and fixed modes. Compares injection results with native scanner candidates and records accuracy, requests, time, model use, and proof. See [evaluation results and reproduction](docs/evaluation.md).
- **`plugins/remediation`**: Generates root-cause explanations, unified diffs, and regression tests for confirmed findings on reviewed Express storefront source revisions. Uses the existing core provider interface and checks retained source hashes. Applying fixes and retesting findings remain separate. See [supported repairs and usage](plugins/remediation/README.md).
- **`packages/discovery`**: Reads manifests and source syntax to identify languages, frameworks, dependencies, probable databases/authentication/middleware, and repository structure. It selects black-box mode when the stack is unsupported or a compatible Express adapter is unavailable. See [discovery usage and verification](packages/discovery/README.md).
- **`packages/workflow`**: Chooses trusted recipes or optional semantic model proposals, validates current page references and credential permissions, and enforces finite planning budgets. Model input uses redacted page models; the browser executes approved actions. See [workflow registration and boundaries](packages/workflow/README.md).
- **`packages/runtime`**: Provides scoped HTTP/browser capabilities and reusable cookie, cross-origin, authorization, XSS and SQL probes. Probes return immutable observations for later policy interpretation. See [runtime setup, usage, and boundaries](packages/runtime/README.md).
- **`packages/security-model`**: Merges source, browser and runtime observations into a framework-independent application model with canonical endpoints, provenance, configuration, data-flow candidates and ownership observations. See [model assembly and merge rules](packages/security-model/README.md).
- **`plugins/cwe`**: Provides all seven CWE rules, independent registration, model-based candidates, declarative probe plans and evidence-linked verdicts. Rules interpret normalized observations and explicit application policy. See [rule setup, proof requirements and execution boundaries](plugins/cwe/README.md).
- **`packages/hypothesis-engine`**: Grounds registered CWE candidates in relevant model observations, attaches concrete reasons and evidence references, and optionally reviews bounded context through a model provider. Results remain hypotheses requiring runtime verification. See [hypothesis generation and reasoning boundaries](packages/hypothesis-engine/README.md).
- **`packages/test-planner`**: Converts hypotheses into ordered, tool-independent probe plans for all seven CWEs, with private input references, explicit prerequisites and structured verification criteria. See [planning setup and execution boundaries](packages/test-planner/README.md).
- **`packages/capability-registry`**: Selects available adapter ports for plans and probes using protocol, CWE support and risk metadata. Supports multiple tools, stable fallback and bounded preflight checks. See [registration, selection and execution boundaries](packages/capability-registry/README.md).
- **`packages/policy-engine`**: Checks approved targets, methods, tools, risk and request limits before execution. Binds scoped runtime capabilities with optional human approval and audit records that omit private data. See [policy setup, approval and runtime boundaries](packages/policy-engine/README.md).
- **`plugins/models/openai`**: Optional structured-generation provider with explicit model selection, backend API-key resolution, bounded transport, and sanitized results. See [provider setup](plugins/models/openai/README.md).
- **`plugins/frameworks/express`**: Uses Noir as the default static endpoint provider. AgentO checks route paths and source records, adds middleware, input and security observations, and blocks tests for unvalidated inventory. See [adapter setup, verification, and boundaries](plugins/frameworks/express/README.md) and [adoption checks](docs/noir-adoption.md).
- **`plugins/tools/semgrep`**: Implements the core static analyzer with bundled JS/TS taint rules for XSS and SQL injection candidates, normalized source/sink evidence, bounded AST context, and optional precomputed Express endpoint association. Static signals require runtime verification. See [installation, CLI, integration, and limitations](plugins/tools/semgrep/README.md).
- **`plugins/tools/security-scanners`**: Runs Nuclei, ZAP, Dalfox, and sqlmap through scoped executor ports. Returns immutable results and redacted candidate evidence, with policy bindings, tool replacement, and isolated failures. See [native tool setup, supported modes, and limits](plugins/tools/security-scanners/README.md).
- **`plugins/tools/e2e-browser`**: Runs portable browser workflows through TesterArmy e2e and Chromium. Target profiles configure personas, authentication, origins, and workflow hints; recipes or bounded iterative planners drive the browser. Verified against a storefront and a distinct JWT SPA, with isolated saved sessions and normalized evidence. See [setup, examples, and compatibility](plugins/tools/e2e-browser/README.md).
- **`demo-apps/demo-app-01`**: A fully functional Node.js + TypeScript + Express + SQLite e-commerce application equipped with both vulnerable and patched implementations of each target CWE for reproducible validation.
- **`demo-apps/demo-app-02`**: A Fastify + JWT + PostgreSQL + Redis + Drizzle ORM microservice built to verify Project Discovery robustness against multi-language, multi-manifest, and non-Express stacks with automatic black-box fallback.

---

## Run the Frontend

Use Node.js 22.12 or later and Python 3.10 or later (for static security analysis). From the repository root:

### 1. Configure Environment & Static Analysis Tooling

AgentO uses pinned Semgrep Community Edition for static code analysis (CWE-79 XSS and CWE-89 SQL injection). Install it in a virtual environment and set up `.env`:

```sh
# 1. Create a virtual environment and install pinned Semgrep
python3 -m venv /tmp/agento-semgrep-venv
/tmp/agento-semgrep-venv/bin/python -m pip install -r plugins/tools/semgrep/requirements.txt

# 2. Configure environment (copy template)
cp .env.example .env
```

`AGENTO_SEMGREP_EXECUTABLE=/tmp/agento-semgrep-venv/bin/semgrep` is predefined in `.env` and `.env.example`. The frontend execution service also automatically checks `/tmp/agento-semgrep-venv/bin/semgrep` and `plugins/tools/semgrep/.venv/bin/semgrep` before falling back to `semgrep` on system `$PATH`.

Install Noir 1.4.0 after installing the Express adapter's dependencies:

```sh
npm run setup:noir --prefix plugins/frameworks/express
```

The Linux x64 installer verifies the release checksum. Other hosts can install
Noir separately and set `AGENTO_NOIR_EXECUTABLE`. Noir supplies static inventory;
AgentO validates and enriches it before test planning.

### 2. Start the Frontend Workspace

```sh
cd apps/frontend
npm ci
npm run dev
```

The local workspace saves projects, discovery, and the latest scan results on disk.
**Run static scan** runs repository discovery and the installed Semgrep adapter;
scan progress, candidate findings, source evidence, and remediation guidance come
from that execution. Runtime verification remains unavailable, so static candidates
are hypotheses. The seeded demo retains its synthetic labels.

Build the host packages and install Semgrep to enable live scans. The interface
also supports saved discovery imports without those tools. See the
[frontend guide](apps/frontend/README.md) for setup, storage, and execution limits.

Run `npm run check` in `apps/frontend` to typecheck, build, and test the client.

---

## License

AgentO is open-source software licensed under the [Apache License 2.0](LICENSE).

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
│   └── frontend/      # Projects, discovery, and static scan evidence
├── packages/
│   ├── core/          # Tool-independent contracts, domain types, and orchestrator
│   ├── discovery/     # Repository metadata, stack detection, and mode selection
│   ├── runtime/       # Scoped HTTP, browser sessions, cookie/header and network observations
│   ├── security-model/ # Evidence-preserving source, browser and runtime application model
│   └── workflow/      # Recipe-first and optional semantic planning with action validation
├── plugins/
│   ├── frameworks/
│   │   └── express/   # Express routes, middleware, configuration, and source evidence
│   ├── models/
│   │   └── openai/    # Optional bounded structured-generation provider
│   └── tools/
│       ├── semgrep/   # Normalized static XSS/SQLi candidates and source/sink evidence
│       └── e2e-browser/ # Portable target profiles, persona workflows, and browser evidence
├── demo-apps/
│   ├── demo-app-01/   # Controlled e-commerce target app (dual-mode: vulnerable / fixed)
│   ├── demo-app-02/   # Fastify + JWT + PostgreSQL + Redis microservice for discovery robustness
│   ├── demo-app-03/   # Server-rendered portal with form redirects and CSRF
│   └── demo-app-04/   # SPA with multi-step authentication and sessionStorage tokens
└── LICENSE            # Apache 2.0 License
```

- **`apps/frontend`**: React + TypeScript workspace for project setup, saved discovery imports, scan progress, and finding evidence. Scan and finding views currently use clearly labelled demo fixtures. See [frontend setup and boundaries](apps/frontend/README.md).
- **`packages/core`**: Contains the decoupled domain model (`Project`, `Endpoint`, `Identity`, `Evidence`, `Finding`), provider interfaces, and the core pipeline orchestrator.
- **`packages/discovery`**: Reads manifests and source syntax to identify languages, frameworks, dependencies, probable databases/authentication/middleware, and repository structure. It selects black-box mode when the stack is unsupported or a compatible Express adapter is unavailable. See [discovery usage and verification](packages/discovery/README.md).
- **`packages/workflow`**: Chooses trusted recipes or optional semantic model proposals, validates current page references and credential permissions, and enforces finite planning budgets. Model input uses redacted page models; the browser executes approved actions. See [workflow registration and boundaries](packages/workflow/README.md).
- **`packages/runtime`**: Provides deterministic HTTP execution, response collection, header/cookie parsing, browser lifecycle, isolated authentication sessions, and network observations through injected capabilities. See [runtime setup, usage, and boundaries](packages/runtime/README.md).
- **`packages/security-model`**: Merges source, browser and runtime observations into a framework-independent application model with canonical endpoints, provenance, configuration, data-flow candidates and ownership observations. See [model assembly and merge rules](packages/security-model/README.md).
- **`plugins/models/openai`**: Optional structured-generation provider with explicit model selection, backend API-key resolution, bounded transport, and sanitized results. See [provider setup](plugins/models/openai/README.md).
- **`plugins/frameworks/express`**: Implements the core framework adapter for read-only JS/TS route extraction, mounted middleware, request inputs, session/cookie/CORS configuration, and database observations. Recognizes all 19 declared demo routes and integrates with discovery through explicit adapter registration. See [adapter setup, verification, and boundaries](plugins/frameworks/express/README.md).
- **`plugins/tools/semgrep`**: Implements the core static analyzer with bundled JS/TS taint rules for XSS and SQL injection candidates, normalized source/sink evidence, bounded AST context, and optional precomputed Express endpoint association. Static signals require runtime verification. See [installation, CLI, integration, and limitations](plugins/tools/semgrep/README.md).
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

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Static Analysis Integration (`plugins/tools/semgrep`)**: Added a read-only Semgrep adapter, focused JS/TS XSS and SQL injection candidate rules, normalized source/sink evidence with AST and framework context, and a standalone JSON CLI. Static signals remain candidates requiring runtime verification.
- **Static Analysis Verification and Documentation**: Added pinned Semgrep installation instructions, core registration examples, execution limits and diagnostics, candidate-only limitations, unit/process tests, and real-tool demo plus unsafe/fixed JS/TS integration tests.
- **Discovery Automation CLI Script (`scripts/discover.mjs`)**: Added a dedicated CLI script allowing selective discovery execution against any selected demo project (e.g. `node scripts/discover.mjs demo-app-02`) or custom repository path, writing project-local `discovery.json` snapshots directly inside target directories.
- **Frontend Local Discovery Dev Bridge (`apps/frontend`)**: Added Vite dev server middleware (`/api/discover` and `/api/demo-apps`) and interactive UI controls in the New Project and Import Discovery dialogs to run discovery directly against local repository paths and quick-load demo projects with a single click.
- **Demo Application 02 (`demo-apps/demo-app-02`)**: Added a Fastify + JWT + PostgreSQL + Redis + Drizzle ORM microservice demonstrating multi-language (TypeScript, JavaScript, Python), multi-manifest (`package.json`, `contracts/package.json`), type-only import filtering, remote URL version masking, and custom CORS headers. Verifies the robustness of Project Discovery stack detection and graceful black-box mode fallback.
- **Express Framework Adapter (`plugins/frameworks/express`)**: Added read-only JS/TS extraction of mounted routes, request inputs, authentication/authorization guards, session/cookie/CORS configuration, and SQL operation metadata with normalized source evidence, redaction, bounded traversal, and incomplete-extraction diagnostics. Includes a standalone JSON CLI, real discovery/core integration, and 31 tests covering all 19 declared demo routes.
- **Express Adapter Documentation**: Added setup, API registration, evidence format, verification, and extraction limitations; updated root and discovery READMEs to link the implemented adapter.
- **AgentO Frontend (`apps/frontend`)**: Added a React + TypeScript workspace for project setup, validated saved discovery imports, stack and adapter summaries, and clearly labelled scan, finding, evidence, and remediation fixtures. Includes responsive layouts, keyboard-accessible forms, loading/error/empty states, a replaceable asynchronous client, and 41 client tests.
- **Frontend Documentation**: Added local development, build, verification, and integration instructions; documented session-only storage and backend execution boundaries in the frontend and root READMEs, and updated the discovery README's adapter milestone reference.
- **Project Discovery (`packages/discovery`)**: Implemented repository scanner that inspects manifests and source code to detect languages, frameworks (Express), dependencies, databases (SQLite), auth sessions, and middleware, selecting code-aware or black-box scanning mode.
- **Documentation**: Updated root `README.md` with `packages/discovery` reference and usage link.

### Changed

- **Project Discovery Verification (`packages/discovery`)**: Added automated integration test validating end-to-end repository discovery and black-box mode fallback against `demo-apps/demo-app-02`.
- **Demo Application Reorganization (`demo-apps/demo-app-01`)**: Relocated the target e-commerce demo application from `demo-app/` into `demo-apps/demo-app-01/` to support multiple structured demonstration targets. Updated discovery integration tests, root `.gitignore`, and documentation paths accordingly.
- **AgentO Frontend UI Presentation (`apps/frontend`)**: Elevated the interface to a high-end cybersecurity workspace aesthetic featuring deep obsidian surfaces, glassmorphic frosted cards, radiant AgentO orange accents, glowing semantic badges for finding states and severities, Inter and JetBrains Mono typography, animated scan replay timeline shimmers, and refined responsive dialogs while preserving all existing component logic, routing, schemas, and test contracts.

## [0.1.0] - 2026-10-10

### Added

- **Documentation (`bd84bd7`)**: Added root `README.md` with project vision, OWASP/CWE scope, repository overview, and scanning pipeline architecture diagram.
- **AgentO Core Contracts and Orchestrator (`ca6457e`)**:
  - Defined tool-independent provider contracts (`StaticAnalyzer`, `BrowserWorkflowDriver`, `SecurityScanner`, `FrameworkAdapter`, `CWEPlugin`, `ReasoningModel`, `RemediationProvider`).
  - Defined core domain models (`Project`, `Endpoint`, `Identity`, `Resource`, `SecurityHypothesis`, `Evidence`, `Finding`).
  - Implemented `AgentOOrchestrator` pipeline with provider abstraction and evidence provenance preservation.
  - Added interface fakes and 15 unit tests verifying orchestration and failure isolation.
- **Vulnerable Demo Application (`c1271f7`)**:
  - Implemented Node.js + TypeScript + Express + SQLite e-commerce target app (`demo-app`).
  - Added test user accounts and roles (`Alice`, `Bob`, `Admin`).
  - Implemented dual-mode (vulnerable vs. fixed) behavior for all 7 scope CWEs: CWE-639, CWE-862, CWE-942, CWE-1004, CWE-614, CWE-79, and CWE-89.
  - Added interactive testing web UI and 18 automated security verification test cases in Vitest.

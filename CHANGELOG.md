# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **AgentO Frontend (`apps/frontend`)**: Added a React + TypeScript workspace for project setup, validated saved discovery imports, stack and adapter summaries, and clearly labelled scan, finding, evidence, and remediation fixtures. Includes responsive layouts, keyboard-accessible forms, loading/error/empty states, a replaceable asynchronous client, and 41 client tests.
- **Frontend Documentation**: Added local development, build, verification, and integration instructions; documented session-only storage and backend execution boundaries in the frontend and root READMEs, and updated the discovery README's adapter milestone reference.
- **Project Discovery (`packages/discovery`)**: Implemented repository scanner that inspects manifests and source code to detect languages, frameworks (Express), dependencies, databases (SQLite), auth sessions, and middleware, selecting code-aware or black-box scanning mode.
- **Documentation**: Updated root `README.md` with `packages/discovery` reference and usage link.

### Changed

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

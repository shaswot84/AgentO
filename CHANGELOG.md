# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Project Discovery (`packages/discovery`)**: Implemented repository scanner that inspects manifests and source code to detect languages, frameworks (Express), dependencies, databases (SQLite), auth sessions, and middleware, selecting code-aware or black-box scanning mode.
- **Documentation**: Updated root `README.md` with `packages/discovery` reference and usage link.

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

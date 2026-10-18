# AgentO Demo Application 05 — Enterprise Cloud Ops Console

A modern single-page dashboard designed to stress-test **LLM-assisted semantic browser planning across dynamic UI patterns (client-side tabs, modal dialogs, and indirect domain terminology)** without relying on hardcoded selectors or workflow recipes.

---

## 1. Architectural & UI Characteristics

- **Architecture**: Single-Page Console with Client-Side Tab & Modal State Management
- **Framework**: Express (`express`) with Cookie Sessions (`cookie-parser`)
- **Authentication**: Form-based authentication (`/sign-in`) with credential validation and HTTP 302 redirect
- **Semantic Challenges**:
  - **Indirect Terminology**: Uses domain-specific operations terminology (`"Threats & Triage"` instead of `"Security Incidents"`, `"Examine Incident"` instead of `"View Details"`, `"Acknowledge & Escalate"` instead of `"Submit"`).
  - **Tab-Gated DOM Views**: The incident queue is rendered in a secondary tab (`#panel-threats`) that is hidden (`display: none`) until the `"Threats & Triage"` tab is activated.
  - **Modal Dialog Interaction**: Inspecting an incident triggers an in-page modal dialog (`<div role="dialog" id="incident-modal">`) requiring contextual focus and state acknowledgment.
  - **Asynchronous Mutation**: Acknowledging an incident triggers an asynchronous background API dispatch (`POST /api/triage/:id/acknowledge`) and updates live DOM status indicators.

---

## 2. Personas and Credentials

| Persona ID | Handle | Passphrase | Role | Department |
|---|---|---|---|---|
| `responder` | `responder.alice` | `Responder!42` | `incident-responder` | `SecOps-Triage` |
| `commander` | `commander.bob` | `Commander!42` | `incident-commander` | `SecOps-Command` |

---

## 3. Quick Start

```bash
cd demo-apps/demo-app-05
npm install
npm run dev
```

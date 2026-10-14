# AgentO Demo Application 04 — Modern Edge-Case SPA & Enterprise Workflow App

A modern Single-Page Application (SPA) designed to test the **robustness, failure boundaries, and extensibility limits of AgentO's Browser Workflow Adapter**.

---

## 1. Architectural Characteristics

- **Architecture**: Single-Page Application (SPA) with Dynamic Client-Side DOM Rendering
- **Framework**: Express (`express`) backend API with Vanilla JavaScript SPA frontend
- **Authentication**:
  - **Multi-Step Flow**: Step 1 Identifier Lookup (`/api/auth/lookup`) -> Dynamic Reveal of Passphrase Field -> Step 2 Submit (`/api/auth/login`)
  - **`sessionStorage` Token Persistence**: Signed JWT stored in `window.sessionStorage` rather than `localStorage` or cookies
- **Real-Time & Boundary Services**:
  - Live WebSocket stream (`/ws/live` via `ws`)
  - Web Worker support (`/worker.js`)
  - Simulated unapproved CDN requests (`/escape/cdn`)

---

## 2. Portability Testing Role

This application validates key edge cases and failure modes identified in the compatibility contract:

1. **Multi-Step Authentication Limits**:
   - `FormLoginStrategy` assumes simultaneous username and password form fields. On a multi-step login, `FormLoginStrategy` fails or times out.
   - Proves the need for declarative custom `AuthenticationStrategy` with multi-action preparation sequences (`fill`, `click`, `wait-visible`, `fill-credential`, `submit`).
2. **`sessionStorage` Persistence Boundary**:
   - Playwright's `context.storageState()` only serializes cookies and `localStorage` origins; it does **not** capture `sessionStorage`.
   - Proves that `sessionStorage`-based SPAs cannot reuse saved sessions in fresh browser contexts without re-authenticating.
3. **Strict Origin & Single-Page Scope Enforcement**:
   - Background WebSockets, Web Workers, and unapproved CDN requests are intercepted and blocked (`websocket-unsupported`, `worker-unsupported`, `origin-scope`).
   - Verifies that any blocked background request triggers `scope-denied` and sets the workflow outcome to `FAILED`, even if the primary page completed.

---

## 3. Personas and Credentials

| Persona ID | Handle | Password | Role | Telemetry ID |
|---|---|---|---|---|
| `operator` | `operator` | `Operator!42` | `operator` | `TEL-900` |
| `supervisor` | `supervisor` | `Supervisor!42` | `supervisor` | `TEL-901` |

---

## 4. Quick Start

```bash
cd demo-apps/demo-app-04
npm install
npm run dev
```

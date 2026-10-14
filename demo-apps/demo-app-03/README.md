# AgentO Demo Application 03 — SSR Multi-Page Portal

A server-side rendered (SSR) Multi-Page Application (MPA) built with Express, designed to test the **browser portability limits and target profile robustness of AgentO's Browser Workflow Adapter**.

---

## 1. Architectural Characteristics

- **Architecture**: Multi-Page Application (MPA) with Server-Side Rendering
- **Framework**: Express (`express`)
- **Authentication**: Traditional HTML form submission with CSRF token verification and HTTP 302/303 redirect
- **Session Management**: Server-side session mapping with `HttpOnly`, `SameSite=Lax` cookies
- **Verification Model**: Rendered DOM text matching (`#user-display`, `#role-display`) rather than client-side JSON API inspection
- **Workflows**: Multi-page navigation (`/login` -> 302 -> `/dashboard` -> `/reports` -> `/reports/:id`)

---

## 2. Portability Testing Role

This application tests:
1. **HTML Form 302/303 Redirects**: Validates how `FormLoginStrategy` handles HTTP 302 redirection responses from non-AJAX form submissions.
2. **CSRF-Protected Logins**: Verifies that automated browser form submission properly preserves server-rendered hidden input tokens without requiring manual script injection.
3. **Pure DOM Verification**: Evaluates session verification against server-rendered HTML elements instead of JSON identity endpoints.
4. **Session Cookie Isolation**: Verifies multi-identity isolation (`analyst` vs `admin`) and session persistence across browser contexts.

---

## 3. Personas and Credentials

| Persona ID | Username | Password | Role | Target Report |
|---|---|---|---|---|
| `analyst` | `analyst` | `Analyst!123` | `auditor` | `REP-501` |
| `admin` | `admin` | `Admin!123` | `administrator` | `REP-999` |

---

## 4. Quick Start

```bash
cd demo-apps/demo-app-03
npm install
npm run dev
```

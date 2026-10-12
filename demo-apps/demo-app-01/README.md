# AgentO Demo Application — Phase 1 Target Environment

A controlled, dual-mode (Vulnerable / Fixed) Node.js + TypeScript + Express + SQLite e-commerce application built as the primary testbed for AgentO.

---

## 1. Quick Start

### Installation

```bash
cd demo-apps/demo-app-01
npm install
```

### Running the App

```bash
# Start in development mode (auto-reload)
npm run dev

# Or compile and run
npm run build
npm start
```

The application runs at: `http://localhost:3000`

### Running the Verification Test Suite

```bash
npm test
```

All 18 security tests verify both vulnerable and fixed implementations across all 7 target CWEs.

---

## 2. Test Personas

The SQLite database seeds three user accounts automatically:

| Username | Password | Role | Persona Description | Owned Seed Resources |
| :--- | :--- | :--- | :--- | :--- |
| `alice` | `alice123` | `customer` | Standard customer | Orders #101, #102 |
| `bob` | `bob123` | `customer` | Standard customer | Order #201 |
| `admin` | `admin123` | `admin` | System Administrator | Order #301, Admin Console |

---

## 3. Dual-Mode Architecture (Vulnerable vs. Fixed)

AgentO requires comparing scanner signals and test executions against known-vulnerable and known-fixed versions of each vulnerability.

### Switching Modes

1. **Environment Variable**:
   ```bash
   SECURITY_MODE=vulnerable npm start  # Default: all 7 CWEs active
   SECURITY_MODE=fixed npm start       # Hardened: all 7 CWEs patched
   ```

2. **API Endpoint / Runtime Toggle**:
   ```bash
   curl -X POST http://localhost:3000/api/config/security-mode \
     -H "Content-Type: application/json" \
     -d '{"mode": "fixed"}'
   ```

3. **Per-Request Header / Query Param** (ideal for automated scanning):
   - Header: `X-Security-Mode: fixed` or `X-Security-Mode: vulnerable`
   - Query: `?security_mode=fixed` or `?security_mode=vulnerable`

---

## 4. CWE Scope & Vulnerability Matrix

| CWE | Name | Category | Endpoint | Vulnerable File |
| :--- | :--- | :--- | :--- | :--- |
| **CWE-639** | IDOR / User-Controlled Key | A01 Broken Access Control | `GET /api/orders/:id` | `src/routes/orders.ts` |
| **CWE-862** | Missing Authorization | A01 Broken Access Control | `GET /api/admin/users` | `src/middleware/auth.ts`, `src/routes/admin.ts` |
| **CWE-942** | Permissive Cross-domain Policy | A02 Security Misconfiguration | CORS (All routes) | `src/middleware/cors.ts` |
| **CWE-1004**| Missing `HttpOnly` Cookie | A02 Security Misconfiguration | `POST /api/auth/login` | `src/middleware/auth.ts`, `src/app.ts` |
| **CWE-614** | Missing `Secure` Cookie Flag | A02 Security Misconfiguration | `POST /api/auth/login` | `src/middleware/auth.ts`, `src/app.ts` |
| **CWE-79**  | Cross-site Scripting (XSS) | A05 Injection | `GET /search?q=` | `src/routes/search.ts` |
| **CWE-89**  | SQL Injection (SQLi) | A05 Injection | `GET /api/search?q=` | `src/routes/search.ts` |

---

## 5. Detailed Reproduction Guide

### CWE-639: IDOR / Insecure Direct Object Reference

- **Location**: `src/routes/orders.ts`
- **Mechanism**:
  - *Vulnerable*: Query `SELECT * FROM orders WHERE id = ?` executes without checking `order.user_id === req.session.user.id`.
  - *Fixed*: Verifies user ownership or admin role. Returns `403 Forbidden` if user does not own the order.
- **Reproduction**:
  1. Authenticate as Bob (`bob` / `bob123`):
     ```bash
     curl -c bob_cookies.txt -X POST http://localhost:3000/api/auth/login \
       -H "Content-Type: application/json" \
       -d '{"username":"bob","password":"bob123"}'
     ```
  2. Request Alice's Order #101:
     ```bash
     curl -b bob_cookies.txt http://localhost:3000/api/orders/101
     ```
  3. *Result*: In vulnerable mode, Bob receives Alice's order with shipping address. In fixed mode, Bob receives `403 Forbidden`.

---

### CWE-862: Missing Authorization

- **Location**: `src/middleware/auth.ts` (`requireAdmin`) & `src/routes/admin.ts`
- **Mechanism**:
  - *Vulnerable*: `requireAdmin` fails to verify `req.session.user.role === 'admin'`.
  - *Fixed*: Enforces `req.session.user.role === 'admin'`. Returns `403 Forbidden` for non-admin accounts.
- **Reproduction**:
  1. Authenticate as Alice (`alice` / `alice123`):
     ```bash
     curl -c alice_cookies.txt -X POST http://localhost:3000/api/auth/login \
       -H "Content-Type: application/json" \
       -d '{"username":"alice","password":"alice123"}'
     ```
  2. Access the protected administration endpoint:
     ```bash
     curl -b alice_cookies.txt http://localhost:3000/api/admin/users
     ```
  3. *Result*: In vulnerable mode, Alice views full user records. In fixed mode, request is rejected with `403 Forbidden`.

---

### CWE-942: Permissive Cross-domain Policy (CORS)

- **Location**: `src/middleware/cors.ts`
- **Mechanism**:
  - *Vulnerable*: Dynamically reflects untrusted `Origin` headers with `Access-Control-Allow-Credentials: true`.
  - *Fixed*: Rejects untrusted origins (returns `Access-Control-Allow-Origin: null`).
- **Reproduction**:
  ```bash
  curl -I -H "Origin: https://evil-attacker.example" http://localhost:3000/api/products
  ```
- *Result*:
  - Vulnerable: `Access-Control-Allow-Origin: https://evil-attacker.example` and `Access-Control-Allow-Credentials: true`.
  - Fixed: `Access-Control-Allow-Origin: null`.

---

### CWE-1004 & CWE-614: Sensitive Cookie Security Flags

- **Location**: `src/middleware/auth.ts` (`attachSessionCookies`)
- **Mechanism**:
  - *Vulnerable*: Session token cookie `auth_token` is issued without `HttpOnly` and without `Secure`.
  - *Fixed*: Session cookie is issued with `HttpOnly; Secure; SameSite=Lax`.
- **Reproduction**:
  ```bash
  curl -i -X POST http://localhost:3000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"alice123"}'
  ```
- *Result*:
  - Vulnerable: `Set-Cookie: auth_token=sess_alice_...; Path=/` (lacks HttpOnly and Secure).
  - Fixed: `Set-Cookie: auth_token=sess_alice_...; Path=/; HttpOnly; Secure; SameSite=Lax`.

---

### CWE-79: Cross-Site Scripting (Reflected XSS)

- **Location**: `src/routes/search.ts` (`GET /search`)
- **Mechanism**:
  - *Vulnerable*: Reflects `req.query.q` directly into server-rendered HTML.
  - *Fixed*: Escapes HTML entities (`&`, `<`, `>`, `"`, `'`).
- **Reproduction**:
  1. Open browser or curl:
     ```bash
     curl "http://localhost:3000/search?q=%3Cscript%3Ealert('XSS')%3C%2Fscript%3E"
     ```
  2. *Result*:
     - Vulnerable: `<span id="search-query-target"><script>alert('XSS')</script></span>`
     - Fixed: `<span id="search-query-target">&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;</span>`

---

### CWE-89: SQL Injection

- **Location**: `src/routes/search.ts` (`GET /api/search`)
- **Mechanism**:
  - *Vulnerable*: Concatenates unescaped user string into `SELECT ... WHERE name LIKE '%${q}%'`.
  - *Fixed*: Prepared statements with parameter placeholders `?`.
- **Reproduction**:
  ```bash
  curl "http://localhost:3000/api/search?q=%27%20UNION%20SELECT%20id%2C%20username%2C%20password%2C%20role%2C%20email%2C%20full_name%20FROM%20users%20--"
  ```
- *Result*:
  - Vulnerable: SQL executes UNION query; returns all seeded user accounts including passwords and roles.
  - Fixed: Parameterized query treats string as a literal; returns 0 rows.

---

## 6. Exit Criteria Verification

All Phase 1 exit criteria defined in `AgentO_Phased_Project_Plan.md` are fulfilled:

- [x] **App runs locally**: Node.js + TypeScript + Express + SQLite setup.
- [x] **Alice, Bob, and Admin can log in**: Seeded identities with distinct privileges and resources.
- [x] **Every selected CWE has one known vulnerable case**: CWE-639, CWE-862, CWE-942, CWE-1004, CWE-614, CWE-79, CWE-89.
- [x] **Every case has a known fixed implementation**: Switchable globally or per request via `X-Security-Mode`.
- [x] **Manual reproduction documented**: Clear curl and browser instructions.
- [x] **Automated test suite passing**: 18 automated tests passing in `npm test`.

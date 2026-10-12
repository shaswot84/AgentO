# AgentO Demo Application 02 — Payment & Token Service

A standalone Fastify microservice designed to validate the **robustness and stack-detection accuracy of the AgentO Project Discovery layer**.

---

## 1. Stack Characteristics

- **Framework**: Fastify (`fastify`)
- **Authentication**: JWT token issuance and verification (`@fastify/jwt`, `@fastify/cookie`)
- **Databases & Cache**: PostgreSQL client (`pg`) and Redis client (`ioredis`)
- **ORM**: Drizzle ORM (`drizzle-orm`)
- **Languages**: TypeScript, JavaScript, Python
- **Middleware**: `@fastify/cors`, `@fastify/cookie`, plus custom CORS headers

---

## 2. Discovery Layer Verification Role

This repository provides non-standard stack diversity to verify that AgentO's Discovery engine:
1. Accurately inventories multi-package and multi-manifest repositories (`package.json` + `contracts/package.json`).
2. Identifies non-Express frameworks (`fastify`).
3. Recognizes database and ORM stacks without claiming unimported runtime packages (e.g. type-only imports like `@prisma/client`).
4. Masks sensitive credentials or remote dependency references.
5. Automatically and gracefully falls back to `black-box` scanning mode when no compatible Express framework adapter is registered.

---

## 3. Quick Start

### Installation

```bash
cd demo-apps/demo-app-02
npm install
```

### Running Tests

```bash
npm test
```

### Type Checking & Build

```bash
npm run typecheck
npm run build
```

# AgentO Discovery — Phase 3

Read-only repository discovery for the initial JavaScript/TypeScript + Express
stack. It runs independently of browsers, security scanners, a running target,
and the future Express extraction adapter.

## Run

Requires Node.js 22 or later and npm. Build the local core contract package first:

```sh
cd packages/core
npm ci
npm run build
cd ../discovery
npm ci
npm run check
npm run discover -- ../../demo-app
```

From the repository root, after building, print plain JSON without npm's banner:

```sh
node packages/discovery/dist/cli.js demo-app
```

The CLI exits successfully for recognized, unsupported, and empty repositories.
An unavailable repository, malformed manifest, failed read/parser, or exceeded
limit produces structured diagnostics and exit code 1. `--help` prints usage.
Discovery does not execute package scripts, import target modules, contact hosts,
or run security tests.

## Demo result

Selected fields from discovery of `demo-app/`:

```json
{
  "languages": ["javascript", "typescript"],
  "frameworks": ["express"],
  "databases": ["sqlite"],
  "orms": [],
  "authentication": ["session"],
  "authenticationPackages": ["express-session"],
  "expressAdapterAvailable": false,
  "availableAdapterIds": [],
  "supportedCodeAwareMode": false,
  "mode": "black-box",
  "fallbackReasons": ["No Express framework adapter is registered."],
  "diagnostics": []
}
```

The backend is TypeScript; the public frontend contributes JavaScript. Dependencies
identify `better-sqlite3`, `express-session`, `cookie-parser`, and `cors`. Syntax
inspection also records the custom `Access-Control-Allow-Origin` header writes in
`src/middleware/cors.ts`, with file and line references.

The real Express adapter belongs to **Phase 5** and is not yet installed. Detecting
Express alone does not make an extraction adapter available. The CLI therefore
selects black-box mode; the tests separately demonstrate code-aware selection with
an injected fake adapter.

## API and core integration

```ts
import { discoverProject, toProject } from '@agento/discovery';
import type { FrameworkAdapter } from '@agento/core';

async function prepareProject(repositoryPath: string, expressAdapter: FrameworkAdapter) {
  const discovery = await discoverProject(repositoryPath, {
    adapters: [{
      framework: 'express',
      languages: ['javascript', 'typescript'],
      adapter: expressAdapter,
    }],
  });
  const project = toProject(discovery, {
    id: 'shop',
    baseUrl: 'http://localhost:3000',
    allowedOrigins: ['http://localhost:3000'],
  });
  return { discovery, project };
}
```

Omit `adapters` to discover metadata without any source extraction capability.
Only register installed implementations of the core `FrameworkAdapter` contract.
Discovery matches their advertised framework/languages; it never invokes
`supports()` or `extract()`. Pass the registered adapter as the core orchestrator's
`frameworkAdapter`; the core still calls `supports(project)` before extraction.
`expressAdapterAvailable` reports registration, while `availableAdapterIds` lists
registrations covering all detected application JS/TS languages.

`supportedCodeAwareMode` is true only when Express is detected, application JS/TS
source exists, a registered adapter covers its JS/TS languages, no unsupported
framework is detected, and discovery has no diagnostics. Otherwise `mode` is
`black-box`, with explicit `fallbackReasons`. Mixed framework repositories fall
back conservatively; selecting individual package roots can isolate a supported
Express application.

`toProject()` carries this mode and the languages into the Phase 2 `Project`
contract. The caller supplies the ID, target URL, and scope. This is metadata
selection, not target authorization or a policy-engine decision.

## Discovered facts and boundaries

- All nested `package.json` files are read. Package names, workspace patterns, and
  direct dependency names/versions retain manifest and dependency-section
  provenance. Transitive lockfile entries are excluded; remote dependency URLs
  are replaced with `[remote reference]` to avoid forwarding embedded credentials.
- Probable framework, database, ORM, authentication, and middleware hints come
  from runtime/optional dependencies and literal runtime imports, re-exports,
  `require()` calls, and dynamic imports. Type-only imports and test/fixture
  source do not establish a runtime stack. Development/peer dependencies remain
  in the inventory without establishing runtime hints by themselves.
- The recognition catalog can identify unsupported frameworks such as Fastify,
  Koa, NestJS, and Next.js. This does not add code-aware support for them. An
  unidentified framework also falls back. Database engines come from recognized
  drivers; a generic ORM alone does not establish its configured engine.
- Middleware observations distinguish package declarations/imports from custom
  literal CORS header calls (`setHeader`, `header`, or `set`). They are probable
  middleware hints, not proof of mounting, configuration, or vulnerability.
  Indirect imports, computed headers, and runtime configuration are not resolved.
- Languages come from source extensions (including frontend and test files).
  A Node manifest without source provides a JavaScript metadata hint but does not
  enable code-aware mode. Common non-Node manifests are inventoried without
  parsing their ecosystem-specific dependencies.
- Structure includes package roots, workspace patterns, source/test/static
  directories, all visited directories, and a source file count. Hidden
  directories, symlinks, dependencies, and common build/cache artifacts are
  skipped. Git is not required and `.gitignore` patterns are not interpreted.
- Traversal is bounded to 20,000 entries and 40 directory levels; each parsed
  manifest/source file is bounded to 1 MiB and total source parsing to 16 MiB.
  Exceeded limits and parser failures yield diagnostics and black-box fallback.
  The parser is pinned to TypeScript 5.9.3 under an npm alias; compilation uses
  the repository's TypeScript 7 toolchain.

The public result is deterministic and JSON-safe. No raw manifest or source text,
cookie/session values, route extraction, scanner findings, or configuration
judgments are returned. These belong to later phases.

## Verification

`npm run check` typechecks, builds JavaScript and declarations, and runs tests.
Tests identify the real demo, demonstrate compatible adapter registration and
core integration, prove black-box source-provider skipping, and cover unsupported
ecosystems/frameworks, nested packages, malformed manifests, ignored artifacts,
symlinks, literal imports, type-only imports, middleware provenance, unknown ORM
engines, size limits, parser failures, determinism, and credential-bearing URLs.

# AgentO Express Framework Adapter

Read-only JavaScript/TypeScript source extraction implementing the core
`FrameworkAdapter` contract. It resolves Express route topology and emits common
`Component`, `Endpoint`, and `Evidence` records. A running application, Express
installation in the adapter, browser, scanner, and reasoning model are unnecessary.

## Run independently

Requires Node.js 22 or later. From the repository root:

```sh
cd packages/core
npm ci
npm run build
cd ../discovery
npm ci
npm run build
cd ../../plugins/frameworks/express
npm ci
npm run check
npm run extract -- ../../../demo-apps/demo-app-01
```

Core is the production contract dependency; discovery is a development dependency
used to verify registration and orchestration. After building, print plain JSON
from the repository root:

```sh
node plugins/frameworks/express/dist/cli.js demo-apps/demo-app-01
```

The CLI returns code 1 when diagnostics indicate incomplete extraction, while
printing the available observations. `--help` prints usage. Unsupported and empty
repositories return an empty analysis. No target modules, package scripts,
database initialization, target configuration plugins, or network requests run.

## Extracted observations

- Declared HTTP methods, literal/constant/array paths, path parameters, route
  handlers, nested imported routers, repeated mounts, middleware arrays, and
  `route(path).get(...).post(...)` chains. `all()` expands to the seven methods
  represented by the core endpoint contract. Implicit HEAD handling and static
  asset routes are not synthesized.
- Path, query, body, header, and cookie reads, including bracket notation,
  destructuring, request aliases, and bounded local helper calls. Query/body
  `required` remains false because a source read alone does not establish
  validation. A `route` observation records whole-body usage in `bodyUsed`.
- Identity-dependent 401 guards and role-dependent 403 guards, with source
  references. Middleware is associated by registration order and mount scope.
  Conditional guards remain explicit observations; a conditional role check
  does not populate a required endpoint role. Unrecognized authentication
  remains `unknown`, even when a handler has an authentication-related name.
- Mounted `express-session`, `cookie-parser`, and `cors` configuration;
  response cookie options; request session-cookie assignments; custom CORS
  header writes; and literal origin allowlists used with `includes()`.
- SQL-like `prepare`, `query`, `execute`, `exec`, and prepared-statement
  `get`/`all`/`run` calls in handlers and helpers. Evidence includes operation,
  table names, interpolation, placeholder count, and argument count. SQL text
  and bound argument values are omitted.

ESM aliases, namespace imports, default exports, local re-exports, and common
literal CommonJS `require()`/`module.exports` patterns are resolved without
loading target code. Source locations are repository-relative and one-based.
IDs distinguish registrations, mounts, methods, paths, and projects; an injected
clock makes complete snapshots repeatable.

The controlled demo produces **19 declared endpoints** without diagnostics.
Authentication is recognized on orders, profile, and admin APIs. The conditional
admin role check, both search SQL branches, session defaults, dynamic cookie
updates, both login-cookie branches, and CORS reflection/allowlist observations
retain source evidence.

## Register with discovery and core

```ts
import { ExpressFrameworkAdapter } from '@agento/framework-express';
import { discoverProject, toProject } from '@agento/discovery';
import { AgentOOrchestrator } from '@agento/core';

const adapter = new ExpressFrameworkAdapter();
const discovery = await discoverProject(repositoryPath, {
  adapters: [{
    framework: 'express',
    languages: ['javascript', 'typescript'],
    adapter,
  }],
});
const project = toProject(discovery, {
  id: 'shop',
  baseUrl: 'http://localhost:3000',
  allowedOrigins: ['http://localhost:3000'],
});
const report = await new AgentOOrchestrator({
  plugins: [],
  frameworkAdapter: adapter,
}).run({ project, identities: [] });
```

Discovery selects `code-aware` mode for a compatible registered adapter and
supported application source. Its metadata-only CLI continues to use black-box
mode without an explicit registration. Core calls `supports()` before extracting;
this adapter requires readable JS/TS source and recognizable Express routes.
It returns false for repositories with read, parse, or traversal diagnostics.

For direct use, call `adapter.extract(project)`. The result extends
`FrameworkAnalysis` with `diagnostics`; callers should expose these diagnostics
when extraction is partial. The current core contract carries endpoints/evidence
but has no diagnostic channel, so direct adapter users retain this additional
detail. Resources and vulnerability signals stay empty: source extraction does
not create runtime resource instances, hypotheses, or verdicts.

## Evidence and limitations

Evidence uses `source-location` and `configuration` kinds and a stable
`facts.observation` discriminator: `route`, `authentication-guard`,
`authorization-guard`, `session`, `cookie-parser`, `cookie`,
`session-cookie-update`, `cors`, `cors-header`, `cors-origin-allowlist`, and
`database-operation`. Each record has project, producer, timestamp, endpoint,
source, and normalized JSON facts. Endpoint evidence IDs reference these records.

All observations set `runtimeVerified: false`. Guards and configuration branches
are syntax observations, not proof of deployed enforcement or vulnerability.
Secrets, passwords, credential options, cookie values, SQL argument values,
raw source, and credentials embedded in configuration URLs are excluded or
redacted. Dynamic values stay `{ "kind": "dynamic" }`; expressions are never
evaluated. Authentication analysis recognizes direct negative `request.user`
and `request.session.user` rejection patterns; custom authentication protocols
and complete control-flow/data-flow analysis require additional analyzers.

Computed paths, regular-expression routes, unresolved handlers, conditional
registrations, router cycles, failed reads/parses, and exceeded limits are
reported through diagnostics. Runtime router factories, aliases supplied by
external packages, TypeScript path aliases, monkey patches, arbitrary ORM APIs,
and cross-router fallthrough effects are outside this initial extractor. Root
apps are analyzed as declared, including application factories; their runtime
invocation is not proven. Router-only projects retain their local route paths.

Traversal skips hidden files, dependencies, common build output, test/fixture
source, and symlinks. It is bounded to 20,000 entries, 40 directory levels, 1 MiB
per source, and 16 MiB of source overall; route expansion is bounded to 10,000
endpoints and 40 mounts; helper/value resolution is bounded to 12 levels.
The syntax parser is pinned to TypeScript 5.9.3 under an npm alias, separately
from the repository's TypeScript compilation toolchain.

## Verification

`npm run check` typechecks, builds JavaScript/declarations, and runs 31 tests.
Tests cover all demo routes and configuration branches, imported handlers,
request inputs, database metadata, source provenance, redaction, repeated and
scoped mounts, route chains, CommonJS, partial extraction, limits, recursion,
non-execution, CLI behavior, and real discovery/core integration.

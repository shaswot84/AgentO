# AgentO Frontend

AgentO's local project and findings interface, built with React, TypeScript, and
Vite. It displays saved discovery results and clearly labelled demonstration
data while execution APIs are being developed.

## Run locally

Use Node.js 22.12 or later and npm. From the repository root:

```sh
cd apps/frontend
npm ci
npm run dev -- --host 127.0.0.1
```

Open the local URL printed by Vite. The frontend installs and builds independently;
it does not need the core or discovery packages built, a running target, a scanner,
or a browser automation service.

```sh
npm run check
npm run preview
```

`check` runs TypeScript checking, a production build, and tests. `preview` serves
the production build created by `check` or `npm run build`.

## Configure a project and import discovery

Create a project from the Projects view, supplying a name, repository path, target
URL, and explicitly allowed origins, one per line. The target's normalized origin
is included automatically until you customize **Allowed origins**. The form opens
that section and focuses the invalid field when scope validation fails.
**Attach saved discovery** is optional; its repository path populates an empty path
field. The form validates these inputs before creating a project:

- A name is required and limited to 120 characters.
- A repository path is required, limited to 4,096 characters, and cannot contain
  control characters.
- The target must be an HTTP(S) URL without embedded credentials, whitespace, or
  backslashes.
- Provide 1–100 explicit HTTP(S) origins without paths, queries, fragments,
  credentials, or wildcards. The target's normalized origin must be included.

The repository path is project metadata: entering it does not grant the browser
filesystem access or start discovery. The target
and origins describe intended scope; the interface does not authorize or enforce
security testing.

To produce a discovery file, first build the CLI in a terminal. From the repository
root:

```sh
cd packages/core
npm ci
npm run build
cd ../discovery
npm ci
npm run build
cd ../..
node packages/discovery/dist/cli.js /absolute/repository > /tmp/discovery.json
```

Replace `/absolute/repository` with the repository to inspect. Attach
`/tmp/discovery.json` in the New project form, or select an existing project and
use **Import JSON** on its Discovery view.

The browser reads the JSON file you select; the CLI performs repository reads.
During Vite development, **Discover**, the local demo shortcuts, and **Refresh**
on the Discovery view also call the existing local development bridge to inspect
a repository on the host. These controls require the discovery package (and Express adapter for
code-aware Express analysis) to be built. They do not run security tests. When the
bridge is unavailable, import a saved JSON file instead.
Discovery reports diagnostics for unreadable or malformed input and falls back to
black-box mode when a compatible adapter is unavailable.

The saved result's repository path must match the configured project path. Imports
accept files up to 2 MiB and validate the full supported `DiscoveryResult` schema,
including field types, known enums, and agreement between the selected mode and
support flag. Unexpected fields, invalid JSON, and mismatched repository paths are
rejected with an error that does not echo uploaded content.
Importing it does not run discovery again, extract routes, scan the target, or
create findings. A newly configured project has no scan progress or evidence;
discovery appears only when a saved result is attached or imported.
The seeded demo's snapshot and findings belong only to the seeded demo project.

## Views and demonstration data

- **Projects**: search by name, target, repository, or stack; filter by data source;
  open a project or configure a new one. Project rows adapt to cards on narrow
  screens. Clear filters to recover from an empty search.
- **Discovery**: inspect languages, frameworks, dependencies, database and ORM
  hints, authentication packages, middleware observations, and repository
  structure. The mode, adapter availability, fallback reasons, and diagnostics
  come from the saved result.
- **Scan progress**: explore labelled fixture progress for the demo. It represents
  a demonstration, not a real run.
- **Findings**: explore the demo's fixture findings, source and runtime evidence,
  and remediation in **Overview**, **Evidence**, and **Remediation** tabs. Use
  Left/Right arrows, Home, and End to navigate the tabs. Structured evidence facts
  and provenance expand on demand. On narrow screens, choosing a finding scrolls
  its details into view. `HYPOTHESIS`, `LIKELY`, `CONFIRMED`, `NOT_REPRODUCED`, and
  `REJECTED` states are shown explicitly; fixture confirmation is not a result
  from testing your target.

Loading, empty, field validation, unavailable-adapter, and failed-operation states
are displayed in context. Projects without imported discovery or fixture results
show empty states. Import failures leave the existing project data intact.

## Integration and boundaries

The views use the `AgentOClient` interface exported by `src/client/index.ts` and
the asynchronous `createFixtureClient()` implementation. The application accepts
an injected client, so a future backend can implement the same interface. It uses
type-only imports from `@agento/core` and `@agento/discovery`. TypeScript resolves
these contracts from their source; Node repository traversal and scanner packages
are not bundled into the browser.

The client contract distinguishes demonstration data from execution API results
and supports pending, running, complete, and failed scan snapshots. Fixture labels
and replay controls appear only for demonstration data. No execution API transport
is connected in this implementation.

The current client stores state in memory. Reloading restores the seeded demo and
discards configured projects and imported files. It does not use local storage,
store credentials, contact target URLs, read a repository, invoke security tools,
or enforce testing policy. Repository access, credentials, execution, persistence,
and policy decisions belong in the backend.

The layout supports narrow screens, labelled controls, keyboard navigation,
visible focus, and readable status text alongside colors. Forms provide field
errors, and asynchronous views expose loading and error feedback.

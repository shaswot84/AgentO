# AgentO Frontend

React, TypeScript, and Vite interface backed by a local workspace API. Projects,
discovery, and the latest scan results survive browser reloads and service restarts.
The seeded demo remains explicitly labelled synthetic data.

## Run locally

Use Node.js 22.12 or later. From the repository root:

```sh
cd apps/frontend
npm ci
npm run dev
```

Open the printed loopback URL. `npm run build` creates the browser bundle;
`npm run preview` serves that build with the same local API. A static-only file
server does not provide the API. The interface and saved discovery imports work
without a running target, browser automation, or installed security tools.

## Enable local discovery and scans

Build the existing host packages from the repository root:

```sh
npm ci --prefix packages/core
npm run build --prefix packages/core
npm ci --prefix packages/discovery
npm run build --prefix packages/discovery
npm ci --prefix plugins/frameworks/express
npm run build --prefix plugins/frameworks/express
npm ci --prefix plugins/tools/semgrep
npm run build --prefix plugins/tools/semgrep
```

Install the pinned Semgrep release using the [adapter instructions](../../plugins/tools/semgrep/README.md):

```sh
python3 -m venv /tmp/agento-semgrep-venv
/tmp/agento-semgrep-venv/bin/python -m pip install -r plugins/tools/semgrep/requirements.txt
```

Configure `AGENTO_SEMGREP_EXECUTABLE` in your `.env` (copied from `.env.example`), or pass it in the environment:

```sh
AGENTO_SEMGREP_EXECUTABLE=/tmp/agento-semgrep-venv/bin/semgrep npm run dev --prefix apps/frontend
```

The frontend local execution service automatically probes `process.env.AGENTO_SEMGREP_EXECUTABLE`, `/tmp/agento-semgrep-venv/bin/semgrep`, and `plugins/tools/semgrep/.venv/bin/semgrep` before falling back to `semgrep` on system `$PATH`.

Create a project with its repository path, target URL, and explicit allowed origins.
Use **Discover**, the local demo shortcuts, or **Refresh** to inspect the repository.
Alternatively, attach or import a saved discovery JSON file. On **Scan progress**,
select **Run static scan**. The service refreshes discovery, extracts available
Express context, and runs the bundled Semgrep XSS and SQL injection candidate rules
against a bounded source snapshot. The UI polls actual pending/running/completed
or failed snapshots; replay controls belong only to the synthetic demo.

**Findings** shows recorded source observations and endpoint associations when
available. The Evidence tab preserves normalized provider facts and provenance.
The Remediation tab provides evidence-linked candidate review guidance and suggested
regression checks. These are suggestions; patches are neither generated nor applied.

Static candidates remain `HYPOTHESIS` findings. Runtime verification rules are not
configured, and the service does not contact the target or use credentials. A
completed static scan is not a completed vulnerability assessment. Unsupported
stacks, unavailable tools, partial analysis, and failed runs remain visible with
diagnostics; an empty result never proves the application safe. Partial runs can
retain observed hypotheses while the scan is marked failed for incomplete coverage.

## Project setup and imports

Project names are required and limited to 120 characters. Repository paths are
required, limited to 4,096 characters, and cannot contain control characters.
Targets must be HTTP(S) URLs without credentials. Declare 1–100 explicit origins
without paths, queries, fragments, credentials, or wildcards, including the target's
normalized origin. These fields do not authorize active testing.

Discovery imports accept the supported `DiscoveryResult` schema up to 2 MiB.
The saved repository path must match the configured project. Invalid or mismatched
imports preserve existing data. Importing discovery does not create scan results.
New projects receive no borrowed demo findings. The seeded demo is read-only;
create a project using a demo shortcut to run real analysis of that repository.

To produce a saved file after building discovery:

```sh
node packages/discovery/dist/cli.js /absolute/repository > /tmp/discovery.json
```

## Storage and service boundaries

The browser uses `createHttpClient()` through the `AgentOClient` contract. Node
filesystem access, adapter imports, process execution, and persistence stay in
`server/`; the browser bundles only compile-time core/discovery types. The
in-memory fixture client remains available for tests and explicit demonstrations,
and is never a fallback for a failed HTTP request.

The default private store is `apps/frontend/.agento/workspace.json`. Its dedicated
directory gets local ignore rules, mode `0700`, and atomic file replacements with
mode `0600`. It contains project metadata, discovery, and each project's latest
scan and findings, including normalized source evidence and remediation guidance.
Starting another scan replaces the prior result. There is no scan-history archive
or credential store.

Set `AGENTO_WORKSPACE_FILE` on the host to choose a different file; protect and
ignore that location yourself. One local service owns each workspace file using
an exclusive process lock. Interrupted scans become failed records on restart.
Corrupt or incompatible files are preserved and reported as service errors rather
than silently replaced. Back up the workspace file if results need to be retained.

Both development and preview APIs require loopback connections and a loopback
Host header, reject cross-origin/cross-site browser requests, bound JSON request
bodies, and sanitize execution failures. Keep the service local; it has no remote
user authentication or deployment configuration. Host package builds and the
Semgrep executable are trusted administrator configuration, never browser inputs.

## Verification and accessibility

```sh
npm run check --prefix apps/frontend
AGENTO_SEMGREP_EXECUTABLE=/tmp/agento-semgrep-venv/bin/semgrep npm run test:integration --prefix apps/frontend
```

`check` runs typechecking, a production build, and client/workspace/real-HTTP API
tests. HTTP tests require loopback socket access. The opt-in integration test uses
the built discovery/Express/Semgrep providers against the demo source and verifies
candidate evidence and persistence without starting the target application.

The interface provides labelled controls, visible focus, keyboard navigation,
responsive layouts, and loading/error/empty states. Findings tabs support arrow
keys, Home, and End. Synthetic examples retain fixture warnings; execution results
show their actual state and have no demo replay controls.

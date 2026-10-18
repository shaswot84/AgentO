# AgentO Runtime

Reusable HTTP and browser capabilities, plus security probes that collect typed
observations. Capability modules contain no assessment logic; probes investigate
behavior without producing vulnerability verdicts. Scanner implementations,
application routes, and credentials are supplied by the host.

## Setup

Use Node.js 22.22.3 or later supported by the browser adapter. From the repository root:

```sh
cd packages/core && npm ci && npm run build
cd ../../plugins/tools/e2e-browser && npm ci && npm run build
cd ../../../packages/runtime && npm ci && npm run check
```

The browser package is a development dependency for integration tests. Runtime
source imports only tool-independent core types and Node built-ins. Applications
inject their chosen `BrowserWorkflowRuntimeDriver`.

## HTTP

```ts
import {
  DeterministicRequestExecutor, NormalizedResponseCollector,
  NormalizedHeaderAnalyzer, NormalizedCookieAnalyzer,
} from '@agento/runtime';

const http = new DeterministicRequestExecutor({
  baseUrl: 'http://127.0.0.1:3000',
  allowedOrigins: ['http://127.0.0.1:3000'],
});
const response = await http.execute({ url: '/account', method: 'GET' });
const observation = new NormalizedResponseCollector().evidence(response);
const headers = await new NormalizedHeaderAnalyzer().analyze(response);
const cookies = await new NormalizedCookieAnalyzer().analyze(response);
```

Each call sends one exchange. There are no automatic redirects or retries, shared
cookies, proxy environment inheritance, or ambient credentials. To follow a
redirect, explicitly execute another scoped request. Origins match scheme, host,
and port. Credentials embedded in URLs and ambiguous framing headers are refused;
TLS uses Node's normal certificate verification.

Defaults: 15 seconds for the whole exchange, 1 MiB each for request/response bodies,
16 KiB for request headers, and 32 KiB for response headers. Request bodies are
explicit strings. Responses preserve binary bytes as base64, separate repeated
header fields, status, first-byte time, and total time. Content encodings remain
unchanged. Oversized response bodies contain a bounded prefix with
`truncated: true`; incomplete connections fail instead of returning complete data.
Callers can supply an `AbortSignal` or inject an `HttpTransport` for testing.

`HttpResponse` is private backend data: its URL, body, and headers can contain
credentials. Do not serialize it to UI, logs, or model input. The collector's
`evidence()` returns response metadata and a body digest, excluding raw headers
and body bytes and redacting query values. Header analysis extracts observed CORS,
security, and cache fields without interpreting them. These application-provided
header strings and URL paths can still contain sensitive data. Cookie analysis
always redacts values and preserves flags, domain/path, expiry, and provenance.

## Browser and authenticated sessions

```ts
import {
  WorkflowBrowserController, RuntimeAuthenticationManager,
  SessionNetworkObserver, SessionCookieInspector,
} from '@agento/runtime';

// Supply an existing driver, AnalysisContext, and optional target profile.
const browser = new WorkflowBrowserController({ driver, context, target });
const authentication = new RuntimeAuthenticationManager({
  browser,
  identities: target.personas,
  http: { baseUrl: context.project.baseUrl, allowedOrigins: context.project.allowedOrigins },
});

const session = await authentication.establishSession(target.personas[0]);
try {
  const response = await session.http.execute({ url: '/account' });
  await session.withBrowser(async page => {
    await page.perform({ action: 'navigate', url: '/account' });
    const inspection = await page.inspect();
  });
  const network = await new SessionNetworkObserver().observe(session);
  const cookies = await new SessionCookieInspector().inspect(session);
} finally {
  await session.close();
  await authentication.close();
}
```

Identities, credentials, authentication strategies, and selectors belong in trusted
target configuration. Alice, Bob, and Admin are integration-test personas, with no
special treatment in runtime source. The browser driver verifies identity and
role, isolates contexts, enforces scope, and manages its private saved state.
`withSession()` / `withBrowser()` expose a callback-scoped handle that is revoked
when the callback returns. The driver closes the browser even on failure.

The authentication manager supports anonymous and session-cookie identities. It
transfers cookies from the verified browser to a private HTTP jar. HTTP cookie
updates are imported before subsequent browser actions, and browser changes commit
to the HTTP jar only after successful driver finalization. Expired and explicitly
closed sessions revoke operations, cancel HTTP work, and clear their jars.
Concurrent requests for one identity share establishment; operations within a
session are serialized. Await each session operation before starting another one
inside its browser callback. Do not call `session.http` or `session.withBrowser`
from that callback; nested operations are refused with `invalid-request` because
the outer session queue is already occupied.

Defaults: 30-minute sessions, 20 active sessions, 200 cookies per session, and 500
network records. Exhausted limits fail explicitly. HTTP calls can return an ordinary
401/403 after server-side expiry; they never silently reauthenticate or retry a
request. Close and establish a fresh session when authentication must be renewed.

The bridge requires the driver's optional private `readCookies` and
`replaceCookies` capabilities. The supplied e2e adapter implements both against
its active browser context. Raw cookie transfer is a trusted backend operation;
public cookie observations contain `[REDACTED]` values. Bearer tokens,
localStorage/sessionStorage authentication, and partitioned-cookie transfer are
reported as unsupported, rather than being converted into HTTP cookie sessions.

The HTTP jar deliberately narrows browser cookie behavior: cookies are bound to
an exact response origin as well as their host/path, parent-domain cookies are
observed but not forwarded, and Secure cookies require HTTPS. Browser transfer is
for the configured base origin; do not combine cookies from several hosts in one
session. SameSite is metadata for backend HTTP calls, which have no browser site
context. Missing SameSite becomes the browser's Lax default on import. Public-suffix
and full browser cookie-policy emulation are outside this package.

`NetworkObserver` takes a non-destructive snapshot. Browser records include method,
URL, status or null, and blocked state; they inherit the driver's collection limits
and exclusions. HTTP records include exchanges made through that session. Bodies,
raw cookie headers, and request authorization values are excluded. Asynchronous
traffic is visible only once the driver has observed it. Failed workflows throw a
sanitized `RuntimeError`; do not treat failure as an empty successful observation.

## Reusable security probes

Probes use `CapabilityRegistry` to request operations and return deeply frozen,
JSON-safe evidence. `ProbeRegistry` registers each investigation independently.
Register capabilities once, then reuse one cookie evidence record across consumers:

```ts
import {
  CapabilityRegistry, ProbeRegistry, CookieSecurityProbe,
  DeterministicRequestExecutor, NormalizedResponseCollector,
  NormalizedCookieAnalyzer,
} from '@agento/runtime';

// project is the target's existing core Project, including exact allowedOrigins.
const capabilities = new CapabilityRegistry()
  .register('request-executor', new DeterministicRequestExecutor({
    baseUrl: project.baseUrl, allowedOrigins: project.allowedOrigins,
  }))
  .register('response-collector', new NormalizedResponseCollector())
  .register('cookie-analyzer', new NormalizedCookieAnalyzer());
const probes = new ProbeRegistry().register('cookie-security', new CookieSecurityProbe());
const probe = probes.get('cookie-security');
const context = { project, capabilities, request: { url: '/' } };
const evidence = await probe.execute(context);
```

`metadata()` lists required and optional capability names. `supports(context)`
checks capability availability and contextual prerequisites; execution also validates
targets and inputs. Missing required capabilities throw `unsupported-capability`.
Duplicate registrations are refused. Extend the `CapabilityCatalog` and `ProbeCatalog`
interfaces through declaration merging to add another implementation or family.

| Probe | Required capabilities | Observations |
| --- | --- | --- |
| `CookieSecurityProbe` | Request executor, response collector, cookie analyzer | Anonymous response cookies; optional authenticated response and jar cookies, with flags and provenance |
| `CrossOriginProbe` | Request executor, response collector, header analyzer | Preflight and actual status, requested Origin, allowed origins, credential flags, methods and headers |
| `AuthorizationProbe` | Request executor, response collector, authentication manager, response comparator | Owner, attacker and anonymous responses; status/body/timing deltas and private owner-marker matches |
| `XSSProbe` | Request executor, response collector | Inert canary reflection and lexical HTML/attribute/script/text hints; optional browser visibility and scanner observations |
| `SQLInjectionProbe` | Request executor, response collector, response comparator | Baseline, syntax and boolean variants; response deltas and heuristic database-error fingerprints; optional scanner observations |

Register `authentication-manager` for authenticated probes, `cookie-inspector` for
authenticated cookie collection, and `response-comparator` using
`NormalizedResponseComparator` for authorization and SQL investigations. Register
`browser-controller` and a configured `anonymousIdentity` for anonymous XSS browser observation. Authenticated XSS uses
the authentication session's browser handle. Cookie investigations accept up to ten
distinct authenticated `identities`; they inspect anonymous cookies once and each
identity once. An optional browser controller also captures browser cookie metadata
that the narrower HTTP jar cannot transfer, such as Secure cookies on HTTP targets.
Cookie values remain `[REDACTED]`.

Cross-origin probes accept up to eight `origins` (default: `null` and two `.invalid`
origins), optional `requestedHeaders`, and an optional authenticated `identity`.
Origin values are header data; requests always target the scoped application.
Preflights omit session credentials. Actual requests use the selected session when
configured. This records HTTP policy responses; it does not simulate browser CORS
enforcement, SameSite behavior, or prove that a browser can read a response.

Authorization contexts require distinct `owner` and `attacker` identities and
exactly one of `resource` or `discoverResource(ownerSession)`. Supply a trusted
resource descriptor with `id`, `ownerIdentityId`, `request`, and optional private
`ownerMarkers`. A discovery callback can use `ownerSession.withBrowser()` to reach
a resource and `ownerSession.http` to read its ownership. The probe checks identity
binding and scope before repeating the same request under the other identities.
Ownership supplied by the host must be reliable; matching bytes alone cannot
establish ownership or an authorization defect. Truncated bodies yield unknown
comparisons, and markers themselves are excluded from evidence.

Injection contexts specify `request`, `parameter: { name, location }`, and optional
`identity`. Supported locations are `query`, `json-body`, and `form-body`; the
parameter must already exist exactly once, with a string value in JSON. GET query
and explicit POST body testing preserve other inputs. Cookie, CORS and authorization
targets allow GET/HEAD only; explicit credential headers are refused. Supply a
standalone executor with no ambient credentials for anonymous requests, and use
the authentication manager for session material. Use a dedicated manager per
investigation or serialize investigations sharing it: probes close their sessions
in `finally`, including on failure. Cancellation stops later dispatches, and errors
expose sanitized runtime codes.

XSS uses a fresh inert custom-element canary. Reflection, lexical context, and visible
browser text do not establish script execution or DOM sink reach. Those fields remain
`null` unless a registered `xss-scanner` supplies objective observations. SQL sends
four bounded HTTP exchanges: baseline, one quote marker, and two boolean variants.
Echoed parameters, dynamic content, or timings can change a response even when
queries are safe. Fingerprints are heuristic; no database dump, writes, delay
payloads, or final security judgment are performed by the built-in probe.

Optional `XSSScanner` and `SQLScanner` ports normalize adapter observations. These
ports deliberately accept facts rather than a scanner's finding verdict. Adapters
receive a private executor limited to eight additional requests to the approved
endpoint and method; its capability is revoked after `scan()` returns. They must
honor the abort signal and exact project origins if using their own transport.
No external injection scanner is bundled here. Missing optional scanners produce
`PARTIAL` coverage with `scanner-unavailable`, and unsupported browser collection
or truncated responses add explicit diagnostics. Present adapters that fail throw
sanitized errors rather than returning successful empty evidence. Tests inject
scanner fakes; they do not claim live scanner verification.

Evidence retains response IDs, digests, lengths and timings, with query values
redacted and raw bodies/headers omitted. URL paths, cookie metadata and observed
CORS strings remain application data and can need additional host redaction.
There is no automatic result cache or UI/scan integration: callers explicitly
reuse the same immutable record for multiple policy consumers.

## Verification

```sh
npm run check
npm run test:integration
```

The first command typechecks, builds, and runs mock/parser/lifecycle tests. Live
tests are opt-in and require loopback sockets, installed Chromium, and the local
storefront's installed dependencies. Install Chromium from the browser adapter
with `npx playwright-core install chromium` if needed, or set
`PLAYWRIGHT_BROWSERS_PATH` to an existing installation.

Live checks exercise binary HTTP data, cookies/headers, scope rejection, redirects,
body/time limits, failed connections, rejected login, and isolated authenticated
browser/HTTP sessions for all three personas. Probe checks run all five families
against the storefront's vulnerable and fixed behavior, including browser-based
owner discovery, session transfer, inert XSS visibility and differential SQL markers.

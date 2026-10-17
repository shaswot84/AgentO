# AgentO Runtime

Reusable HTTP and browser operations with structured observations. The package
contains no assessment rules, scanners, application routes, or built-in users.

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
browser/HTTP sessions for all three personas.

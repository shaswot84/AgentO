import { createHash, randomUUID } from 'node:crypto';
import { mkdir, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { web, surfaceOf } from '@e2e-dev/web';
import type { OperationContext } from 'e2e/engine';
import type { BrowserContext, Page, Request, Response } from 'playwright-core';
import type { BrowserContextCookie, BrowserPageInspection } from '@agento/core';
import { BrowserError, redactUrl } from './policy.js';
import { privateStorageValues } from './private-values.js';
import type { BrowserAction, BrowserRuntime, BrowserRuntimeRequest, BrowserSession, BrowserState, ResponseExpectation } from './types.js';

/** e2e owns Chromium and context isolation; AgentO owns execution and evidence above its live surface. */
export class E2EWebRuntime implements BrowserRuntime {
  async start(request: BrowserRuntimeRequest): Promise<BrowserSession> {
    // An explicit headers object makes e2e create contexts with serviceWorkers: 'block'.
    const engine = web({ browser: 'chromium', headers: {} });
    const attemptId = randomUUID();
    const cleanup = { signal: new AbortController().signal, timeoutMs: 5000 };
    const dispose = async () => {
      try { await engine.endAttempt?.(cleanup); } finally { await engine.dispose?.(cleanup); }
    };
    const operation = (): OperationContext => ({ signal: request.signal, timeoutMs: request.timeoutMs,
      runId: attemptId, attemptId, origin: 'test' });
    try {
      await engine.init?.({ runId: attemptId, targetName: 'agento', projectRoot: process.cwd(),
        app: { site: new URL(request.project.baseUrl).hostname }, env: process.env,
        headed: false, workerSlot: 0, signal: request.signal, log: () => undefined });
      await engine.startAttempt?.({ attemptId, artifactsDir: tmpdir(), signal: request.signal,
        resolveSecret: async () => { throw new BrowserError('authentication-failed'); },
        appLog: () => undefined, navigation: () => undefined, environment: () => undefined });
      if (request.state) await engine.state!.restore(request.state, operation());
      const context = surfaceOf(engine)!.context();
      context.setDefaultTimeout(Math.min(10_000, request.timeoutMs));
      const blocked = new WeakSet<Request>();
      let primaryPage: Page | undefined;
      const record = (item: Request, status: number | null, denied = false, headers?: Record<string, string>) => {
        let initiatingPage: string | undefined;
        try { initiatingPage = item.frame().page().url(); } catch { /* Worker requests have no page. */ }
        request.onNetwork({ url: item.url(), method: item.method(), resourceType: item.resourceType(), status, blocked: denied,
          timestamp: new Date().toISOString(), ...(initiatingPage ? { initiatingPage } : {}),
          ...(headers ? { headers: { 'content-type': headers['content-type'] ?? '',
            'x-content-type-options': headers['x-content-type-options'] ?? '' } } : {}) });
      };
      const guards = new WeakMap<Page, Promise<void>>();
      const guardPage = (page: Page): Promise<void> => {
        let ready = guards.get(page);
        if (!ready) {
          ready = (async () => {
            // Playwright routing skips later hops in a browser redirect chain. Chromium's
            // request-stage gate sees every hop in the primary page and its frames.
            const client = await context.newCDPSession(page);
            client.on('Fetch.requestPaused', event => {
              const work = async () => {
                try { request.assertUrl(event.request.url); }
                catch {
                  request.onNetwork({ url: event.request.url, method: event.request.method,
                    resourceType: event.resourceType.toLowerCase(), status: null, blocked: true, blockedReason: 'origin-scope' });
                  await client.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'BlockedByClient' });
                  return;
                }
                await client.send('Fetch.continueRequest', { requestId: event.requestId });
              };
              void work().catch(() => undefined); // The page may close during teardown.
            });
            await client.send('Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Request' }] });
          })();
          guards.set(page, ready);
        }
        return ready;
      };
      context.on('page', page => {
        if (!primaryPage) { primaryPage = page; return; }
        // A popup's initial navigation can precede attaching a Chromium gate. This layer
        // supports one primary page per identity and refuses secondary pages outright.
        request.onNetwork({ url: page.url(), method: 'GET', resourceType: 'document', status: null,
          blocked: true, blockedReason: 'popup-unsupported' });
        void page.close().catch(() => undefined);
      });
      // Fetch only one hop so the adapter's HTTP client cannot expand browser scope.
      await context.route('**/*', async route => {
        const item = route.request();
        try { request.assertUrl(item.url()); }
        catch {
          blocked.add(item); record(item, null, true);
          await route.abort('blockedbyclient').catch(() => undefined); return;
        }
        try {
          let page: Page;
          try { page = item.frame().page(); }
          catch {
            blocked.add(item);
            request.onNetwork({ url: item.url(), method: item.method(), resourceType: item.resourceType(), status: null,
              blocked: true, blockedReason: 'worker-unsupported' });
            await route.abort('blockedbyclient'); return;
          }
          if (page !== primaryPage) {
            blocked.add(item);
            request.onNetwork({ url: item.url(), method: item.method(), resourceType: item.resourceType(), status: null,
              blocked: true, blockedReason: 'popup-unsupported' });
            await route.abort('blockedbyclient'); return;
          }
          await guardPage(page);
          const response = await route.fetch({ maxRedirects: 0, timeout: Math.min(10_000, request.timeoutMs) });
          try {
            const location = response.headers().location;
            if (response.status() >= 300 && response.status() < 400 && location) {
              const destination = new URL(location, item.url()).href;
              try { request.assertUrl(destination); }
              catch {
                blocked.add(item); record(item, response.status());
                request.onNetwork({ url: destination, method: item.method(), resourceType: item.resourceType(), status: null,
                  blocked: true, blockedReason: 'origin-scope' });
                await route.abort('blockedbyclient'); return;
              }
            }
            await route.fulfill({ response });
          } finally { await response.dispose(); }
        } catch { await route.abort('failed').catch(() => undefined); }
      });
      // WebSockets bypass HTTP routing; this REST workflow layer refuses them entirely.
      await context.routeWebSocket('**/*', socket => {
        request.onNetwork({ url: socket.url(), method: 'GET', resourceType: 'websocket', status: null, blocked: true,
          blockedReason: 'websocket-unsupported' });
        socket.close();
      });
      context.on('response', response => { if (!blocked.has(response.request())) record(response.request(), response.status(), false, response.headers()); });
      context.on('requestfailed', item => { if (!blocked.has(item)) record(item, null); });
      // Use the public live context for AgentO's bounded deterministic action grammar. These
      // actions are outside the e2e test harness; raw harness traces are neither made nor exported.
      const page = await context.newPage();
      await guardPage(page);
      let closing: Promise<void> | undefined;
      const close = () => {
        request.signal.removeEventListener('abort', abort);
        return closing ??= dispose();
      };
      const abort = () => { void close().catch(() => undefined); };
      request.signal.addEventListener('abort', abort, { once: true });
      if (request.signal.aborted) { await close(); throw new BrowserError('timeout'); }
      return new LiveSession(context, page, request, close);
    } catch (error) {
      await dispose().catch(() => undefined);
      throw error;
    }
  }
}

class LiveSession implements BrowserSession {
  private readonly inspectionNonce = randomUUID();
  constructor(private readonly context: BrowserContext,
    private readonly page: Page, private readonly request: BrowserRuntimeRequest,
    readonly close: () => Promise<void>) {}

  async perform(action: BrowserAction): Promise<void> {
    if (this.request.signal.aborted) throw new BrowserError('timeout');
    const response = 'response' in action && action.response
      ? this.page.waitForResponse(item => matchesResponse(item, action.response!, this.request.assertUrl)) : undefined;
    // Consume a waiter even if the action fails first; no late unhandled rejection.
    void response?.catch(() => undefined);
    switch (action.action) {
      case 'navigate': await this.page.goto(this.request.assertUrl(action.url), { waitUntil: 'domcontentloaded' }); break;
      case 'wait-url': await this.page.waitForURL(this.request.assertUrl(action.url), { waitUntil: 'domcontentloaded' }); break;
      case 'fill': {
        const element = await this.page.locator(action.selector).elementHandle();
        if (!element) throw new BrowserError('browser-failed');
        try { await element.fill(action.value); } finally { await element.dispose(); }
        break;
      }
      case 'click': await this.page.locator(action.selector).click(); break;
      case 'submit': await this.page.locator(action.selector).evaluate((element: HTMLFormElement) => element.requestSubmit()); break;
      case 'wait-visible': await this.page.locator(action.selector).waitFor({ state: 'visible' }); break;
    }
    if (response) {
      const observed = await response;
      if ('response' in action && action.response?.status !== undefined && observed.status() !== action.response.status) {
        throw new BrowserError('browser-failed');
      }
    }
  }

  async verify(verification: Parameters<BrowserSession['verify']>[0]): Promise<boolean> {
    const response = await this.page.goto(this.request.assertUrl(verification.url), { waitUntil: 'domcontentloaded' });
    if (!response || response.status() !== 200) return false;
    try {
      if ('identitySelector' in verification) {
        const identity = this.page.locator(verification.identitySelector);
        await identity.waitFor({ state: 'visible' });
        if ((await identity.textContent())?.trim() !== verification.expectedIdentity) return false;
        if (verification.role) {
          const role = this.page.locator(verification.role.selector);
          await role.waitFor({ state: 'visible' });
          if ((await role.textContent())?.trim() !== verification.role.expected) return false;
        }
        return true;
      }
      const body: unknown = await response.json();
      const read = (path: readonly string[]) => {
        let value = body;
        for (const key of path) {
          if (!value || typeof value !== 'object' || !Object.hasOwn(value, key)) return undefined;
          value = (value as Record<string, unknown>)[key];
        }
        return value;
      };
      return read(verification.identityPath) === verification.expectedIdentity
        && (!verification.role || read(verification.role.path) === verification.role.expected);
    } catch { return false; }
  }

  async inspect(): Promise<BrowserPageInspection> {
    const url = this.page.url();
    if (url !== 'about:blank') this.request.assertUrl(url);
    const storageValues = await this.page.evaluate(() => {
      const values: string[] = [];
      for (const kind of ['localStorage', 'sessionStorage'] as const) {
        try {
          const storage = window[kind];
          for (let index = 0; index < Math.min(storage.length, 100); index++) {
            const key = storage.key(index), value = key ? storage.getItem(key) : null;
            if (value) values.push(value.slice(0, 16_384));
          }
        } catch { /* Storage may be unavailable on blank or restricted pages. */ }
      }
      return values;
    });
    const privateValues = storageValues.flatMap(privateStorageValues).slice(0, 512);
    const raw = await this.page.locator('a, button, input, form, [role="button"]').evaluateAll(elements => {
      const kinds = { A: 'link', BUTTON: 'button', INPUT: 'input', FORM: 'form' } as const;
      const visible = (element: Element) => {
        const rect = element.getBoundingClientRect(), style = getComputedStyle(element);
        return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden'
          && style.display !== 'none' && !element.closest('[aria-hidden="true"]');
      };
      const selector = (element: Element) => {
        const parts: string[] = [];
        let node: Element | null = element;
        while (node && parts.length < 30) {
          const tag = node.tagName.toLowerCase();
          const parent: Element | null = node.parentElement;
          const siblings: Element[] = parent ? [...parent.children].filter(child => child.tagName === node!.tagName) : [];
          parts.unshift(`${tag}:nth-of-type(${parent ? siblings.indexOf(node) + 1 : 1})`);
          node = parent;
        }
        return parts.join(' > ');
      };
      const controls = elements.slice(0, 1000).filter(visible).slice(0, 100).map(element => {
        const kind = kinds[element.tagName as keyof typeof kinds] ?? 'button';
        const label = element.getAttribute('aria-label') ?? (kind === 'input' ? element.getAttribute('placeholder')
          : kind === 'form' ? '' : (element as HTMLElement).innerText);
        const form = 'form' in element ? (element as HTMLInputElement | HTMLButtonElement).form : null;
        return { selector: selector(element), kind, label: (label ?? '').trim().slice(0, 4096),
          enabled: !element.matches(':disabled') && element.getAttribute('aria-disabled') !== 'true',
          ...(element instanceof HTMLInputElement ? { inputType: element.type } : {}),
          ...(form ? { formSelector: selector(form) } : {}),
          ...(element instanceof HTMLAnchorElement ? { href: element.href } : {}) };
      });
      const headings = [...document.querySelectorAll('h1,h2,h3,h4,h5,h6')].filter(visible).slice(0, 20)
        .map(element => (element as HTMLElement).innerText.trim().slice(0, 4096));
      const fragments: string[] = [];
      const walker = document.createTreeWalker(document.body ?? document.documentElement, NodeFilter.SHOW_TEXT);
      let length = 0;
      for (let index = 0; index < 500 && length < 4096; index++) {
        const node = walker.nextNode(), parent = node?.parentElement;
        if (!node) break;
        if (!parent || !visible(parent) || parent.closest('input,textarea,script,style,noscript,[aria-hidden="true"]')) continue;
        const text = (node.textContent ?? '').trim().slice(0, 4096 - length);
        if (text) { fragments.push(text); length += text.length; }
      }
      return { controls, title: document.title.slice(0, 4096), headings, visibleTextSummary: fragments.join(' ').slice(0, 4096) };
    });
    const redact = (value: string, maximum: number) => {
      for (const secret of privateValues.filter(Boolean)) value = value.split(secret).join('[REDACTED]');
      return value.replace(/\beyJ[A-Za-z0-9_.-]+/g, '[REDACTED]')
        .replace(/[A-Za-z0-9_.~%+=-]{40,}/g, '[REDACTED]').slice(0, maximum);
    };
    const stateId = createHash('sha256').update(JSON.stringify([this.inspectionNonce, url, raw])).digest('hex');
    return { stateId, url: url === 'about:blank' ? url : redactUrl(url, privateValues), title: redact(raw.title, 256),
      headings: raw.headings.map(value => redact(value, 256)), visibleTextSummary: redact(raw.visibleTextSummary, 4096),
      controls: raw.controls.map(control => ({ ...control, label: redact(control.label, 256),
        ...(control.href ? { href: redactUrl(control.href, privateValues) } : {}) })) };
  }

  async readCookies(): Promise<readonly BrowserContextCookie[]> {
    return this.context.cookies();
  }

  async replaceCookies(cookies: readonly BrowserContextCookie[]): Promise<void> {
    await this.context.clearCookies();
    await this.context.addCookies([...cookies]);
  }

  async captureState(): Promise<BrowserState> {
    // Same format as e2e's state capability. Reading the live context avoids exporting
    // harness observations, logs, or screenshots containing credentials.
    return { format: 'playwright-storage-state', version: 1, data: await this.context.storageState({ indexedDB: true }) };
  }

  async snapshot(): Promise<Awaited<ReturnType<BrowserSession['snapshot']>>> {
    const url = this.page.url();
    if (url !== 'about:blank') this.request.assertUrl(url);
    if (!this.request.screenshot) return { url };
    const directory = resolve(this.request.screenshot.directory);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const screenshotPath = join(directory, `${randomUUID()}.png`);
    const masks = ['input', 'textarea', ...this.request.screenshot.maskSelectors].map(selector => this.page.locator(selector));
    await this.page.screenshot({ path: screenshotPath, mask: masks, animations: 'disabled' });
    await chmod(screenshotPath, 0o600);
    return { url, screenshotPath };
  }
}

function matchesResponse(response: Response, expectation: ResponseExpectation, assertUrl: (url: string) => string): boolean {
  const expected = assertUrl(expectation.url);
  const urlMatches = expected.endsWith('*') ? response.url().startsWith(expected.slice(0, -1)) : response.url() === expected;
  return urlMatches && (expectation.method === undefined || response.request().method() === expectation.method);
}

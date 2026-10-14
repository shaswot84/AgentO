import { createServer, type Server } from 'node:http';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AnalysisContext, TargetApplicationProfile } from '@agento/core';
import {
  TesterArmyE2EAdapter,
  portalBrowserOptions,
  edgeSpaBrowserOptions,
  FileSessionStore,
  MemorySessionStore,
} from '../src/index.js';

const suite = process.env.AGENTO_BROWSER_INTEGRATION === '1' ? describe : describe.skip;

function listen(server: Server): Promise<string> {
  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${address.port}`);
    });
    server.on('error', reject);
  });
}

function close(server: Server): Promise<void> {
  return new Promise(resolve => server.close(() => resolve()));
}

function contextFor(baseUrl: string, target: TargetApplicationProfile): AnalysisContext {
  return {
    project: {
      id: `project-${target.id}`,
      name: target.id,
      mode: 'black-box',
      baseUrl,
      allowedOrigins: target.baseOrigins,
      languages: [],
    },
    components: [],
    endpoints: [],
    identities: target.personas ?? [],
    resources: [],
    signals: [],
    evidence: [],
  };
}

suite('real browser portability and edge cases against Demo Apps 03 and 04', () => {
  let portalServer: Server;
  let edgeServer: Server;
  let trapServer: Server;
  let portalOrigin: string;
  let edgeOrigin: string;
  let trapOrigin: string;
  let directory: string;
  let forbiddenRequests = 0;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'agento-demo-apps-portability-'));

    // Trap server to verify zero forbidden scope escapes
    trapServer = createServer((_req, res) => {
      forbiddenRequests++;
      res.writeHead(403);
      res.end('forbidden');
    });
    trapOrigin = await listen(trapServer);

    // Demo App 03 — SSR Multi-Page Portal (Express + HTML Form 302 Redirect + CSRF)
    const { createApp: createPortalApp } = await import(
      new URL('../../../../demo-apps/demo-app-03/src/app.ts', import.meta.url).pathname
    );
    portalServer = createServer(createPortalApp());
    portalOrigin = await listen(portalServer);

    // Demo App 04 — Modern Edge-Case SPA (Multi-Step Auth + sessionStorage + WebSocket/CDN)
    const { createApp: createEdgeApp } = await import(
      new URL('../../../../demo-apps/demo-app-04/src/app.ts', import.meta.url).pathname
    );
    edgeServer = createServer(createEdgeApp({ unapprovedCdnOrigin: trapOrigin }));
    edgeOrigin = await listen(edgeServer);
  });

  afterAll(async () => {
    const received = forbiddenRequests;
    await Promise.all([portalServer, edgeServer, trapServer].filter(Boolean).map(close));
    if (directory) {
      await rm(directory, { recursive: true, force: true });
    }
    // Strict isolation assertion: trap server must never be contacted
    expect(received).toBe(0);
  });

  // --- Scenario 1: Multi-Page App (MPA) with HTML 302 redirect, CSRF, and DOM verification ---
  it('executes full workflow on Demo App 03 (MPA) with HTML 302 form redirect and DOM verification', async () => {
    const options = portalBrowserOptions([portalOrigin]);
    const ctx = contextFor(portalOrigin, options.target!);

    const result = await new TesterArmyE2EAdapter(options).observe(ctx, {
      id: 'portal-audit',
      identityId: 'analyst',
      goal: 'open latest report',
    });

    expect(result.diagnostics).toEqual([]);
    expect(result.outcome).toBe('COMPLETED');

    const reportApi = result.evidence.find(
      item => item.kind === 'http-response' && item.facts.url === `${portalOrigin}/reports/REP-501`
    );
    expect(reportApi).toBeDefined();
    expect(reportApi?.facts.status).toBe(200);
    expect(result.evidence.some(e => e.kind === 'identity-session')).toBe(true);
  }, 35_000);

  it('restores MPA cookie session across fresh adapters using FileSessionStore', async () => {
    const sessionStore = new FileSessionStore(join(directory, 'portal-sessions'));
    const options = { ...portalBrowserOptions([portalOrigin]), sessionStore };
    const ctx = contextFor(portalOrigin, options.target!);

    // Initial login creates session snapshot on disk
    const initial = await new TesterArmyE2EAdapter(options).observe(ctx, {
      id: 'portal-initial',
      identityId: 'analyst',
      goal: 'open latest report',
    });
    expect(initial.outcome).toBe('COMPLETED');
    expect(initial.evidence.find(e => e.kind === 'identity-session')?.facts.reused).toBe(false);

    // Second execution with invalid credentials proves session reuse
    const reused = await new TesterArmyE2EAdapter({
      ...options,
      credentials: async () => {
        throw new Error('Cached session should suffice');
      },
    }).observe(ctx, {
      id: 'portal-reused',
      identityId: 'analyst',
      goal: 'open latest report',
    });

    expect(reused.outcome).toBe('COMPLETED');
    expect(reused.evidence.find(e => e.kind === 'identity-session')?.facts.reused).toBe(true);
    expect(await readdir(join(directory, 'portal-sessions'))).toHaveLength(1);
  }, 45_000);

  // --- Scenario 4: Multi-Step Login Flow (Custom Strategy vs FormLoginStrategy Failure) ---
  it('succeeds on Demo App 04 multi-step login using custom declarative strategy', async () => {
    const options = edgeSpaBrowserOptions([edgeOrigin], 'edge-spa', 'edge-multi-step');
    const ctx = contextFor(edgeOrigin, options.target!);

    const result = await new TesterArmyE2EAdapter(options).observe(ctx, {
      id: 'edge-multistep-success',
      identityId: 'operator',
      goal: 'open latest telemetry',
    });

    expect(result.diagnostics).toEqual([]);
    expect(result.outcome).toBe('COMPLETED');

    const telemetryApi = result.evidence.find(
      item => item.kind === 'http-response' && item.facts.url === `${edgeOrigin}/api/telemetry/TEL-900`
    );
    expect(telemetryApi).toBeDefined();
    expect(telemetryApi?.facts.status).toBe(200);
  }, 35_000);

  it('proves FormLoginStrategy fails on multi-step login because password field is not initially active', async () => {
    // Attempting single-step FormLoginStrategy against a multi-step login
    const options = edgeSpaBrowserOptions([edgeOrigin], 'edge-spa', 'edge-single-step');
    const ctx = contextFor(edgeOrigin, options.target!);

    const result = await new TesterArmyE2EAdapter(options).observe(ctx, {
      id: 'edge-multistep-fail',
      identityId: 'operator',
      goal: 'open latest telemetry',
    });

    // Proves the limitation: FormLoginStrategy cannot complete multi-step login flows
    expect(result.outcome).toBe('FAILED');
    expect(result.diagnostics[0]?.code).toMatch(/authentication-failed|browser-failed/);
  }, 35_000);

  // --- Scenario 2: sessionStorage persistence limitation across fresh browser contexts ---
  it('proves sessionStorage cannot be reused in a fresh browser context because storageState excludes it', async () => {
    const sessionStore = new MemorySessionStore();
    const options = { ...edgeSpaBrowserOptions([edgeOrigin], 'edge-spa', 'edge-multi-step'), sessionStore };
    const ctx = contextFor(edgeOrigin, options.target!);

    // Initial run succeeds and captures Playwright storageState
    const initial = await new TesterArmyE2EAdapter(options).observe(ctx, {
      id: 'edge-initial',
      identityId: 'operator',
      goal: 'open latest telemetry',
    });
    expect(initial.outcome).toBe('COMPLETED');

    // Fresh adapter tries to reuse state without credentials resolver
    // Playwright's storageState does NOT persist window.sessionStorage, so the fresh context lacks the JWT
    // The fresh adapter's verification against /workspace fails, stale state is evicted, and without credentials it fails
    const reused = await new TesterArmyE2EAdapter({
      ...options,
      credentials: async () => {
        throw new Error('Session storage is not serialized by storageState');
      },
    }).observe(ctx, {
      id: 'edge-reuse-attempt',
      identityId: 'operator',
      goal: 'open latest telemetry',
    });

    // Proves the documented limitation: sessionStorage SPAs cannot reuse saved sessions across fresh contexts
    expect(reused.outcome).toBe('FAILED');
    expect(reused.diagnostics[0]?.code).toBe('authentication-failed');
  }, 45_000);

  // --- Scenario 3: Real-Time WebSockets and CDN Boundary Failures ---
  it('proves background WebSocket attempts fail the workflow with scope-denied', async () => {
    const options = edgeSpaBrowserOptions([edgeOrigin]);
    const ctx = contextFor(edgeOrigin, options.target!);

    // Custom recipe navigating to a route that triggers a background WebSocket
    const result = await new TesterArmyE2EAdapter({
      ...options,
      resolveGoal: () => [
        { action: 'navigate', url: '/escape/websocket' },
        { action: 'wait-visible', selector: '[data-ws-done="true"]' },
      ],
    }).observe(ctx, {
      id: 'edge-ws-test',
      identityId: 'operator',
      goal: 'trigger background websocket',
    });

    // Proves strict scope boundary: WebSockets are blocked and fail the observation
    expect(result.outcome).toBe('FAILED');
    expect(result.diagnostics.some(d => d.code === 'scope-denied')).toBe(true);
    const wsEvidence = result.evidence.find(e => e.facts.blockedReason === 'websocket-unsupported');
    if (!wsEvidence) {
      console.error('DEBUG EVIDENCE:', result.evidence.map(e => e.facts));
    }
    expect(result.evidence.some(e => e.facts.blocked === true)).toBe(true);
  }, 35_000);

  it('proves unapproved external CDN requests fail the workflow with origin-scope', async () => {
    const options = edgeSpaBrowserOptions([edgeOrigin]);
    const ctx = contextFor(edgeOrigin, options.target!);

    // Custom recipe navigating to a route that attempts an external CDN fetch
    const result = await new TesterArmyE2EAdapter({
      ...options,
      resolveGoal: () => [{ action: 'navigate', url: '/escape/cdn' }],
    }).observe(ctx, {
      id: 'edge-cdn-test',
      identityId: 'operator',
      goal: 'trigger unapproved cdn',
    });

    // Proves strict scope boundary: unapproved origins are blocked and fail the observation
    expect(result.outcome).toBe('FAILED');
    expect(result.diagnostics.some(d => d.code === 'scope-denied')).toBe(true);
  }, 35_000);
});

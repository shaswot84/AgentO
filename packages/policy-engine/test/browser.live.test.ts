import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AnalysisContext } from '@agento/core';
import { CapabilityRegistry } from '@agento/capability-registry';
import { DeterministicRequestExecutor, WorkflowBrowserController } from '@agento/runtime';
import { TesterArmyE2EAdapter } from '@agento/tool-e2e-browser';
import { PolicyEngine } from '../src/index.js';
import type { PolicyConfiguration } from '../src/index.js';

const suite = process.env.AGENTO_POLICY_INTEGRATION === '1' ? describe : describe.skip;
suite('live policy boundary with loopback HTTP and Chromium', () => {
  let server: Server, trap: Server, origin: string, trapOrigin: string, context: AnalysisContext;
  let trapRequests = 0, posts = 0;
  const anonymous = { id: 'anonymous', label: 'Anonymous', roles: [], authentication: 'anonymous' as const };
  const listen = (server: Server) => new Promise<string>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.removeListener('error', reject); resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`); });
  });
  beforeAll(async () => {
    trap = createServer((_request, response) => { trapRequests++; response.end('forbidden'); });
    trapOrigin = await listen(trap);
    server = createServer((request, response) => {
      if (request.method === 'POST') { posts++; response.end('posted'); return; }
      if (request.url === '/redirect') { response.writeHead(302, { location: '/escape' }); response.end(); return; }
      if (request.url === '/escape') { response.writeHead(302, { location: `${trapOrigin}/private?token=SECRET` }); response.end(); return; }
      response.setHeader('content-type', 'text/html');
      if (request.url === '/fetch') { response.end(`<body><script>fetch('${trapOrigin}/fetch').catch(()=>{}).finally(()=>document.body.dataset.done='yes')</script></body>`); return; }
      if (request.url === '/post') { response.end("<body><script>fetch('/mutate',{method:'POST',body:'PRIVATE'}).catch(()=>{}).finally(()=>document.body.dataset.done='yes')</script></body>"); return; }
      if (request.url === '/form') { response.end('<body><form id="form" action="/mutate" method="POST"><button>Submit</button></form></body>'); return; }
      response.end('<body><p id="done">Approved page</p></body>');
    });
    origin = await listen(server);
    // The driver has a wider declared scope, so these tests prove the policy narrows it.
    context = { project: { id: 'policy-live', name: 'Policy', mode: 'black-box', baseUrl: origin,
      allowedOrigins: [origin, trapOrigin], languages: [] }, identities: [anonymous], endpoints: [], components: [], resources: [], signals: [], evidence: [] };
  });
  afterAll(async () => {
    await Promise.all([server, trap].filter(server => server?.listening).map(server => new Promise<void>((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve()); server.closeAllConnections();
    })));
  });
  async function browser(path: string, options: Partial<PolicyConfiguration> = {}, submit = false) {
    const adapter = new TesterArmyE2EAdapter({ timeoutMs: 10_000 });
    const controller = new WorkflowBrowserController({ driver: adapter, context });
    const registry = new CapabilityRegistry().register({ metadata: { id: 'browser', capabilities: ['browser-controller'],
      supportedCwes: 'all', protocols: ['http'], risk: 'active' }, capabilities: { 'browser-controller': controller } });
    const plan = { id: 'live-plan', targetUrl: `${origin}${path}`, risk: 'active' as const, requiredCapabilities: ['browser-controller'] };
    const resolution = await registry.resolvePlan({ ...plan, cweId: 'CWE-79' });
    const engine = new PolicyEngine({ allowedOrigins: [origin], tools: { browser: {} }, approval: { risks: [], severities: [] }, ...options });
    const result = engine.run({ project: context.project, plan }, resolution, async e => e.capabilities.get('browser-controller').withSession(anonymous, async page => {
      await page.perform({ action: 'navigate', url: plan.targetUrl });
      if (submit) await page.perform({ action: 'submit', selector: '#form' });
      if (path === '/post' || path === '/fetch') await page.perform({ action: 'wait-visible', selector: 'body[data-done="yes"]' });
    }));
    return { engine, outcome: await result.then(() => 'completed', () => 'denied') };
  }
  it('allows an approved real page and records one exchange per network request', async () => {
    const { engine, outcome } = await browser('/');
    expect(outcome).toBe('completed');
    expect(engine.audit().some(record => record.operation === 'request' && record.outcome === 'ALLOW')).toBe(true);
    expect(engine.audit().some(record => record.code === 'rate-limited')).toBe(false);
  }, 20_000);
  it.each(['/redirect', '/fetch'])('blocks %s before the unauthorized listener receives traffic', async path => {
    const before = trapRequests;
    const { engine, outcome } = await browser(path);
    expect(outcome).toBe('denied'); expect(trapRequests).toBe(before);
    expect(engine.audit().some(record => record.code === 'target-denied')).toBe(true);
  }, 20_000);
  it.each(['/post', '/form'])('blocks page-originated POST from %s before it reaches the target', async path => {
    const before = posts;
    const { engine, outcome } = await browser(path, {}, path === '/form');
    expect(outcome).toBe('denied'); expect(posts).toBe(before);
    expect(engine.audit().some(record => record.code === 'method-denied')).toBe(true);
  }, 20_000);
  it('enforces the request budget on an in-origin redirect hop', async () => {
    const { engine, outcome } = await browser('/redirect', { maxRequestsPerExecution: 1 });
    expect(outcome).toBe('denied');
    expect(engine.audit().some(record => record.code === 'request-limit')).toBe(true);
  }, 20_000);
  it('guards a real single-hop HTTP client and refuses an external redirect', async () => {
    const before = trapRequests;
    const http = new DeterministicRequestExecutor({ baseUrl: origin, allowedOrigins: [origin, trapOrigin] });
    const registry = new CapabilityRegistry().register({ metadata: { id: 'http', capabilities: ['request-executor'],
      supportedCwes: 'all', protocols: ['http'], risk: 'passive' }, capabilities: { 'request-executor': http } });
    const plan = { id: 'http-plan', targetUrl: `${origin}/escape`, risk: 'active' as const, requiredCapabilities: ['request-executor'] };
    const resolution = await registry.resolvePlan({ ...plan, cweId: 'CWE-79' });
    const engine = new PolicyEngine({ allowedOrigins: [origin], tools: { http: {} }, approval: { risks: [], severities: [] } });
    await expect(engine.run({ project: context.project, plan }, resolution, async e => e.capabilities.get('request-executor').execute({ url: plan.targetUrl }))).rejects.toThrow('redirect-denied');
    expect(trapRequests).toBe(before);
  });
});

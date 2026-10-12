import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { AgentOOrchestrator } from '@agento/core';
import type { Project } from '@agento/core';
import { discoverProject, toProject } from '@agento/discovery';
import { ExpressFrameworkAdapter } from '../src/index.js';
import type { ExpressAnalysis } from '../src/index.js';
import { runCli } from '../src/cli.js';

const roots: string[] = [];
const demoPath = fileURLToPath(new URL('../../../../demo-apps/demo-app-01/', import.meta.url));
const adapter = new ExpressFrameworkAdapter({ now: () => '2026-10-12T00:00:00.000Z' });
const project = (repositoryPath: string): Project => ({ id: 'test-shop', name: 'Shop', mode: 'code-aware',
  repositoryPath, baseUrl: 'http://localhost:3000', allowedOrigins: ['http://localhost:3000'], languages: ['javascript', 'typescript'] });
async function repository(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'agento-express-'));
  roots.push(root);
  for (const [file, contents] of Object.entries(files)) {
    await mkdir(dirname(join(root, file)), { recursive: true });
    await writeFile(join(root, file), contents);
  }
  return root;
}
afterEach(async () => { await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true }))); });
function facts(analysis: ExpressAnalysis, observation: string, path?: string) {
  const endpoints = analysis.endpoints.filter(endpoint => !path || endpoint.path === path).map(endpoint => endpoint.id);
  return analysis.evidence.filter(item => item.facts.observation === observation && endpoints.includes(item.endpointId!)).map(item => item.facts);
}
const gate = `export function authenticate(request, response, next) {
  if (!request.session || !request.session.user) return response.status(401).json({ error: 'Login required' });
  next();
}`;

describe('real demo and contract integration', () => {
  it('extracts every declared demo route with full router mount paths', async () => {
    expect(await adapter.supports(project(demoPath))).toBe(true);
    const analysis = await adapter.extract(project(demoPath));
    expect(analysis.diagnostics).toEqual([]);
    expect(analysis.endpoints.map(endpoint => `${endpoint.method} ${endpoint.path}`).sort()).toEqual([
      'POST /api/auth/login', 'POST /api/auth/logout', 'GET /api/auth/me', 'GET /api/profile', 'PUT /api/profile',
      'GET /api/products', 'GET /api/products/:id', 'GET /api/orders', 'POST /api/orders', 'GET /api/orders/:id',
      'GET /api/admin/users', 'GET /api/admin/stats', 'DELETE /api/admin/users/:id', 'GET /api/config/security-mode',
      'POST /api/config/security-mode', 'POST /api/config/reset-db', 'GET /api/search', 'GET /search', 'GET /admin',
    ].sort());
    expect(analysis.components).toMatchObject([{ projectId: 'test-shop', kind: 'service' }]);
    expect(analysis.resources).toEqual([]);
    expect(analysis.signals).toEqual([]);
  });

  it('recognizes authentication and retains conditional admin authorization without claiming a required role', async () => {
    const analysis = await adapter.extract(project(demoPath));
    expect(analysis.endpoints.find(endpoint => endpoint.path === '/api/orders/:id')?.authentication).toBe('required');
    expect(analysis.endpoints.find(endpoint => endpoint.path === '/api/profile')?.authentication).toBe('required');
    const admin = analysis.endpoints.find(endpoint => endpoint.path === '/api/admin/users');
    expect(admin).toMatchObject({ authentication: 'required', roles: [] });
    expect(facts(analysis, 'authorization-guard', '/api/admin/users')).toContainEqual(expect.objectContaining({
      roles: ['admin'], enforcement: 'conditional', runtimeVerified: false,
    }));
    expect(analysis.endpoints.find(endpoint => endpoint.path === '/api/products')?.authentication).toBe('unknown');
  });

  it('collects inputs from handlers, destructuring, and imported request helpers', async () => {
    const analysis = await adapter.extract(project(demoPath));
    const orders = analysis.endpoints.find(endpoint => endpoint.method === 'POST' && endpoint.path === '/api/orders');
    expect(orders?.parameters).toEqual(expect.arrayContaining(['productName', 'quantity', 'totalPrice', 'shippingAddress']
      .map(name => ({ name, location: 'body', required: false }))));
    expect(analysis.endpoints.find(endpoint => endpoint.path === '/api/orders/:id')?.parameters)
      .toContainEqual({ name: 'id', location: 'path', required: true });
    expect(analysis.endpoints.find(endpoint => endpoint.path === '/api/search')?.parameters).toEqual(expect.arrayContaining([
      { name: 'q', location: 'query', required: false }, { name: 'security_mode', location: 'query', required: false },
      { name: 'x-security-mode', location: 'header', required: false },
    ]));
  });

  it('extracts session defaults and both cookie branches, redacting all source secrets and tokens', async () => {
    const analysis = await adapter.extract(project(demoPath));
    expect(facts(analysis, 'session', '/api/auth/login')).toContainEqual(expect.objectContaining({ options: {
      name: 'agento_sid', secret: '[REDACTED]', resave: false, saveUninitialized: false,
      cookie: { httpOnly: false, secure: false, sameSite: 'lax', maxAge: 86400000 },
    } }));
    const cookies = facts(analysis, 'cookie', '/api/auth/login');
    expect(cookies).toHaveLength(2);
    expect(cookies).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: 'auth_token', options: expect.objectContaining({ httpOnly: true, secure: true }),
        conditions: [{ kind: 'conditional', branch: 'then' }] }),
      expect.objectContaining({ options: expect.objectContaining({ httpOnly: false, secure: false }),
        conditions: [{ kind: 'conditional', branch: 'else' }] }),
    ]));
    expect(facts(analysis, 'session-cookie-update', '/api/auth/login')).toContainEqual(expect.objectContaining({
      attribute: 'httpOnly', value: { kind: 'dynamic' },
    }));
    const serialized = JSON.stringify(analysis);
    for (const secret of ['agento-super-secret-demo-session-key', 'alice123', 'bob123', 'admin123', 'sess_${']) {
      expect(serialized).not.toContain(secret);
    }
  });

  it('represents custom CORS reflection, static values, and conditional branches', async () => {
    const analysis = await adapter.extract(project(demoPath));
    const cors = facts(analysis, 'cors-header', '/api/orders/:id');
    expect(cors).toContainEqual(expect.objectContaining({ header: 'access-control-allow-origin',
      value: { kind: 'dynamic' }, requestInput: 'headers.origin' }));
    expect(cors).toContainEqual(expect.objectContaining({ header: 'access-control-allow-origin', value: '*' }));
    expect(cors).toContainEqual(expect.objectContaining({ header: 'access-control-allow-credentials', value: 'true' }));
    expect(cors.some(item => (item.conditions as unknown[]).length > 0)).toBe(true);
    expect(facts(analysis, 'cors-origin-allowlist', '/api/orders/:id')).toContainEqual(expect.objectContaining({
      origins: ['http://localhost:3000', 'http://127.0.0.1:3000'],
    }));
  });

  it('represents SQL around orders, admin, search, and profile without storing SQL or data values', async () => {
    const analysis = await adapter.extract(project(demoPath));
    expect(facts(analysis, 'database-operation', '/api/orders/:id')).toContainEqual(expect.objectContaining({
      api: 'get', operation: 'SELECT', tables: ['orders', 'users'], interpolated: false, placeholders: 1,
    }));
    expect(facts(analysis, 'database-operation', '/api/search')).toEqual(expect.arrayContaining([
      expect.objectContaining({ api: 'all', interpolated: true, placeholders: 0, argumentCount: 0 }),
      expect.objectContaining({ api: 'all', interpolated: false, placeholders: 2, argumentCount: 2 }),
    ]));
    expect(facts(analysis, 'database-operation', '/api/profile')).toContainEqual(expect.objectContaining({ operation: 'UPDATE', tables: ['users'] }));
    expect(facts(analysis, 'database-operation', '/api/admin/users/:id')).toContainEqual(expect.objectContaining({ operation: 'DELETE', tables: ['users'] }));
    expect(JSON.stringify(analysis)).not.toContain('SELECT o.*');
  });

  it('preserves JSON-safe evidence IDs, project provenance, handlers, and accurate source lines', async () => {
    const analysis = await adapter.extract(project(demoPath));
    const ids = new Set(analysis.evidence.map(item => item.id));
    expect(ids.size).toBe(analysis.evidence.length);
    expect(JSON.parse(JSON.stringify(analysis))).toEqual(analysis);
    for (const endpoint of analysis.endpoints) {
      expect(endpoint.evidenceIds.every(id => ids.has(id))).toBe(true);
      expect(endpoint.handler?.file).toMatch(/^src\//);
      const route = analysis.evidence.find(item => item.endpointId === endpoint.id && item.facts.observation === 'route')!;
      const lines = (await readFile(join(demoPath, route.source!.file), 'utf8')).split('\n');
      expect(lines[route.source!.startLine - 1]).toContain(`.${endpoint.method.toLowerCase()}(`);
    }
    expect(analysis.evidence.every(item => item.projectId === 'test-shop' && item.producerId === adapter.id)).toBe(true);
  });

  it('registers the real adapter with discovery and runs the core pipeline without scanners or browsers', async () => {
    const discovery = await discoverProject(demoPath, { adapters: [{ framework: 'express',
      languages: ['javascript', 'typescript'], adapter }] });
    expect(discovery).toMatchObject({ mode: 'code-aware', expressAdapterAvailable: true,
      availableAdapterIds: [adapter.id], supportedCodeAwareMode: true });
    const prepared = toProject(discovery, { id: 'wired-shop', baseUrl: 'http://localhost:3000', allowedOrigins: ['http://localhost:3000'] });
    const result = await new AgentOOrchestrator({ plugins: [], frameworkAdapter: adapter }).run({ project: prepared, identities: [] });
    expect(result.context.endpoints).toHaveLength(19);
    expect(result.context.evidence.length).toBeGreaterThan(0);
    expect(result.findings).toEqual([]);
  });

  it('produces stable IDs and repeatable results with an injected clock', async () => {
    expect(await adapter.extract(project(demoPath))).toEqual(await adapter.extract(project(demoPath)));
    const other = await adapter.extract({ ...project(demoPath), id: 'another-shop' });
    const first = await adapter.extract(project(demoPath));
    expect(other.endpoints[0]?.id).not.toBe(first.endpoints[0]?.id);
  });
});

describe('route syntax and middleware topology', () => {
  it('resolves aliased ESM factories, default handlers, barrels, namespaces, and mounted routers', async () => {
    const root = await repository({
      'main.ts': `import server from 'express'; import routes from './routes.js';
        const app = server(); app.use('/api', routes);`,
      'routes.ts': `import { Router as makeRouter } from 'express'; import * as handlers from './barrel.js';
        const r = makeRouter(); r.get('/items/:id', handlers.read); export default r;`,
      'barrel.ts': `export { default as read } from './handler.js';`,
      'handler.ts': `export default function readItem(input, output) { output.json({ q: input.query.q }); }`,
    });
    const analysis = await adapter.extract(project(root));
    expect(analysis.diagnostics).toEqual([]);
    expect(analysis.endpoints).toMatchObject([{ method: 'GET', path: '/api/items/:id',
      handler: { file: 'handler.ts', symbol: 'readItem' } }]);
    expect(analysis.endpoints[0]?.parameters).toContainEqual({ name: 'q', location: 'query', required: false });
  });

  it('supports route chains, all methods, array paths, handler arrays, and constant paths', async () => {
    const root = await repository({ 'app.js': `import express from 'express'; const app = express();
      const read = (req, res) => res.json(req.query.page); const write = (req, res) => res.json(req.body.title);
      const path = '/items/:id'; app.route(path).get([read]).post(write);
      app.all('/health', read); app.get(['/one', '/two'], read);` });
    const analysis = await adapter.extract(project(root));
    expect(analysis.diagnostics).toEqual([]);
    expect(analysis.endpoints.map(item => `${item.method} ${item.path}`)).toEqual(expect.arrayContaining([
      'GET /items/:id', 'POST /items/:id', 'GET /one', 'GET /two', 'OPTIONS /health', 'PATCH /health', 'DELETE /health',
    ]));
    expect(analysis.endpoints).toHaveLength(11);
  });

  it('keeps middleware order, path scopes, sibling routers, and repeated mounts distinct', async () => {
    const root = await repository({ 'app.js': `import express from 'express'; ${gate}
      const app = express(); const r = express.Router(); r.get('/:id', (req,res)=>res.json(req.params.id));
      app.get('/early', (req,res)=>res.end()); app.use('/private', authenticate);
      app.use('/private', r); app.use('/public', r); app.use(authenticate);
      app.get('/late', (req,res)=>res.end());` });
    const analysis = await adapter.extract(project(root));
    expect(analysis.endpoints.map(item => [item.path, item.authentication])).toEqual([
      ['/early', 'unknown'], ['/private/:id', 'required'], ['/public/:id', 'unknown'], ['/late', 'required'],
    ]);
    expect(new Set(analysis.endpoints.map(item => item.id)).size).toBe(4);
  });

  it('applies parent middleware scoped below a router mount to matching child routes', async () => {
    const root = await repository({ 'app.js': `import express from 'express'; ${gate}
      const app=express(), r=express.Router(); app.use('/api/private', authenticate);
      r.get('/private', (req,res)=>res.end()); r.get('/public', (req,res)=>res.end()); app.use('/api', r);` });
    const analysis = await adapter.extract(project(root));
    expect(analysis.endpoints.map(item => [item.path, item.authentication])).toEqual([
      ['/api/private', 'required'], ['/api/public', 'unknown'],
    ]);
  });

  it('recognizes an unconditional role guard and keeps conditional identity checks unknown', async () => {
    const root = await repository({ 'app.js': `import express from 'express'; const app=express();
      function admin(req,res,next) { if(!req.user) return res.sendStatus(401);
        if(req.user.role !== 'admin') return res.sendStatus(403); next(); }
      function sometimes(req,res,next) { if (!req.user && process.env.CHECK) return res.sendStatus(401); next(); }
      app.get('/admin', admin, (req,res)=>res.end()); app.get('/conditional', sometimes, (req,res)=>res.end());` });
    const analysis = await adapter.extract(project(root));
    expect(analysis.endpoints[0]).toMatchObject({ authentication: 'required', roles: ['admin'] });
    expect(analysis.endpoints[1]?.authentication).toBe('unknown');
    expect(facts(analysis, 'authentication-guard', '/conditional')).toContainEqual(expect.objectContaining({ enforcement: 'conditional' }));
  });

  it('does not infer authentication from names, login credential checks, or nested callback guards', async () => {
    const root = await repository({ 'app.js': `import express from 'express'; const app=express();
      function requireAuth(req,res,next) { next(); }
      app.get('/fake', requireAuth, (req,res)=>res.end());
      app.post('/login', (req,res)=> { if (!req.body.password) return res.sendStatus(401); res.end(); });
      app.get('/anonymous-session', (req,res)=> { if (!req.session) return res.sendStatus(401); res.end(); });
      app.get('/callback', (req,res)=> { const ignored = () => { if(!req.user) return res.sendStatus(401); }; res.end(); });` });
    const analysis = await adapter.extract(project(root));
    expect(analysis.endpoints.every(item => item.authentication === 'unknown')).toBe(true);
  });

  it('follows CommonJS router defaults and named handler exports', async () => {
    const root = await repository({
      'app.cjs': `const express=require('express'); const router=require('./routes.cjs'); const app=express(); app.use('/api', router);`,
      'routes.cjs': `const {Router}=require('express'); const {read}=require('./handler.cjs');
        const router=Router(); router.get('/items', read); module.exports=router;`,
      'handler.cjs': `function read(req,res) { res.json(req.query.filter); } module.exports={read};`,
    });
    const analysis = await adapter.extract(project(root));
    expect(analysis.diagnostics).toEqual([]);
    expect(analysis.endpoints).toMatchObject([{ path: '/api/items', handler: { file: 'handler.cjs', symbol: 'read' } }]);
    expect(analysis.endpoints[0]?.parameters).toContainEqual({ name: 'filter', location: 'query', required: false });
  });

  it('does not confuse unrelated get methods or shadowed router names with Express routes', async () => {
    const root = await repository({ 'app.ts': `import express from 'express'; const app=express();
      const cache={get(path, fn) {}}; cache.get('/fake', ()=>{});
      function ignored() { const app=cache; app.get('/shadow', ()=>{}); }
      app.get('/real', (req,res)=>res.end());` });
    expect((await adapter.extract(project(root))).endpoints.map(item => item.path)).toEqual(['/real']);
  });

  it('keeps duplicate same-line routes and mount registrations identifiable', async () => {
    const root = await repository({ 'app.js': `import express from 'express'; const app=express(),r=express.Router();
      r.get('/x',()=>{}); r.get('/x',()=>{}); app.use('/api',r); app.use('/api',r);` });
    const analysis = await adapter.extract(project(root));
    expect(analysis.endpoints).toHaveLength(4);
    expect(new Set(analysis.endpoints.map(item => item.id)).size).toBe(4);
  });

  it('observes string concatenation SQL and redacts credentials embedded in configuration URLs', async () => {
    const root = await repository({ 'app.js': `import express from 'express'; import cors from 'cors'; const app=express();
      app.use(cors({origin:'https://user:private-password@example.test'}));
      app.get('/query', (req,res)=>res.json(db.query('SELECT * FROM users WHERE id = ' + req.query.id)));` });
    const analysis = await adapter.extract(project(root));
    expect(facts(analysis, 'database-operation')).toContainEqual(expect.objectContaining({ operation: 'SELECT', tables: ['users'], interpolated: true }));
    expect(facts(analysis, 'cors')[0]?.options).toEqual({ origin: '[REDACTED]' });
    expect(JSON.stringify(analysis)).not.toContain('private-password');
  });

  it('handles bracket inputs, request aliases, destructuring aliases, and helper argument positions', async () => {
    const root = await repository({ 'app.js': `import express from 'express'; const app=express();
      function helper(unused, input) { return input.query.helper; }
      app.post('/inputs/{:id}', (request,response)=> { const r=request;
        const { email: address, ...rest }=r.body; helper(1,r);
        response.json([r.query['q'], r.get('X-Mode'), r.cookies.session, address]); });` });
    const analysis = await adapter.extract(project(root));
    expect(analysis.endpoints[0]?.parameters).toEqual(expect.arrayContaining([
      { name: 'email', location: 'body', required: false }, { name: '*', location: 'body', required: false },
      { name: 'q', location: 'query', required: false }, { name: 'helper', location: 'query', required: false },
      { name: 'x-mode', location: 'header', required: false }, { name: 'session', location: 'cookie', required: false },
    ]));
  });

  it('extracts mounted library CORS and session configuration while retaining unresolved values', async () => {
    const root = await repository({ 'app.js': `import express from 'express'; import cors from 'cors'; import session from 'express-session';
      const app=express(); const cookie={httpOnly:true,secure:process.env.TLS,sameSite:'strict'};
      const config={secret:'hidden-value',cookie,saveUninitialized:false};
      app.use(session(config)); app.use(cors({origin:['http://localhost:3000'],credentials:true}));
      app.get('/ok', (req,res)=>res.end());` });
    const analysis = await adapter.extract(project(root));
    expect(facts(analysis, 'session')).toContainEqual(expect.objectContaining({ options: {
      secret: '[REDACTED]', saveUninitialized: false, cookie: { httpOnly: true, secure: { kind: 'dynamic' }, sameSite: 'strict' },
    } }));
    expect(facts(analysis, 'cors')).toContainEqual(expect.objectContaining({ options: { origin: ['http://localhost:3000'], credentials: true } }));
    expect(JSON.stringify(analysis)).not.toContain('hidden-value');
  });

  it('ignores settings getters, recognizes optional parameters, and reports unknown middleware factories', async () => {
    const root = await repository({ 'app.js': `import express from 'express'; import makeGate from 'custom-auth'; const app=express();
      const setting=app.get('env'); const gate=makeGate(); app.use(gate);
      app.get('/users{/:id}', (req,res)=>res.end()); app.get('/files{/*splat}', (req,res)=>res.end());` });
    const analysis = await adapter.extract(project(root));
    expect(analysis.endpoints.map(item => item.path)).toEqual(['/users{/:id}', '/files{/*splat}']);
    expect(analysis.endpoints[0]?.parameters).toContainEqual({ name: 'id', location: 'path', required: false });
    expect(analysis.endpoints[1]?.parameters).toContainEqual({ name: 'splat', location: 'path', required: false });
    expect(analysis.diagnostics.map(item => item.code)).toEqual(['unresolved-handler', 'unresolved-handler']);
    expect(analysis.endpoints.every(item => item.authentication === 'unknown')).toBe(true);
  });
});

describe('read-only boundaries and incomplete source', () => {
  it('returns partial observations with diagnostics for unresolved paths and handlers', async () => {
    const root = await repository({ 'app.js': `import express from 'express'; const app=express();
      app.get(process.env.ROUTE, (req,res)=>res.end()); app.get(/regex/, ()=>{});
      app.get('/known', missingHandler);` });
    const analysis = await adapter.extract(project(root));
    expect(analysis.endpoints.map(item => item.path)).toEqual(['/known']);
    expect(analysis.diagnostics.map(item => item.code)).toEqual(['unresolved-route', 'unresolved-route', 'unresolved-handler']);
  });

  it('reports conditional registration and does not assert mandatory authentication on it', async () => {
    const root = await repository({ 'app.js': `import express from 'express'; ${gate} const app=express();
      if(process.env.ADMIN) app.get('/conditional', authenticate, (req,res)=>res.end());` });
    const analysis = await adapter.extract(project(root));
    expect(analysis.endpoints[0]?.authentication).toBe('unknown');
    expect(analysis.diagnostics).toContainEqual(expect.objectContaining({ code: 'conditional-registration' }));
    expect(facts(analysis, 'route')[0]?.conditional).toBe(true);
  });

  it('bounds cyclic router mounts and recursive helpers', async () => {
    const root = await repository({ 'app.js': `import express from 'express'; const app=express(),r=express.Router();
      function helper(req) { helper(req); return req.query.q; }
      r.get('/ok', (req,res)=>res.json(helper(req))); r.use('/loop',r); app.use('/api',r);` });
    const analysis = await adapter.extract(project(root));
    expect(analysis.endpoints.map(item => item.path)).toEqual(['/api/ok']);
    expect(analysis.diagnostics).toContainEqual(expect.objectContaining({ code: 'router-cycle' }));
  });

  it('bounds cyclic receiver aliases and self-referential middleware arrays', async () => {
    const root = await repository({ 'app.js': `import express from 'express'; const app=express();
      const receiver=receiver.route('/cycle'); receiver.get(()=>{});
      const middleware=[middleware]; app.get('/ok',middleware,(req,res)=>res.end());` });
    const analysis = await adapter.extract(project(root));
    expect(analysis.endpoints.map(item => item.path)).toEqual(['/ok']);
    expect(analysis.diagnostics).toContainEqual(expect.objectContaining({ code: 'limit-reached' }));
  });

  it('skips test fixtures, build output, dependencies, hidden files, and symlinks', async () => {
    const source = `import express from 'express'; const app=express(); app.get('/ignored',()=>{});`;
    const root = await repository({ 'app.js': source.replace('/ignored', '/real'), 'test/fake.js': source,
      'fixtures/fake.js': source, 'dist/fake.js': source, 'node_modules/fake.js': source, '.hidden/fake.js': source });
    const outside = await repository({ 'outside.js': source });
    await symlink(join(outside, 'outside.js'), join(root, 'linked.js'));
    expect((await adapter.extract(project(root))).endpoints.map(item => item.path)).toEqual(['/real']);
    await symlink(root, join(outside, 'repository-link'));
    expect(await adapter.supports(project(join(outside, 'repository-link')))).toBe(false);
  });

  it('reports parse errors and oversized source files without reading raw text into diagnostics', async () => {
    const root = await repository({ 'bad.ts': 'const secret = "private-password"; const x = ;',
      'big.js': 'x'.repeat(1_048_577), 'good.js': `import express from 'express'; const app=express(); app.get('/ok',()=>{});` });
    const analysis = await adapter.extract(project(root));
    expect(analysis.endpoints.map(item => item.path)).toEqual(['/ok']);
    expect(analysis.diagnostics.map(item => item.code)).toEqual(['parse-failed', 'limit-reached']);
    expect(JSON.stringify(analysis)).not.toContain('private-password');
    expect(await adapter.supports(project(root))).toBe(false);
  });

  it('handles unavailable paths, empty repositories, and unsupported frameworks', async () => {
    const root = await repository({ 'app.js': `import fastify from 'fastify'; const app=fastify(); app.get('/no',()=>{});` });
    expect(await adapter.supports(project(root))).toBe(false);
    expect((await adapter.extract(project(root))).endpoints).toEqual([]);
    expect(await adapter.supports(project(await repository({})))).toBe(false);
    const analysis = await adapter.extract(project(join(root, 'missing')));
    expect(analysis.diagnostics).toContainEqual(expect.objectContaining({ code: 'repository-unavailable' }));
    const { repositoryPath: omitted, ...withoutRepository } = project(root);
    expect((await adapter.extract(withoutRepository)).diagnostics[0]?.code).toBe('repository-unavailable');
  });

  it('does not import target code, execute scripts, or create the target database', async () => {
    const root = await repository({
      'app.js': `import express from 'express'; import {writeFileSync} from 'node:fs';
        writeFileSync(new URL('./executed.txt',import.meta.url),'executed'); throw new Error('never run');
        const app=express(); app.get('/ok',()=>{});`,
      'package.json': JSON.stringify({ scripts: { preinstall: 'exit 99' }, dependencies: { express: '*' } }),
    });
    expect((await adapter.extract(project(root))).endpoints).toHaveLength(1);
    await expect(readFile(join(root, 'executed.txt'))).rejects.toThrow();
    await expect(readFile(join(root, 'demo.sqlite'))).rejects.toThrow();
  });

  it('demonstrates independent CLI JSON output and useful exit status', async () => {
    let output = '', error = '';
    const writeOut = (text: string) => { output = text; };
    const writeError = (text: string) => { error = text; };
    expect(await runCli([demoPath], writeOut, writeError)).toBe(0);
    expect(JSON.parse(output).endpoints).toHaveLength(19);
    expect(error).toBe('');
    expect(await runCli(['--help'], writeOut, writeError)).toBe(0);
    expect(output).toContain('Usage:');
    expect(await runCli(['/does-not-exist'], writeOut, writeError)).toBe(1);
    expect(JSON.parse(output).diagnostics[0].code).toBe('repository-unavailable');
    expect(await runCli([], writeOut, writeError)).toBe(1);
    expect(error).toContain('Usage:');
  });
});

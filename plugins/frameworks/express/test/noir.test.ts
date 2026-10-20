import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { isEndpointTestable, type EndpointDiscoveryProvider, type Project } from '@agento/core';
import { ExpressFrameworkAdapter, NoirEndpointDiscoveryProvider } from '../src/index.js';
import { runCli } from '../src/cli.js';

const roots: string[] = [];
const now = () => '2026-10-20T00:00:00.000Z';
const source = `import express from 'express';
const app=express(), router=express.Router();
router.get('/items/:id', (req,res)=>res.json(req.query.q));
app.use('/api', router);`;
const project = (repositoryPath: string): Project => ({ id: 'shop', name: 'Shop', mode: 'code-aware', repositoryPath,
  baseUrl: 'http://localhost:3000', allowedOrigins: ['http://localhost:3000'], languages: ['javascript'] });
async function directory(files: Record<string, string> = {}): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'agento-noir-test-')); roots.push(root);
  for (const [file, text] of Object.entries(files)) { await mkdir(dirname(join(root, file)), { recursive: true }); await writeFile(join(root, file), text); }
  return root;
}
async function tool(body: string, version = '1.4.0'): Promise<string> {
  const root = await directory();
  const executable = join(root, 'noir.cjs');
  await writeFile(executable, `#!${process.execPath}\nif(process.argv[2]==='--version'){require('node:fs').writeSync(1,${JSON.stringify(version + '\n')});process.exit(0);}\nconsole.log=value=>require('node:fs').writeSync(1,String(value)+'\\n');\nconsole.error=value=>require('node:fs').writeSync(2,String(value)+'\\n');\n${body}\n`);
  await chmod(executable, 0o700); return executable;
}
const raw = (extra = '') => `const path=require('node:path'); const fs=require('node:fs'); const root=process.argv[3];
const endpoint={url:'/items/:id',method:'GET',protocol:'http',internal:false,params:[{name:'id',param_type:'path',value:'PRIVATE'},
{name:'q',param_type:'query',value:'PRIVATE'},{name:'title',param_type:'json',value:'PRIVATE'}],
details:{technology:'js_express',code_paths:[{path:path.join(root,'app.js'),line:3}]},tags:[{name:'PRIVATE'}]};
${extra}
console.log(JSON.stringify({endpoints:[endpoint],errors:[]}));`;
afterEach(async () => { vi.unstubAllEnvs(); await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true }))); });

describe('Noir boundary and default composition', () => {
  it('normalizes names and source locations without raw values, tags, auth guesses or handlers', async () => {
    const root = await directory({ 'app.js': source });
    const provider = new NoirEndpointDiscoveryProvider({ executable: await tool(raw()), now });
    const result = await provider.discover(project(root));
    expect(result.discovery).toMatchObject({ status: 'completed', diagnostics: [] });
    expect(result.endpoints).toHaveLength(1);
    expect(result.endpoints[0]).toMatchObject({ authentication: 'unknown', roles: [], discovery: { validation: 'candidate' },
      parameters: expect.arrayContaining([{ name: 'title', location: 'body', required: false }]) });
    expect(result.endpoints[0]?.handler).toBeUndefined();
    expect(result.evidence.find(item => item.endpointId)?.source).toEqual({ file: 'app.js', startLine: 3 });
    expect(JSON.stringify(result)).not.toContain('PRIVATE');
    expect(await provider.discover(project(root))).toEqual(result);
  });

  it('repairs a lost mount only from independent source topology and retains the original claim', async () => {
    const root = await directory({ 'app.js': source });
    const adapter = new ExpressFrameworkAdapter({ noir: { executable: await tool(raw()) }, now });
    const result = await adapter.extract(project(root));
    expect(result.endpoints).toHaveLength(1);
    expect(result.endpoints[0]).toMatchObject({ path: '/api/items/:id', discovery: { validation: 'source-corroborated' } });
    expect(result.endpoints[0]?.parameters.map(item => item.name)).toEqual(['id', 'q']);
    expect(result.evidence.find(item => item.facts.observation === 'endpoint-candidate')?.facts.path).toBe('/items/:id');
    expect(result.evidence.every(item => !item.endpointId || result.endpoints.some(endpoint => endpoint.id === item.endpointId))).toBe(true);
    expect(isEndpointTestable(result.endpoints[0]!)).toBe(true);
  });

  it('keeps unresolved router-chain mounts as non-executable candidates', async () => {
    const root = await directory({ 'app.js': `import express,{Router} from 'express';
const r=Router().use('/api', Router());
r.get('/items/:id', (req,res)=>res.end()); const app=express(); app.use(r);` });
    const result = await new ExpressFrameworkAdapter({ noir: { executable: await tool(raw()) }, now }).extract(project(root));
    expect(result.endpoints).toHaveLength(1);
    expect(isEndpointTestable(result.endpoints[0]!)).toBe(false);
    expect(result.diagnostics.some(item => item.code === 'unvalidated-endpoint')).toBe(true);
  });

  it('accepts a tool-independent normalized provider through the same port', async () => {
    const root = await directory({ 'app.js': source });
    const provider: EndpointDiscoveryProvider = { id: 'alternative', capabilities: ['static-endpoint-discovery'],
      async discover() { return { components: [], endpoints: [], resources: [], signals: [], evidence: [],
        discovery: { providerId: 'alternative', status: 'completed', diagnostics: [] } }; } };
    const result = await new ExpressFrameworkAdapter({ endpointDiscoveryProvider: provider, now }).extract(project(root));
    expect(result.endpoints[0]?.path).toBe('/api/items/:id');
    expect(result.discovery?.providerId).toBe('alternative');
  });

  it('reports an absent binary and does not silently substitute the custom extractor', async () => {
    const root = await directory({ 'app.js': source });
    const result = await new ExpressFrameworkAdapter({ noir: { executable: join(root, 'missing') }, now }).extract(project(root));
    expect(result.discovery).toMatchObject({ status: 'unavailable', diagnostics: [{ code: 'tool-unavailable' }] });
    expect(result.endpoints).toEqual([]);
    expect(result.evidence.find(item => item.facts.observation === 'endpoint-discovery-run')?.facts.completeCoverage).toBe(false);
  });

  it('rejects unsupported versions before scanning and suppresses raw failures', async () => {
    const root = await directory({ 'app.js': source });
    const version = await new NoirEndpointDiscoveryProvider({ executable: await tool('throw new Error("PRIVATE");', '0.0.0') }).discover(project(root));
    expect(version.discovery.diagnostics[0]?.code).toBe('tool-version');
    const failed = await new NoirEndpointDiscoveryProvider({ executable: await tool('console.error("PRIVATE");process.exit(9);') }).discover(project(root));
    expect(failed.discovery.diagnostics[0]?.code).toBe('tool-failed');
    expect(JSON.stringify(failed)).not.toContain('PRIVATE');
  });

  it('rejects malformed JSON and retains explicit partial status for strict exit 2', async () => {
    const root = await directory({ 'app.js': source });
    const malformed = await new NoirEndpointDiscoveryProvider({ executable: await tool('console.log("PRIVATE");') }).discover(project(root));
    expect(malformed.discovery).toMatchObject({ status: 'failed', diagnostics: [{ code: 'invalid-output' }] });
    const partial = await new NoirEndpointDiscoveryProvider({ executable: await tool(raw() + '\nprocess.exitCode=2;') }).discover(project(root));
    expect(partial.discovery).toMatchObject({ status: 'partial', diagnostics: [{ code: 'tool-failed' }] });
    expect(partial.endpoints).toHaveLength(1);
  });

  it('bounds time and combined stdout/stderr, and honors cancellation', async () => {
    const root = await directory({ 'app.js': source });
    const hanging = await tool('setInterval(()=>{},1000);');
    const timed = await new NoirEndpointDiscoveryProvider({ executable: hanging, timeoutMs: 100 }).discover(project(root));
    expect(timed.discovery.diagnostics[0]?.code).toBe('tool-timeout');
    const huge = await new NoirEndpointDiscoveryProvider({ executable: await tool('console.error("x".repeat(10000));'), maxOutputBytes: 512 }).discover(project(root));
    expect(huge.discovery.diagnostics[0]?.code).toBe('tool-output-limit');
    const controller = new AbortController();
    const cancelled = new NoirEndpointDiscoveryProvider({ executable: hanging }).discover(project(root), { signal: controller.signal });
    setTimeout(() => controller.abort(), 100);
    expect((await cancelled).discovery.diagnostics[0]?.code).toBe('cancelled');
  });

  it('rejects foreign, symlinked and out-of-range source locations and unsafe URLs', async () => {
    const root = await directory({ 'app.js': source });
    const outside = await directory({ 'outside.js': source });
    await symlink(join(outside, 'outside.js'), join(root, 'linked.js'));
    for (const modify of ["endpoint.details.code_paths[0].path='../outside.js';", "endpoint.details.code_paths[0].path=path.join(root,'linked.js');",
      'endpoint.details.code_paths[0].line=90000;', "endpoint.url='https://elsewhere.test/';", "endpoint.url='/login?token=PRIVATE';",
      "endpoint.url='//elsewhere.test/';", "endpoint.method='SEND';", "endpoint.protocol='cli';"]) {
      const result = await new NoirEndpointDiscoveryProvider({ executable: await tool(raw(modify)) }).discover(project(root));
      expect(result.endpoints).toEqual([]); expect(result.discovery.status).toBe('partial');
      expect(JSON.stringify(result)).not.toContain('PRIVATE');
    }
  });

  it('limits inventory records and parameter names while retaining explicit partial status', async () => {
    const root = await directory({ 'app.js': source });
    const parameters = await new NoirEndpointDiscoveryProvider({ executable: await tool(raw(
      "endpoint.params=Array.from({length:257},(_,index)=>({name:'q'+index,param_type:'query',value:'PRIVATE'}));")) }).discover(project(root));
    expect(parameters.endpoints[0]?.parameters).toHaveLength(256);
    expect(parameters.discovery).toMatchObject({ status: 'partial', diagnostics: [{ code: 'tool-output-limit' }] });
    const executable = await tool(raw().replace('endpoints:[endpoint]', 'endpoints:Array(10001).fill(endpoint)'));
    const inventory = await new NoirEndpointDiscoveryProvider({ executable }).discover(project(root));
    expect(inventory.endpoints).toHaveLength(1);
    expect(inventory.discovery).toMatchObject({ status: 'partial', diagnostics: [{ code: 'tool-output-limit' }] });
  });

  it('scans only selected source with an empty config and without model credentials or target execution', async () => {
    const root = await directory({ 'app.js': source + `\nrequire('node:fs').writeFileSync('executed','bad');`,
      'test/fake.js': source, 'node_modules/fake.js': source, 'data/static/codefixes/fake.js': source,
      '.env': 'OPENAI_API_KEY=PRIVATE', 'noir.yaml': 'ai: true', 'package.json': '{"scripts":{"preinstall":"exit 99"}}' });
    vi.stubEnv('OPENAI_API_KEY', 'PRIVATE');
    const result = await new NoirEndpointDiscoveryProvider({ executable: await tool(raw(`
if(process.env.OPENAI_API_KEY || fs.existsSync(path.join(root,'test')) || fs.existsSync(path.join(root,'node_modules'))
  || fs.existsSync(path.join(root,'data')) || fs.existsSync(path.join(root,'noir.yaml')) || fs.existsSync(path.join(root,'.env')))
  throw new Error('PRIVATE');
const config=process.argv[process.argv.indexOf('--config-file')+1];
if(fs.readFileSync(config,'utf8')!=='{}\\n' || process.argv.some(x=>/^--(ai|send|deliver|passive)/.test(x))) throw new Error('PRIVATE');
`) ) }).discover(project(root));
    expect(result.discovery.status).toBe('completed');
    await expect(readFile(join(root, 'executed'))).rejects.toThrow();
  });

  it('uses Noir by default in the standalone CLI', async () => {
    const root = await directory({ 'app.js': source });
    vi.stubEnv('AGENTO_NOIR_EXECUTABLE', await tool(raw()));
    let output = '';
    expect(await runCli([root], text => { output = text; }, () => {})).toBe(0);
    expect(JSON.parse(output)).toMatchObject({ discovery: { providerId: 'noir-endpoint-discovery' },
      endpoints: [{ path: '/api/items/:id', discovery: { validation: 'source-corroborated' } }] });
  });

  it('applies both adapter and provider exclusions to inventory and source enrichment', async () => {
    const root = await directory({ 'app.js': source,
      'private/hidden.js': source.replace('/items/:id', '/private'), 'generated/hidden.js': source.replace('/items/:id', '/generated') });
    const executable = await tool(raw(`if(fs.existsSync(path.join(root,'private')) || fs.existsSync(path.join(root,'generated'))) process.exit(9);`));
    const result = await new ExpressFrameworkAdapter({ excludePaths: ['private'], noir: { executable, excludePaths: ['generated'] } }).extract(project(root));
    expect(result.endpoints.map(item => item.path)).toEqual(['/api/items/:id']);
    expect(result.discovery?.status).toBe('completed');
  });
});

describe.runIf(process.env.AGENTO_NOIR_INTEGRATION === '1')('real pinned Noir integration', () => {
  it('retains all 19 mounted demo routes and AgentO security enrichment', async () => {
    const root = fileURLToPath(new URL('../../../../demo-apps/demo-app-01/', import.meta.url));
    const result = await new ExpressFrameworkAdapter({ now }).extract(project(root));
    expect(result.discovery).toMatchObject({ status: 'completed', diagnostics: [] });
    expect(result.endpoints).toHaveLength(19);
    expect(result.endpoints.every(isEndpointTestable)).toBe(true);
    expect(result.endpoints.find(endpoint => endpoint.path === '/api/orders/:id')?.authentication).toBe('required');
    expect(result.endpoints.find(endpoint => endpoint.path === '/api/search')?.parameters).toContainEqual({ name: 'q', location: 'query', required: false });
    expect(result.evidence.some(item => item.facts.observation === 'database-operation')).toBe(true);
    expect(result.diagnostics).toEqual([]);
  });
});

import { createServer, request } from 'node:http';
import type { Server } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createLocalApi } from '../server/api';
import { createHttpClient } from '../src/client';
import type { ExecutionServices } from '../server/execution';
import { demoDiscovery } from '../src/data/demo-discovery';

const input = { name: 'HTTP project', repositoryPath: '/work/http', baseUrl: 'http://localhost:3000', allowedOrigins: ['http://localhost:3000'] };
const execution: ExecutionServices = {
  discover: async repositoryPath => ({ ...demoDiscovery, repositoryPath }),
  analyze: async () => ({ analysis: { status: 'completed', diagnostics: [], signals: [], evidence: [] } }),
};
let server: Server;
let folder: string;
let base: string;
let closeApi: () => Promise<void>;
beforeEach(async () => {
  folder = await mkdtemp(join(tmpdir(), 'agento-api-test-'));
  const middleware = createLocalApi({ root: fileURLToPath(new URL('../../..', import.meta.url)), file: join(folder, 'workspace.json'), execution });
  closeApi = middleware.close;
  server = createServer((req, res) => { void middleware(req, res, () => { res.statusCode = 404; res.end(); }); });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
afterEach(async () => {
  if (server?.listening) await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  await closeApi?.();
  if (folder) await rm(folder, { recursive: true, force: true });
});
const post = (path: string, value: unknown, headers = {}) => fetch(`${base}${path}`, {
  method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(value),
});

describe('same-origin local API transport', () => {
  it('serves the browser client over real HTTP, including persisted project reads and typed empty states', async () => {
    const client = createHttpClient((path, options) => fetch(`${base}${path}`, options));
    const project = await client.createProject(input);
    expect(await client.getProject(project.id)).toMatchObject({ name: input.name });
    expect(await client.listProjects()).toHaveLength(2);
    await expect(client.getDiscovery(project.id)).rejects.toMatchObject({ code: 'DISCOVERY_UNAVAILABLE' });
    await expect(client.getScan(project.id)).rejects.toMatchObject({ code: 'SCAN_UNAVAILABLE' });
    expect(await client.getFindings(project.id)).toEqual([]);
    const found = await post('/api/discover', { repositoryPath: input.repositoryPath });
    await client.importDiscovery(project.id, (await found.json()).data);
    expect((await client.getDiscovery(project.id)).repositoryPath).toBe(input.repositoryPath);
  });
  it('rejects cross-origin mutations before saving or executing work', async () => {
    const response = await post('/api/projects', { input }, { Origin: 'https://attacker.example' });
    expect(response.status).toBe(403);
    expect((await response.json()).code).toBe('REQUEST_FORBIDDEN');
    expect((await (await fetch(`${base}/api/projects`)).json()).data).toHaveLength(1);
    const discover = await post('/api/discover', { repositoryPath: '/work/private' }, { Origin: 'https://attacker.example' });
    expect(discover.status).toBe(403);
  });
  it('rejects DNS rebinding hosts and cross-site fetches', async () => {
    for (const headers of [{ Host: 'evil.example' }, { 'Sec-Fetch-Site': 'cross-site' }]) {
      const status = await new Promise<number | undefined>((resolve, reject) => {
        const req = request(`${base}/api/projects`, { headers }, response => { response.resume(); resolve(response.statusCode); });
        req.once('error', reject); req.end();
      });
      expect(status).toBe(403);
    }
  });
  it('accepts a same-origin request and rejects non-JSON/oversized/invalid bodies', async () => {
    expect((await post('/api/projects', { input }, { Origin: base })).status).toBe(201);
    expect((await fetch(`${base}/api/projects`, { method: 'POST', body: 'input=bad' })).status).toBe(400);
    expect((await fetch(`${base}/api/projects`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{secret' })).status).toBe(400);
    expect((await post('/api/projects', { input: { ...input, name: 'x'.repeat(2_200_000) } })).status).toBe(400);
  });
  it('returns 202 for accepted work, then reports a terminal real scan through polling', async () => {
    const project = (await (await post('/api/projects', { input })).json()).data;
    const accepted = await post(`/api/projects/${project.id}/scan`, {});
    expect(accepted.status).toBe(202);
    expect((await accepted.json()).data).toMatchObject({ source: 'execution-api', state: 'pending' });
    await expect.poll(async () => (await (await fetch(`${base}/api/projects/${project.id}/scan`)).json()).data.state).toBe('complete');
    const findings = await fetch(`${base}/api/projects/${project.id}/findings`);
    expect((await findings.json()).data).toEqual([]);
  });
  it('handles unknown projects and unsupported methods without leaking internals', async () => {
    const response = await fetch(`${base}/api/projects/unknown`);
    expect(response.status).toBe(404);
    expect((await response.json()).code).toBe('PROJECT_NOT_FOUND');
    expect((await fetch(`${base}/api/projects`, { method: 'DELETE' })).status).toBe(405);
    expect((await fetch(`${base}/api/unknown`)).status).toBe(404);
  });
});

describe('HTTP failure behavior', () => {
  it('does not substitute fixtures when the service is disconnected', async () => {
    const client = createHttpClient(async () => { throw new Error('network failure'); });
    await expect(client.listProjects()).rejects.toMatchObject({ code: 'CLIENT_UNAVAILABLE' });
  });
});

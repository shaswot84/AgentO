import type { IncomingMessage, ServerResponse } from 'node:http';
import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { AgentOClientError } from '../src/client/types.ts';
import type { ProjectInput } from '../src/client/types.ts';
import type { DiscoveryResult } from '@agento/discovery';
import type { ExecutionServices } from './execution.ts';
import { LocalService } from './service.ts';
import { Workspace } from './workspace.ts';
import { claimWorkspace } from './lock.ts';

const loopback = (hostname: string) => ['localhost', '127.0.0.1', '[::1]'].includes(hostname);
const maxBody = 2 * 1024 * 1024 + 16 * 1024;

function respond(res: ServerResponse, status: number, value: unknown) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.end(JSON.stringify(value));
}

/** Guard local filesystem/tool capabilities against cross-site browser requests. */
function checkRequest(req: IncomingMessage) {
  const host = req.headers.host;
  const origin = host ? new URL(`http://${host}`) : undefined;
  if (!origin || !loopback(origin.hostname) || origin.host !== host
    || !['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress ?? '')
    || req.headers['sec-fetch-site'] === 'cross-site'
    || (req.headers.origin !== undefined && req.headers.origin !== origin.origin)) {
    throw new AgentOClientError('REQUEST_FORBIDDEN', 'The workspace API accepts same-origin loopback requests only.');
  }
  if (req.method === 'POST' && req.headers['content-type']?.split(';')[0]?.trim() !== 'application/json') {
    throw new AgentOClientError('INVALID_INPUT', 'Send an application/json request.');
  }
}

async function body(req: IncomingMessage): Promise<Record<string, unknown>> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req.iterator({ destroyOnReturn: false })) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > maxBody) {
      req.resume();
      throw new AgentOClientError('INVALID_INPUT', 'The request is too large.');
    }
    chunks.push(bytes);
  }
  try {
    const value: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (value && typeof value === 'object' && !Array.isArray(value)) return value as Record<string, unknown>;
  } catch { /* Do not return request content in errors. */ }
  throw new AgentOClientError('INVALID_INPUT', 'Send a valid JSON object.');
}

export function createLocalApi(options: { root: string; file: string; execution: ExecutionServices }) {
  let service: Promise<LocalService> | undefined;
  let release: (() => Promise<void>) | undefined;
  const getService = () => service ??= (async () => {
    release = await claimWorkspace(options.file);
    try { return new LocalService(await Workspace.open(options.file), options.execution); }
    catch (error) { await release(); release = undefined; throw error; }
  })().catch(error => { service = undefined; throw error; });
  const middleware = async (req: IncomingMessage, res: ServerResponse, next: () => void) => {
    if (!req.url?.startsWith('/api/')) { next(); return; }
    try {
      checkRequest(req);
      const pathname = new URL(req.url, 'http://localhost').pathname;
      let data: unknown;
      let status = 200;
      if (pathname === '/api/demo-apps' && req.method === 'GET') {
        const directory = join(options.root, 'demo-apps');
        const entries = await readdir(directory, { withFileTypes: true });
        data = entries.filter(item => item.isDirectory() && !item.name.startsWith('.')).map(item => ({
          id: item.name, name: item.name, path: join(directory, item.name), discoveryFile: join(directory, item.name, 'discovery.json'),
        }));
      } else if (pathname === '/api/discover' && req.method === 'POST') {
        const input = await body(req);
        if (typeof input.repositoryPath !== 'string' || !input.repositoryPath.trim()
          || input.repositoryPath.length > 4096 || /[\u0000-\u001f\u007f]/u.test(input.repositoryPath)) {
          throw new AgentOClientError('INVALID_INPUT', 'Enter a valid repository path.');
        }
        data = await options.execution.discover(input.repositoryPath.trim());
      } else {
        const match = /^\/api\/projects(?:\/([^/]+)(?:\/(discovery|scan|findings|workflows)(?:\/([^/]+))?)?)?$/u.exec(pathname);
        if (!match) { respond(res, 404, { ok: false, code: 'INVALID_INPUT', error: 'Unknown workspace API route.' }); return; }
        const [, encodedId, resource, encodedFinding] = match;
        const id = encodedId ? decodeURIComponent(encodedId) : undefined;
        const client = await getService();
        if (!id && req.method === 'GET') data = await client.listProjects();
        else if (!id && req.method === 'POST') {
          const input = await body(req);
          data = await client.createProject(input.input as ProjectInput, input.discovery as DiscoveryResult | undefined);
          status = 201;
        } else if (id && !resource && req.method === 'GET') data = await client.getProject(id);
        else if (id && resource === 'discovery' && !encodedFinding && req.method === 'GET') data = await client.getDiscovery(id);
        else if (id && resource === 'discovery' && !encodedFinding && req.method === 'POST') data = await client.importDiscovery(id, (await body(req)).discovery as DiscoveryResult);
        else if (id && resource === 'scan' && !encodedFinding && req.method === 'GET') data = await client.getScan(id);
        else if (id && resource === 'scan' && !encodedFinding && req.method === 'POST') {
          await body(req);
          data = await client.startScan(id);
          status = 202;
        } else if (id && resource === 'findings' && req.method === 'GET') {
          data = encodedFinding ? await client.getFinding(id, decodeURIComponent(encodedFinding)) : await client.getFindings(id);
        } else if (id && resource === 'workflows' && req.method === 'GET') {
          data = encodedFinding ? await client.getWorkflow(id, decodeURIComponent(encodedFinding)) : await client.getWorkflows(id);
        } else if (id && resource === 'workflows' && !encodedFinding && req.method === 'POST') {
          const input = await body(req);
          if (!client.runWorkflow) throw new AgentOClientError('CLIENT_UNAVAILABLE', 'Workflow execution is not supported by this client.');
          data = await client.runWorkflow(id, input as any);
          status = 200;
        } else { respond(res, 405, { ok: false, code: 'INVALID_INPUT', error: 'Unsupported workspace API method.' }); return; }
      }
      respond(res, status, { ok: true, data });
    } catch (error) {
      const known = error instanceof AgentOClientError;
      const code = known ? error.code : 'CLIENT_UNAVAILABLE';
      const status = code === 'REQUEST_FORBIDDEN' ? 403 : code === 'SCAN_IN_PROGRESS' ? 409
        : ['PROJECT_NOT_FOUND', 'FINDING_NOT_FOUND', 'SCAN_UNAVAILABLE', 'DISCOVERY_UNAVAILABLE', 'WORKFLOW_NOT_FOUND'].includes(code) ? 404
        : ['INVALID_INPUT', 'INVALID_DISCOVERY', 'WORKFLOW_FAILED'].includes(code) ? 400 : 503;
      respond(res, status, { ok: false, code, error: known ? error.message : 'The local workspace service could not complete the request. Check package builds, workspace access, and local tool installation.' });
    }

  };
  return Object.assign(middleware, { async close() {
    try { if (service) await (await service).idle(); }
    finally { await release?.(); }
  } });
}

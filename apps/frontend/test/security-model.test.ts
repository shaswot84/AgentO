import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Evidence, FrameworkAnalysis, Project } from '@agento/core';
import type { BrowserWorkflowResult } from '../src/client/types.ts';
import type { ExecutionServices } from '../server/execution.ts';
import { Workspace } from '../server/workspace.ts';
import { LocalService } from '../server/service.ts';
import { createFixtureClient } from '../src/client/fixture-client.ts';
import { demoDiscovery } from '../src/data/demo-discovery.ts';

const input = { name: 'Model project', repositoryPath: '/work/model', baseUrl: 'http://localhost:3000', allowedOrigins: ['http://localhost:3000'] };
const capturedAt = '2026-10-18T00:00:00.000Z';
const folders: string[] = [];
afterEach(async () => { await Promise.all(folders.splice(0).map(folder => rm(folder, { recursive: true, force: true }))); });
const proof = (project: Project, id: string, endpointId: string, kind: Evidence['kind'], facts: Evidence['facts']): Evidence => ({
  id, projectId: project.id, endpointId, kind, facts, producerId: 'test-provider', capturedAt, summary: 'Normalized public observation.',
});
function framework(project: Project): FrameworkAnalysis {
  return { components: [{ id: 'api', projectId: project.id, name: 'API service', kind: 'service' }], resources: [], signals: [],
    endpoints: [{ id: 'source-order', componentId: 'api', method: 'GET', path: '/api/orders/:id',
      authentication: 'required', roles: ['customer'], parameters: [{ name: 'id', location: 'path', required: true }],
      handler: { file: 'src/order.ts', startLine: 5 }, evidenceIds: ['source-route', 'source-db'] },
    { id: 'source-health', componentId: 'api', method: 'GET', path: '/health', authentication: 'optional', roles: [], parameters: [], evidenceIds: [] }],
    evidence: [proof(project, 'source-route', 'source-order', 'source-location', { observation: 'route' }),
      proof(project, 'source-db', 'source-order', 'source-location', { observation: 'database-operation', operation: 'SELECT', tables: ['orders'], runtimeVerified: false })],
  };
}
function workflow(project: Project): BrowserWorkflowResult {
  return { id: 'workflow-one', projectId: project.id, sourceType: 'execution-api', executedAt: capturedAt,
    targetUrl: project.baseUrl, goal: 'Observe an order', identityId: 'alice', personaLabel: 'Alice', outcome: 'COMPLETED', actionsCount: 2,
    identities: [{ id: 'alice', label: 'Alice', roles: ['customer'], authentication: 'session-cookie' }],
    endpoints: [{ id: 'browser-order', componentId: 'browser-api', method: 'GET', path: '/api/orders/102',
      authentication: 'unknown', roles: [], parameters: [], evidenceIds: ['browser-response', 'browser-owner'] }],
    resources: [{ id: 'order-102', projectId: project.id, type: 'Order', externalKey: '102', ownerIdentityId: 'alice', endpointId: 'browser-order', evidenceIds: ['browser-owner'] }],
    evidence: [proof(project, 'browser-response', 'browser-order', 'http-response', { method: 'GET', url: 'http://localhost:3000/api/orders/102', status: 200 }),
      { ...proof(project, 'browser-owner', 'browser-order', 'resource-ownership', { resourceId: 'order-102', ownerIdentityId: 'alice' }), identityId: 'alice' }],
    network: [], diagnostics: [],
  };
}
const execution: ExecutionServices = {
  discover: async repositoryPath => ({ ...demoDiscovery, repositoryPath }),
  analyze: async project => ({ framework: framework(project), analysis: { status: 'completed', diagnostics: [], signals: [], evidence: [] } }),
  observeWorkflow: async project => workflow(project),
};
async function setup(services: ExecutionServices = execution) {
  const folder = await mkdtemp(join(tmpdir(), 'agento-model-ui-')); folders.push(folder);
  const file = join(folder, 'workspace.json'), workspace = await Workspace.open(file);
  const service = new LocalService(workspace, services), project = await service.createProject(input);
  return { file, workspace, service, project };
}

describe('retained application model integration', () => {
  it('reads an empty model without executing source scans, browser sessions or tools', async () => {
    const discover = vi.fn(execution.discover), analyze = vi.fn(execution.analyze), observeWorkflow = vi.fn(execution.observeWorkflow!);
    const { service, project } = await setup({ discover, analyze, observeWorkflow });
    const result = await service.getSecurityModel(project.id);
    expect(result).toMatchObject({ state: 'empty', projectId: project.id, sourceType: 'execution-api', updatedAt: null, inputs: [] });
    expect(result.model.endpoints).toEqual([]);
    expect(result.diagnostics.map(item => item.code)).toEqual(['source-model-missing', 'browser-model-missing']);
    expect(discover).not.toHaveBeenCalled(); expect(analyze).not.toHaveBeenCalled(); expect(observeWorkflow).not.toHaveBeenCalled();
    await expect(service.getSecurityModel('unknown')).rejects.toMatchObject({ code: 'PROJECT_NOT_FOUND' });
  });

  it('retains full source routes even with zero findings, and merges explicitly evidenced runtime ownership after restart', async () => {
    const { service, project, file, workspace } = await setup();
    await service.startScan(project.id); await service.idle();
    const source = await service.getSecurityModel(project.id);
    expect(source.state).toBe('partial');
    expect(source.model.endpoints).toHaveLength(2);
    expect(await service.getFindings(project.id)).toEqual([]);
    expect(workspace.read()[0]!.modelSource!.contributions[0]!.endpoints).toHaveLength(2);
    await service.runWorkflow(project.id, { goal: 'Observe an order' });
    const result = await service.getSecurityModel(project.id);
    expect(result.state).toBe('ready');
    const order = result.model.endpoints.find(item => item.path === '/api/orders/:id')!;
    expect(order.aliases).toEqual(['browser-order', 'source-order']);
    expect(result.model.endpoints).toHaveLength(2);
    expect(result.model.databaseOperations[0]!.endpointIds).toEqual([order.id]);
    expect(result.model.observedOwnership[0]!.details.ownerIdentityId).toBe('alice');
    expect(result.model.evidence.find(item => item.id === 'browser-owner')!.endpointId).toBe('browser-order');
    expect(result.inputs).toHaveLength(2);
    expect(result.inputs.every(item => item.included)).toBe(true);
    const restarted = new LocalService(await Workspace.open(file), execution);
    expect(await restarted.getSecurityModel(project.id)).toEqual(result);
    expect(JSON.parse(await readFile(file, 'utf8')).projects[0].modelSource.version).toBe(1);
  });

  it('keeps a prior source snapshot explicitly stale during and after a failed replacement scan', async () => {
    let fail = false;
    const { service, project } = await setup({ ...execution, analyze: async project => {
      if (fail) throw new Error('PRIVATE_PROVIDER_SECRET');
      return execution.analyze(project);
    } });
    await service.startScan(project.id); await service.idle();
    const original = await service.getSecurityModel(project.id);
    fail = true;
    await service.startScan(project.id);
    expect((await service.getSecurityModel(project.id)).state).toBe('stale');
    await service.idle();
    const failed = await service.getSecurityModel(project.id);
    expect(failed.state).toBe('stale');
    expect(failed.model).toEqual(original.model);
    expect(failed.diagnostics.some(item => item.code === 'source-model-stale')).toBe(true);
    expect(JSON.stringify(failed)).not.toContain('PRIVATE_PROVIDER_SECRET');
  });

  it('retains partial framework context with coverage diagnostics when static analysis is incomplete', async () => {
    const { service, project } = await setup({ ...execution, analyze: async project => ({ framework: framework(project),
      analysis: { status: 'partial', diagnostics: [{ code: 'limit-reached', message: 'Source limit reached.' }], signals: [], evidence: [] } }) });
    await service.startScan(project.id); await service.idle();
    const result = await service.getSecurityModel(project.id);
    expect(result.model.endpoints).toHaveLength(2);
    expect(result.state).toBe('partial');
    expect(result.inputs[0]).toMatchObject({ outcome: 'partial', included: true });
    expect(result.diagnostics).toContainEqual({ code: 'limit-reached', message: 'Source limit reached.' });
  });

  it('rejects incompatible workflow target data without borrowing or replacing source observations', async () => {
    const { service, project } = await setup({ ...execution, observeWorkflow: async project => ({ ...workflow(project), targetUrl: 'https://other.test' }) });
    await service.startScan(project.id); await service.idle();
    await service.runWorkflow(project.id, { goal: 'Observe' });
    const result = await service.getSecurityModel(project.id);
    expect(result.model.endpoints).toHaveLength(2);
    expect(result.inputs.find(item => item.source === 'browser')!.included).toBe(false);
    expect(result.diagnostics.some(item => item.code === 'workflow-model-invalid')).toBe(true);
    expect((await service.getWorkflows(project.id))[0]!.targetUrl).toBe('https://other.test');
  });

  it('does not reinterpret source routes after a project binding changes', async () => {
    const { service, project, workspace } = await setup();
    await service.startScan(project.id); await service.idle();
    await workspace.update(records => { records[0]!.project = { ...records[0]!.project, baseUrl: 'http://localhost:4000', allowedOrigins: ['http://localhost:4000'] }; });
    const result = await service.getSecurityModel(project.id);
    expect(result.model.endpoints).toEqual([]);
    expect(result.inputs[0]!.included).toBe(false);
    expect(result.diagnostics.some(item => item.code === 'source-model-invalid')).toBe(true);
  });

  it('keeps older workspaces readable while explaining missing source context', async () => {
    const { service, file, project } = await setup();
    await service.startScan(project.id); await service.idle();
    const stored = JSON.parse(await readFile(file, 'utf8'));
    delete stored.projects[0].modelSource;
    await writeFile(file, JSON.stringify(stored));
    const reopened = new LocalService(await Workspace.open(file), execution);
    const result = await reopened.getSecurityModel(project.id);
    expect(result.state).toBe('empty');
    expect(result.diagnostics[0]!.message).toContain('new static scan');
    expect(await reopened.getScan(project.id)).toMatchObject({ state: 'complete' });
  });

  it('uses explicit synthetic demo models and never copies them into a new project', async () => {
    const client = createFixtureClient({ delayMs: 0 });
    const demo = await client.getSecurityModel('demo-shop');
    expect(demo.sourceType).toBe('demo-fixture');
    expect(demo.model.endpoints.length).toBeGreaterThan(0);
    expect(demo.model.evidence.every(item => item.facts.fixture === true)).toBe(true);
    const project = await client.createProject(input);
    expect((await client.getSecurityModel(project.id)).model.endpoints).toEqual([]);
    (demo.model.evidence as Evidence[]).pop();
    expect((await client.getSecurityModel('demo-shop')).model.evidence.length).toBeGreaterThan(demo.model.evidence.length);
  });
});

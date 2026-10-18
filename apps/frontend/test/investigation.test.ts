import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Project } from '@agento/core';
import type { ExecutionServices } from '../server/execution.ts';
import { generateInvestigation } from '../server/investigation.ts';
import * as planning from '../server/investigation.ts';
import { LocalService } from '../server/service.ts';
import { Workspace } from '../server/workspace.ts';
import { demoDiscovery } from '../src/data/demo-discovery.ts';
import { demoSecurityModel } from '../src/data/model-fixture.ts';
import { createFixtureClient } from '../src/client/fixture-client.ts';

const folders: string[] = [];
afterEach(async () => { vi.restoreAllMocks(); await Promise.all(folders.splice(0).map(folder => rm(folder, { recursive: true, force: true }))); });
const input = { name: 'Investigation project', repositoryPath: '/work/investigation', baseUrl: 'http://localhost:3000', allowedOrigins: ['http://localhost:3000'] };
const capturedAt = '2026-10-18T00:00:00.000Z';
const execution: ExecutionServices = {
  discover: vi.fn(async repositoryPath => ({ ...demoDiscovery, repositoryPath })),
  analyze: vi.fn(async (project: Project) => ({
    framework: { components: [{ id: 'api', projectId: project.id, name: 'API', kind: 'service' as const }],
      endpoints: [{ id: 'search', componentId: 'api', path: '/search', method: 'GET' as const,
        authentication: 'optional' as const, roles: [], parameters: [{ name: 'q', location: 'query' as const, required: true }], evidenceIds: ['source'] }],
      resources: [], signals: [], evidence: [{ id: 'source', projectId: project.id, endpointId: 'search', kind: 'source-location' as const,
        producerId: 'test-framework', capturedAt, summary: 'A source route was observed.', facts: { observation: 'route', privateSource: 'PRIVATE_SOURCE_VALUE' } }] },
    analysis: { status: 'completed' as const, diagnostics: [],
      signals: [{ id: 'xss-candidate', projectId: project.id, endpointId: 'search', producerId: 'test-static', cweIds: ['CWE-79' as const], summary: 'Input may reach an HTML sink.', evidenceIds: ['static'] }],
      evidence: [{ id: 'static', projectId: project.id, endpointId: 'search', kind: 'static-analysis' as const, producerId: 'test-static', capturedAt,
        summary: 'A static candidate requires investigation.', facts: { observation: 'static-candidate', privateSource: 'PRIVATE_SOURCE_VALUE' } }] },
  })),
  observeWorkflow: async project => ({ id: 'new-browser-observation', projectId: project.id, sourceType: 'execution-api',
    executedAt: capturedAt, targetUrl: project.baseUrl, goal: 'Observe a page', identityId: 'alice', outcome: 'COMPLETED',
    actionsCount: 1, endpoints: [], network: [], evidence: [], diagnostics: [] }),
};
async function setup(services = execution) {
  const folder = await mkdtemp(join(tmpdir(), 'agento-investigation-')); folders.push(folder);
  const file = join(folder, 'workspace.json'), workspace = await Workspace.open(file);
  const service = new LocalService(workspace, services), project = await service.createProject(input);
  return { file, workspace, service, project };
}

describe('saved investigation projections', () => {
  it('projects real engine output without raw plan scopes, input bindings, resource keys or evidence facts', async () => {
    const source = structuredClone(demoSecurityModel);
    const raw = JSON.stringify(source).replaceAll('"externalKey":"102"', '"externalKey":"PRIVATE_RESOURCE_KEY"');
    expect(raw).toContain('PRIVATE_RESOURCE_KEY');
    const { snapshot } = await generateInvestigation(JSON.parse(raw));
    expect(snapshot.hypotheses).toHaveLength(1);
    expect(snapshot.plans).toHaveLength(1);
    expect(snapshot.coverage).toHaveLength(7);
    expect(snapshot.plans[0]).toMatchObject({ readiness: 'BLOCKED', execution: 'not-run',
      prerequisites: expect.arrayContaining([{ code: 'authorization-policy-required' }, { code: 'input-required', parameter: { name: 'id', location: 'path' } }]) });
    expect(snapshot.plans[0]!.steps.length).toBeGreaterThan(1);
    expect(snapshot.modelReview).toBe('disabled');
    expect(JSON.stringify(snapshot)).not.toMatch(/PRIVATE_RESOURCE_KEY|"scope"|"parameters"|"facts"|"valueRef"|"targetUrl"|"sessionRef"/);
  });

  it('starts empty and never borrows demo questions or invokes a source tool on read', async () => {
    const { service, project } = await setup();
    const before = vi.mocked(execution.discover).mock.calls.length;
    const empty = await service.getInvestigation(project.id);
    expect(empty).toMatchObject({ projectId: project.id, sourceType: 'execution-api', state: 'empty', generatedAt: null, hypotheses: [], plans: [] });
    expect(empty.coverage).toHaveLength(7);
    expect(vi.mocked(execution.discover).mock.calls.length).toBe(before);
    await expect(service.getInvestigation('missing')).rejects.toMatchObject({ code: 'PROJECT_NOT_FOUND' });
  });

  it('runs the real engines after source analysis, retains blocked drafts and restores them after restart', async () => {
    const { service, project, file } = await setup();
    await service.startScan(project.id); await service.idle();
    const scan = await service.getScan(project.id), result = await service.getInvestigation(project.id);
    expect(scan.state).toBe('complete');
    expect(scan.stages.filter(stage => ['hypotheses', 'planning'].includes(stage.id)).map(stage => stage.status)).toEqual(['complete', 'complete']);
    expect(scan.stages.find(stage => stage.id === 'runtime')?.status).toBe('unavailable');
    expect(result.hypotheses.map(item => item.cweId)).toEqual(['CWE-79']);
    expect(result.plans[0]).toMatchObject({ readiness: 'BLOCKED', execution: 'not-run' });
    expect(result.plans[0]!.prerequisites).toContainEqual({ code: 'input-required', parameter: { name: 'q', location: 'query' } });
    expect(JSON.stringify(result)).not.toContain('PRIVATE_SOURCE_VALUE');
    const restarted = new LocalService(await Workspace.open(file), execution);
    expect(await restarted.getInvestigation(project.id)).toEqual(result);
  });

  it('marks old plans stale when browser observations change and regenerates without rerunning target tools', async () => {
    const { service, project } = await setup();
    await service.startScan(project.id); await service.idle();
    const saved = await service.getInvestigation(project.id);
    await service.runWorkflow(project.id, { goal: 'Observe a page' });
    const stale = await service.getInvestigation(project.id);
    expect(stale.state).toBe('stale');
    expect(stale.hypotheses).toEqual(saved.hypotheses);
    expect(stale.diagnostics).toContain('model-changed');
    const scans = vi.mocked(execution.analyze).mock.calls.length;
    const fresh = await service.refreshInvestigation(project.id);
    expect(fresh.state).not.toBe('stale');
    expect(vi.mocked(execution.analyze).mock.calls.length).toBe(scans);
    expect(await service.getInvestigation(project.id)).toEqual(fresh);
  });

  it('keeps static scan results when the optional planning packages fail', async () => {
    const failed = vi.spyOn(planning, 'generateInvestigation').mockRejectedValue(new Error('PRIVATE_PROVIDER_FAILURE'));
    const { service, project } = await setup();
    await service.startScan(project.id); await service.idle();
    const scan = await service.getScan(project.id);
    expect(scan.state).toBe('complete');
    expect(await service.getFindings(project.id)).toHaveLength(1);
    expect(scan.stages.find(stage => stage.id === 'planning')?.status).toBe('unavailable');
    expect(JSON.stringify(scan)).not.toContain('PRIVATE_PROVIDER_FAILURE');
    failed.mockRestore();
  });

  it('does not overwrite saved plans when model observations change during generation', async () => {
    const { service, project, workspace } = await setup();
    await service.startScan(project.id); await service.idle();
    const previous = await service.getInvestigation(project.id);
    let release!: () => void, started!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const reached = new Promise<void>(resolve => { started = resolve; });
    const original = planning.generateInvestigation;
    vi.spyOn(planning, 'generateInvestigation').mockImplementation(async source => { started(); await gate; return original(source); });
    const pending = service.refreshInvestigation(project.id);
    await reached;
    await service.runWorkflow(project.id, { goal: 'Observe a page' });
    release();
    await expect(pending).rejects.toMatchObject({ code: 'CLIENT_UNAVAILABLE' });
    expect(workspace.read()[0]!.investigation!.snapshot).toEqual(previous);
    expect((await service.getInvestigation(project.id)).state).toBe('stale');
  });

  it('withholds manual regeneration while a source scan is active', async () => {
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const { service, project } = await setup({ ...execution, discover: async path => { await gate; return execution.discover(path); } });
    await service.startScan(project.id);
    await expect(service.refreshInvestigation(project.id)).rejects.toMatchObject({ code: 'SCAN_IN_PROGRESS' });
    release(); await service.idle();
  });

  it('keeps fixture provenance and refuses generation in an unconnected in-memory project', async () => {
    const client = createFixtureClient({ delayMs: 0 });
    const demo = await client.getInvestigation('demo-shop');
    expect(demo.sourceType).toBe('demo-fixture');
    expect(demo.hypotheses).toHaveLength(1);
    const project = await client.createProject(input);
    expect(await client.getInvestigation(project.id)).toMatchObject({ state: 'empty', hypotheses: [], plans: [] });
    await expect(client.refreshInvestigation(project.id)).rejects.toMatchObject({ code: 'CLIENT_UNAVAILABLE' });
  });
});

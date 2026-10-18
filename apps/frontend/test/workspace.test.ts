import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { FrameworkAnalysis, Project } from '@agento/core';
import type { SemgrepAnalysis } from '../../../plugins/tools/semgrep/src/types';
import { Workspace } from '../server/workspace';
import { LocalService } from '../server/service';
import type { ExecutionServices } from '../server/execution';
import { demoDiscovery } from '../src/data/demo-discovery';
import type { ProjectInput } from '../src/client';
import { claimWorkspace } from '../server/lock';

const folders: string[] = [];
afterEach(async () => { await Promise.all(folders.splice(0).map(folder => rm(folder, { recursive: true, force: true }))); });
const input: ProjectInput = { name: 'Real project', repositoryPath: '/work/real', baseUrl: 'http://localhost:3000', allowedOrigins: ['http://localhost:3000'] };
const discovery = (path = input.repositoryPath) => ({ ...demoDiscovery, repositoryPath: path });
function analysis(project: Project, status: SemgrepAnalysis['status'] = 'completed'): SemgrepAnalysis {
  return { status, diagnostics: status === 'completed' ? [] : [{ code: 'tool-failed', message: 'Static analysis incomplete.' }],
    signals: [{ id: 'signal-1', projectId: project.id, cweIds: ['CWE-89'], producerId: 'semgrep-adapter', summary: 'Static SQL candidate',
      evidenceIds: ['evidence-1'], endpointId: 'endpoint-1', source: { file: 'src/search.ts', startLine: 8 } }],
    evidence: [{ id: 'evidence-1', projectId: project.id, kind: 'static-analysis', producerId: 'semgrep-adapter', capturedAt: '2026-10-18T00:00:00Z',
      summary: 'Recorded source observation', facts: { runtimeVerified: false }, source: { file: 'src/search.ts', startLine: 8 } }],
  };
}
const execution: ExecutionServices = { discover: async path => discovery(path), analyze: async project => ({ analysis: analysis(project) }) };
async function setup(services: ExecutionServices = execution) {
  const folder = await mkdtemp(join(tmpdir(), 'agento-workspace-test-'));
  folders.push(folder);
  const file = join(folder, 'private', 'workspace.json');
  const workspace = await Workspace.open(file);
  return { file, workspace, service: new LocalService(workspace, services) };
}

describe('durable local projects', () => {
  it('allows only one local service to own a workspace file', async () => {
    const { file } = await setup();
    const release = await claimWorkspace(file);
    await expect(claimWorkspace(file)).rejects.toThrow('Another local service');
    await release();
    const next = await claimWorkspace(file);
    await next();
  });
  it('recovers a stale process lock before reopening a workspace', async () => {
    const { file } = await setup();
    // Create the parent through the normal acquisition path, then simulate a dead owner.
    const first = await claimWorkspace(file);
    await first();
    await writeFile(`${file}.lock`, JSON.stringify({ pid: 123, token: 'dead-owner' }));
    const kill = vi.spyOn(process, 'kill').mockImplementationOnce(() => { throw Object.assign(new Error('No process'), { code: 'ESRCH' }); });
    try { const release = await claimWorkspace(file); await release(); }
    finally { kill.mockRestore(); }
  });
  it('persists projects and imports across service restart with private file modes', async () => {
    const { service, file } = await setup();
    const project = await service.createProject(input);
    await service.importDiscovery(project.id, discovery());
    const restarted = new LocalService(await Workspace.open(file), execution);
    expect(await restarted.getProject(project.id)).toMatchObject({ name: input.name, dataSource: 'saved-discovery' });
    expect(await restarted.getDiscovery(project.id)).toEqual(discovery());
    expect((await stat(file)).mode & 0o777).toBe(0o600);
    expect((await stat(join(file, '..'))).mode & 0o777).toBe(0o700);
  });
  it('serializes concurrent writes and returns isolated data', async () => {
    const { service, file } = await setup();
    const projects = await Promise.all(Array.from({ length: 8 }, (_, index) => service.createProject({ ...input, name: `Project ${index}` })));
    expect(new Set(projects.map(project => project.id)).size).toBe(8);
    const result = await service.listProjects();
    (result[0]!.languages as string[]).push('mutated');
    expect((await service.listProjects())[0]!.languages).toEqual([]);
    expect((await Workspace.open(file)).read()).toHaveLength(8);
  });
  it.each([null, {}, { ...input, name: 12 }, { ...input, allowedOrigins: ['*'] }, { ...input, allowedOrigins: [12] }])('rejects invalid input at the service boundary %#', async value => {
    const { service } = await setup();
    await expect(service.createProject(value as ProjectInput)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(await service.listProjects()).toHaveLength(1);
  });
  it('leaves discovery intact on invalid/mismatched import', async () => {
    const { service } = await setup();
    const project = await service.createProject(input, discovery());
    await expect(service.importDiscovery(project.id, discovery('/wrong'))).rejects.toMatchObject({ code: 'INVALID_DISCOVERY' });
    expect(await service.getDiscovery(project.id)).toEqual(discovery());
  });
  it('does not commit in-memory state when the disk write fails', async () => {
    const { file, service } = await setup();
    await writeFile(join(file, '..'), 'occupied');
    await expect(service.createProject(input)).rejects.toThrow();
    expect(await service.listProjects()).toHaveLength(1);
  });
  it('preserves corrupt storage for recovery instead of resetting it', async () => {
    const { file, service } = await setup();
    await service.createProject(input);
    await writeFile(file, '{broken');
    await expect(Workspace.open(file)).rejects.toThrow();
    expect(await readFile(file, 'utf8')).toBe('{broken');
  });
  it('deletes projects from workspace storage and protects read-only or scanning targets', async () => {
    const { service, file } = await setup();
    const project1 = await service.createProject(input);
    const project2 = await service.createProject({ ...input, name: 'Project Two' });
    expect(await service.listProjects()).toHaveLength(3);

    await service.deleteProject(project1.id);
    const remaining = await service.listProjects();
    expect(remaining).toHaveLength(2);
    expect(remaining.some(p => p.id === project1.id)).toBe(false);
    expect(remaining.some(p => p.id === project2.id)).toBe(true);

    const restarted = new LocalService(await Workspace.open(file), execution);
    expect((await restarted.listProjects()).some(p => p.id === project1.id)).toBe(false);

    await service.deleteProject('demo-shop');
    const afterDemoDelete = await service.listProjects();
    expect(afterDemoDelete.some(p => p.id === 'demo-shop')).toBe(false);
    expect(afterDemoDelete).toHaveLength(1);

    const restartedAfterDemoDelete = new LocalService(await Workspace.open(file), execution);
    expect((await restartedAfterDemoDelete.listProjects()).some(p => p.id === 'demo-shop')).toBe(false);

    await expect(service.deleteProject('demo-shop')).rejects.toMatchObject({ code: 'PROJECT_NOT_FOUND' });
    await expect(service.deleteProject('unknown-id')).rejects.toMatchObject({ code: 'PROJECT_NOT_FOUND' });
  });
});

describe('local scan lifecycle and provenance', () => {
  it('reports pending/running, rejects conflicting work, and persists observed findings', async () => {
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const { service, file } = await setup({ ...execution, analyze: async project => {
      entered(); await gate;
      const framework: FrameworkAnalysis = { components: [], resources: [], signals: [], evidence: [], endpoints: [{
        id: 'endpoint-1', componentId: 'app', path: '/api/search', method: 'GET', authentication: 'unknown', roles: [], parameters: [], evidenceIds: [],
      }] };
      return { analysis: analysis(project), framework };
    } });
    const project = await service.createProject(input);
    const queued = await service.startScan(project.id);
    expect(queued).toMatchObject({ source: 'execution-api', state: 'pending' });
    await started;
    expect(await service.getScan(project.id)).toMatchObject({ state: 'running', stages: expect.arrayContaining([expect.objectContaining({ id: 'static', status: 'running' })]) });
    await expect(service.startScan(project.id)).rejects.toMatchObject({ code: 'SCAN_IN_PROGRESS' });
    const second = await service.createProject({ ...input, name: 'Second' });
    await expect(service.startScan(second.id)).rejects.toMatchObject({ code: 'SCAN_IN_PROGRESS' });
    await expect(service.importDiscovery(project.id, discovery())).rejects.toMatchObject({ code: 'SCAN_IN_PROGRESS' });
    await expect(service.deleteProject(project.id)).rejects.toMatchObject({ code: 'SCAN_IN_PROGRESS' });
    release(); await service.idle();
    const scan = await service.getScan(project.id);
    expect(scan.state).toBe('complete');
    expect(scan.stages.find(stage => stage.id === 'runtime')?.status).toBe('unavailable');
    const finding = (await service.getFindings(project.id))[0]!;
    expect(finding).toMatchObject({ sourceType: 'execution-api', status: 'HYPOTHESIS', testPlanIds: [], endpoint: { path: '/api/search' } });
    expect(finding.remediation.explanation).toContain('parameterized queries');
    expect(finding.evidenceIds).toEqual(finding.remediation.evidenceIds);
    expect(finding.evidence[0]?.facts.runtimeVerified).toBe(false);
    const restarted = new LocalService(await Workspace.open(file), execution);
    expect(await restarted.getFinding(project.id, finding.id)).toEqual(finding);
    expect(await restarted.getScan(project.id)).toEqual(scan);
    expect((await restarted.listProjects()).find(item => item.id === project.id)?.scanState).toBe('complete');
  });
  it.each(['partial', 'failed', 'skipped'] as const)('does not describe %s analysis as a complete scan', async status => {
    const { service } = await setup({ ...execution, analyze: async project => ({ analysis: { ...analysis(project, status), signals: status === 'partial' ? analysis(project).signals : [] } }) });
    const project = await service.createProject(input);
    await service.startScan(project.id); await service.idle();
    const scan = await service.getScan(project.id);
    expect(scan.state).toBe('failed');
    expect(scan.diagnostics?.[0]?.code).toBe('tool-failed');
    expect(scan.summary).toContain(status);
    expect(await service.getFindings(project.id)).toHaveLength(status === 'partial' ? 1 : 0);
  });
  it('clears previous findings before a new run and never borrows fixtures', async () => {
    let fail = false;
    const { service } = await setup({ ...execution, analyze: async project => {
      if (fail) throw new Error('PRIVATE_PROVIDER_SECRET');
      return { analysis: analysis(project) };
    } });
    const project = await service.createProject(input);
    expect(await service.getFindings(project.id)).toEqual([]);
    await expect(service.getScan(project.id)).rejects.toMatchObject({ code: 'SCAN_UNAVAILABLE' });
    await service.startScan(project.id); await service.idle();
    fail = true;
    await service.startScan(project.id);
    expect(await service.getFindings(project.id)).toEqual([]);
    await service.idle();
    const scan = await service.getScan(project.id);
    expect(scan.state).toBe('failed');
    expect(JSON.stringify(scan)).not.toContain('PRIVATE_PROVIDER_SECRET');
    await expect(service.getFinding('missing-project', 'missing')).rejects.toMatchObject({ code: 'PROJECT_NOT_FOUND' });
  });
  it('recovers interrupted scans as failed on restart', async () => {
    const { service, workspace, file } = await setup();
    const project = await service.createProject(input);
    await workspace.update(records => { records[0]!.scan = { id: 'interrupted', projectId: project.id, source: 'execution-api', state: 'running', summary: 'Running', stages: [{ id: 'static', label: 'Static', status: 'running', details: 'Running' }] }; });
    const restarted = new LocalService(await Workspace.open(file), execution);
    expect(await restarted.getScan(project.id)).toMatchObject({ state: 'failed', summary: expect.stringContaining('stopped'), stages: [expect.objectContaining({ status: 'failed' })] });
  });
  it('keeps demo fixtures read-only and synthetic', async () => {
    const { service } = await setup();
    expect(await service.getScan('demo-shop')).toMatchObject({ source: 'demo-fixture' });
    expect((await service.getFindings('demo-shop')).every(item => item.sourceType === 'demo-fixture')).toBe(true);
    await expect(service.startScan('demo-shop')).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(service.importDiscovery('demo-shop', discovery())).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
  it('persists workflows with project records and enforces fixture immutability', async () => {
    const { service, file } = await setup({
      ...execution,
      observeWorkflow: async (project, input) => ({
        id: 'wf-local-1',
        projectId: project.id,
        goal: input.goal,
        identityId: input.identityId || 'alice',
        targetUrl: project.baseUrl,
        outcome: 'COMPLETED',
        actionsCount: 2,
        endpoints: [],
        network: [],
        diagnostics: [],
        evidence: [],
        sourceType: 'execution-api',
        executedAt: new Date().toISOString(),
      }),
    });
    const project = await service.createProject(input);
    const ran = await service.runWorkflow(project.id, { goal: 'Test persistent workflow' });
    expect(ran.id).toBe('wf-local-1');

    const restarted = new LocalService(await Workspace.open(file), execution);
    const workflows = await restarted.getWorkflows(project.id);
    expect(workflows).toHaveLength(1);
    expect(workflows[0]!.goal).toBe('Test persistent workflow');

    await expect(service.runWorkflow('demo-shop', { goal: 'test' })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});

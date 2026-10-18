import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { localExecution } from '../server/execution';
import { LocalService } from '../server/service';
import { Workspace } from '../server/workspace';

describe.skipIf(process.env.AGENTO_FRONTEND_INTEGRATION !== '1')('installed local providers', () => {
  it('reports a real unsupported stack as skipped analysis, without fixture findings', async () => {
    const folder = await mkdtemp(join(tmpdir(), 'agento-unsupported-workspace-'));
    try {
      const root = fileURLToPath(new URL('../../..', import.meta.url));
      const service = new LocalService(await Workspace.open(join(folder, 'workspace.json')), localExecution(root));
      const project = await service.createProject({ name: 'Unsupported stack', repositoryPath: join(root, 'demo-apps/demo-app-02'),
        baseUrl: 'http://localhost:3000', allowedOrigins: ['http://localhost:3000'] });
      await service.startScan(project.id); await service.idle();
      expect(await service.getScan(project.id)).toMatchObject({ state: 'failed', diagnostics: expect.arrayContaining([expect.objectContaining({ code: 'mode-not-code-aware' })]) });
      expect(await service.getFindings(project.id)).toEqual([]);
    } finally { await rm(folder, { recursive: true, force: true }); }
  });
  it('discovers and scans the real demo, saves XSS/SQL candidates, and restores their evidence', async () => {
    const folder = await mkdtemp(join(tmpdir(), 'agento-live-workspace-'));
    try {
      const root = fileURLToPath(new URL('../../..', import.meta.url));
      const file = join(folder, 'workspace.json');
      const services = localExecution(root);
      const service = new LocalService(await Workspace.open(file), services);
      const project = await service.createProject({ name: 'Live static demo', repositoryPath: join(root, 'demo-apps/demo-app-01'),
        baseUrl: 'http://localhost:3000', allowedOrigins: ['http://localhost:3000'] });
      await service.startScan(project.id); await service.idle();
      const scan = await service.getScan(project.id);
      expect(scan.state).toBe('complete');
      expect(scan.diagnostics).toEqual([]);
      const findings = await service.getFindings(project.id);
      expect(findings.map(finding => finding.cweId).sort()).toEqual(['CWE-79', 'CWE-89']);
      expect(findings.map(finding => finding.endpoint?.path).sort()).toEqual(['/api/search', '/search']);
      expect(findings.every(finding => finding.status === 'HYPOTHESIS' && finding.sourceType === 'execution-api'
        && finding.evidence.length > 0 && finding.remediation.evidenceIds.length > 0)).toBe(true);
      const restarted = new LocalService(await Workspace.open(file), services);
      expect(await restarted.getFindings(project.id)).toEqual(findings);
      const model = await restarted.getSecurityModel(project.id);
      expect(model.model.endpoints).toHaveLength(19);
      expect(model.model.databaseOperations.length).toBeGreaterThan(0);
      expect(model.model.cookies.length).toBeGreaterThan(0);
      expect(model.model.corsConfigurations.length).toBeGreaterThan(0);
      expect(model.model.dataFlows.length).toBeGreaterThan(0);
      expect(model.model.evidence.every(item => item.projectId === project.id)).toBe(true);
    } finally { await rm(folder, { recursive: true, force: true }); }
  }, 30_000);
});

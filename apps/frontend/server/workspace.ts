import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { DiscoveryResult } from '@agento/discovery';
import type { FindingDetail, ProjectSummary, ScanSnapshot } from '../src/client/types.ts';
import { parseSavedDiscovery, validateProjectInput } from '../src/client/validation.ts';

export interface ProjectRecord {
  project: ProjectSummary;
  discovery?: DiscoveryResult;
  scan?: ScanSnapshot;
  findings: readonly FindingDetail[];
}
interface WorkspaceData { version: 1; projects: ProjectRecord[] }

/** One local service owns the file. Writes commit to disk before becoming visible. */
export class Workspace {
  private data: WorkspaceData = { version: 1, projects: [] };
  private pending: Promise<unknown> = Promise.resolve();
  private constructor(private readonly file: string) {}

  static async open(file: string): Promise<Workspace> {
    const workspace = new Workspace(file);
    let raw: string;
    try { raw = await readFile(file, 'utf8'); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      return workspace;
    }
    const data = JSON.parse(raw) as WorkspaceData;
    // Fail closed on an incompatible/corrupt store; never silently replace it.
    if (data.version !== 1 || !Array.isArray(data.projects)) throw new Error('Invalid workspace');
    const ids = new Set<string>();
    for (const record of data.projects) {
      const project = record.project;
      if (!project || typeof project.id !== 'string' || project.id === 'demo-shop' || ids.has(project.id)
        || typeof project.createdAt !== 'string' || !Array.isArray(project.languages)
        || !['project-input', 'saved-discovery'].includes(project.dataSource)
        || !['code-aware', 'black-box'].includes(project.mode)
        || !project.repositoryPath || Object.keys(validateProjectInput({ ...project, repositoryPath: project.repositoryPath })).length
        || !Array.isArray(record.findings)) throw new Error('Invalid workspace');
      ids.add(project.id);
      if (record.discovery && (!parseSavedDiscovery(record.discovery).ok
        || record.discovery.repositoryPath !== project.repositoryPath)) throw new Error('Invalid workspace discovery');
      if (record.scan && (record.scan.projectId !== project.id || record.scan.source !== 'execution-api'
        || !['pending', 'running', 'complete', 'failed'].includes(record.scan.state)
        || !Array.isArray(record.scan.stages))) throw new Error('Invalid workspace scan');
      if (record.findings.some(finding => finding.projectId !== project.id || finding.sourceType !== 'execution-api')) {
        throw new Error('Invalid workspace findings');
      }
    }
    workspace.data = data;
    if (data.projects.some(record => record.scan && ['pending', 'running'].includes(record.scan.state))) {
      await workspace.update(records => {
        for (const record of records) {
          if (!record.scan || !['pending', 'running'].includes(record.scan.state)) continue;
          record.scan = { ...record.scan, state: 'failed', completedAt: new Date().toISOString(),
            summary: 'The local service stopped before this scan completed. Start a new scan to retry.',
            stages: record.scan.stages.map(stage => stage.status === 'running' || stage.status === 'pending'
              ? { ...stage, status: 'failed', details: 'Execution interrupted by a service restart.' } : stage) };
        }
      });
    }
    return workspace;
  }

  read(): ProjectRecord[] { return structuredClone(this.data.projects); }

  update<T>(change: (records: ProjectRecord[]) => T): Promise<T> {
    const task = this.pending.then(async () => {
      const next = structuredClone(this.data);
      const result = change(next.projects);
      const directory = dirname(this.file);
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const temporary = `${this.file}.${randomUUID()}.tmp`;
      try {
        await writeFile(temporary, JSON.stringify(next), { mode: 0o600, flag: 'wx' });
        await rename(temporary, this.file);
        this.data = next;
      } finally { await rm(temporary, { force: true }); }
      return structuredClone(result);
    });
    this.pending = task.catch(() => undefined);
    return task;
  }
}

import { randomUUID } from 'node:crypto';
import type { DiscoveryResult } from '@agento/discovery';
import { createFixtureClient } from '../src/client/fixture-client.ts';
import { AgentOClientError } from '../src/client/types.ts';
import type { AgentOClient, BrowserWorkflowInput, BrowserWorkflowResult, ProjectInput, ProjectSummary, ScanSnapshot, ScanStage } from '../src/client/types.ts';
import { parseSavedDiscovery, validateProjectInput } from '../src/client/validation.ts';

import { candidateFindings, scanStages } from './execution.ts';
import type { ExecutionServices } from './execution.ts';
import { Workspace } from './workspace.ts';
import type { ProjectRecord } from './workspace.ts';
import { securityModelFor } from './security-model.ts';
import { fromFrameworkAnalysis, fromStaticAnalysis } from '../../../packages/security-model/src/contributions.ts';
import { emptyInvestigation, generateInvestigation, modelFingerprint } from './investigation.ts';

const demoId = 'demo-shop';
const isActive = (scan?: ScanSnapshot) => scan?.state === 'pending' || scan?.state === 'running';

function discoveryFor(path: string, value: unknown): DiscoveryResult {
  const parsed = parseSavedDiscovery(value);
  if (!parsed.ok) throw new AgentOClientError('INVALID_DISCOVERY', parsed.error);
  const normalize = (text: string) => text.trim().replace(/\/+$/u, '') || '/';
  if (normalize(parsed.value.repositoryPath) !== normalize(path)) {
    throw new AgentOClientError('INVALID_DISCOVERY', 'The discovery repository path must match the project repository path.');
  }
  return { ...parsed.value, repositoryPath: path };
}

export class LocalService implements AgentOClient {
  readonly storage = 'disk' as const;
  private readonly demo = createFixtureClient({ delayMs: 0 });
  private readonly jobs = new Set<Promise<void>>();
  private readonly storageFailures = new Set<string>();
  constructor(private readonly workspace: Workspace, private readonly execution: ExecutionServices) {}

  private ensureNotDeletedDemo(id: string): void {
    if (id === demoId && this.workspace.isDemoDeleted()) {
      throw new AgentOClientError('PROJECT_NOT_FOUND', 'This project is not available in the workspace.');
    }
  }

  private record(id: string, records = this.workspace.read()): ProjectRecord {
    const record = records.find(item => item.project.id === id);
    if (!record) throw new AgentOClientError('PROJECT_NOT_FOUND', 'This project is not available in the workspace.');
    return record;
  }
  private summary(record: ProjectRecord): ProjectSummary {
    return { ...record.project, ...(record.scan ? { scanState: record.scan.state } : {}) };
  }
  async listProjects() {
    const demo = this.workspace.isDemoDeleted() ? [] : await this.demo.listProjects();
    return [...this.workspace.read().map(record => this.summary(record)), ...demo];
  }
  async getProject(id: string) {
    if (id === demoId) {
      this.ensureNotDeletedDemo(id);
      return this.demo.getProject(id);
    }
    return this.summary(this.record(id));
  }

  async createProject(input: ProjectInput, discovery?: DiscoveryResult) {
    if (!input || typeof input.name !== 'string' || typeof input.repositoryPath !== 'string'
      || typeof input.baseUrl !== 'string' || !Array.isArray(input.allowedOrigins)
      || input.allowedOrigins.some(value => typeof value !== 'string') || Object.keys(validateProjectInput(input)).length) {
      throw new AgentOClientError('INVALID_INPUT', 'Check the project fields before continuing.');
    }
    const repositoryPath = input.repositoryPath.trim();
    const saved = discovery === undefined ? undefined : discoveryFor(repositoryPath, discovery);
    const project: ProjectSummary = {
      id: randomUUID(), name: input.name.trim(), repositoryPath, baseUrl: new URL(input.baseUrl.trim()).href,
      allowedOrigins: [...new Set(input.allowedOrigins.map(value => new URL(value.trim()).origin))],
      createdAt: new Date().toISOString(), languages: saved?.languages ?? [], mode: saved?.mode ?? 'black-box',
      dataSource: saved ? 'saved-discovery' : 'project-input',
    };
    return this.workspace.update(records => {
      records.unshift({ project, findings: [], ...(saved ? { discovery: saved } : {}) });
      return project;
    });
  }
  async deleteProject(id: string): Promise<void> {
    if (id === demoId) {
      this.ensureNotDeletedDemo(id);
      await this.workspace.deleteDemo();
      await this.demo.deleteProject(id);
      return;
    }
    await this.workspace.update(records => {
      const index = records.findIndex(item => item.project.id === id);
      if (index === -1) throw new AgentOClientError('PROJECT_NOT_FOUND', 'This project is not available in the workspace.');
      const record = records[index]!;
      if (isActive(record.scan)) throw new AgentOClientError('SCAN_IN_PROGRESS', 'Wait for the current scan to finish before deleting the project.');
      records.splice(index, 1);
    });
    this.storageFailures.delete(id);
  }
  async importDiscovery(id: string, discovery: DiscoveryResult) {
    if (id === demoId) {
      this.ensureNotDeletedDemo(id);
      throw new AgentOClientError('INVALID_INPUT', 'Create a project to save live discovery; the demo fixture is read-only.');
    }
    return this.workspace.update(records => {
      const record = this.record(id, records);
      if (isActive(record.scan)) throw new AgentOClientError('SCAN_IN_PROGRESS', 'Wait for the current scan before changing discovery.');
      record.discovery = discoveryFor(record.project.repositoryPath!, discovery);
      record.project = { ...record.project, languages: record.discovery.languages, mode: record.discovery.mode, dataSource: 'saved-discovery' };
      return this.summary(record);
    });
  }
  async getDiscovery(id: string) {
    if (id === demoId) {
      this.ensureNotDeletedDemo(id);
      return this.demo.getDiscovery(id);
    }
    const result = this.record(id).discovery;
    if (!result) throw new AgentOClientError('DISCOVERY_UNAVAILABLE', 'Run discovery or import a saved discovery result.');
    return result;
  }
  async getScan(id: string) {
    if (id === demoId) {
      this.ensureNotDeletedDemo(id);
      return this.demo.getScan(id);
    }
    if (this.storageFailures.has(id)) throw new AgentOClientError('CLIENT_UNAVAILABLE', 'Scan results could not be saved. Check workspace disk access and restart the service.');
    const result = this.record(id).scan;
    if (!result) throw new AgentOClientError('SCAN_UNAVAILABLE', 'No scan has run. Start a local static scan to collect source evidence.');
    return result;
  }
  async getSecurityModel(id: string) {
    if (id === demoId) {
      this.ensureNotDeletedDemo(id);
      return this.demo.getSecurityModel(id);
    }
    return securityModelFor(this.record(id));
  }
  async getInvestigation(id: string) {
    if (id === demoId) {
      this.ensureNotDeletedDemo(id);
      return this.demo.getInvestigation(id);
    }
    const record = this.record(id), source = securityModelFor(record);
    if (!record.investigation) return emptyInvestigation(source);
    const saved = record.investigation;
    return saved.fingerprint === modelFingerprint(source) ? saved.snapshot
      : { ...saved.snapshot, state: 'stale' as const, sourceState: source.state,
        diagnostics: [...new Set([...saved.snapshot.diagnostics, 'model-changed'])] };
  }
  async refreshInvestigation(id: string) {
    if (id === demoId) {
      this.ensureNotDeletedDemo(id);
      return this.demo.getInvestigation(id);
    }
    const record = this.record(id);
    if (isActive(record.scan)) throw new AgentOClientError('SCAN_IN_PROGRESS', 'Wait for the scan to finish before generating hypotheses and plans.');
    let result;
    try { result = await generateInvestigation(securityModelFor(record)); }
    catch { throw new AgentOClientError('CLIENT_UNAVAILABLE', 'Planning is unavailable. Build the CWE rules, hypothesis engine, and test planner, then try again.'); }
    return this.workspace.update(records => {
      const current = this.record(id, records);
      if (isActive(current.scan) || modelFingerprint(securityModelFor(current)) !== result.fingerprint) {
        throw new AgentOClientError('CLIENT_UNAVAILABLE', 'Application observations changed during planning. Generate plans again.');
      }
      current.investigation = result;
      return result.snapshot;
    });
  }
  async getFindings(id: string) {
    if (id === demoId) {
      this.ensureNotDeletedDemo(id);
      return this.demo.getFindings(id);
    }
    return this.record(id).findings;
  }
  async getFinding(id: string, findingId: string) {
    const finding = (await this.getFindings(id)).find(item => item.id === findingId);
    if (!finding) throw new AgentOClientError('FINDING_NOT_FOUND', 'This finding is not available for the selected project.');
    return finding;
  }
  async getWorkflows(id: string) {
    if (id === demoId) {
      this.ensureNotDeletedDemo(id);
      return this.demo.getWorkflows(id);
    }
    return (this.record(id).workflows ?? []);
  }
  async getWorkflow(id: string, workflowId: string) {
    const workflow = (await this.getWorkflows(id)).find(item => item.id === workflowId);
    if (!workflow) throw new AgentOClientError('WORKFLOW_NOT_FOUND', 'This workflow observation is not available for the selected project.');
    return workflow;
  }
  async runWorkflow(id: string, input: BrowserWorkflowInput): Promise<BrowserWorkflowResult> {
    if (id === demoId) {
      this.ensureNotDeletedDemo(id);
      throw new AgentOClientError('INVALID_INPUT', 'Create a project to execute live workflows; the demo contains recorded fixture workflows.');
    }
    if (!input || typeof input.goal !== 'string' || !input.goal.trim() || input.goal.length > 2_000
      || (input.identityId !== undefined && (typeof input.identityId !== 'string' || input.identityId.length > 100))
      || (input.targetName !== undefined && (typeof input.targetName !== 'string' || input.targetName.length > 100))
      || (input.planningMode !== undefined && !['automatic', 'recipes'].includes(input.planningMode))) {
      throw new AgentOClientError('INVALID_INPUT', 'Enter a goal of up to 2,000 characters and valid workflow parameters.');
    }
    const project = this.record(id).project;
    if (!this.execution.observeWorkflow) {
      throw new AgentOClientError('CLIENT_UNAVAILABLE', 'Browser workflow execution service is unavailable.');
    }
    const result = await this.execution.observeWorkflow(project, input);
    await this.workspace.update(records => {
      const record = this.record(id, records);
      const existing = (record.workflows ?? []).filter(item => item.id !== result.id);
      record.workflows = [result, ...existing];
    });
    return result;
  }


  async startScan(id: string): Promise<ScanSnapshot> {
    if (id === demoId) {
      this.ensureNotDeletedDemo(id);
      throw new AgentOClientError('INVALID_INPUT', 'Create a project for live scans; the demo contains synthetic evidence.');
    }
    const scan = await this.workspace.update(records => {
      const record = this.record(id, records);
      if (isActive(record.scan)) throw new AgentOClientError('SCAN_IN_PROGRESS', 'A scan is already running for this project.');
      if (records.some(item => isActive(item.scan))) throw new AgentOClientError('SCAN_IN_PROGRESS', 'The local scanner is busy. Wait for the current scan to finish.');
      record.scan = { id: randomUUID(), projectId: id, source: 'execution-api', state: 'pending',
        stages: scanStages(), summary: 'Source scan and local planning queued. Runtime verification is unavailable.' };
      record.findings = [];
      return record.scan;
    });
    this.storageFailures.delete(id);
    // Return the durable pending snapshot before starting long-running tool work.
    const job = new Promise<void>(resolve => setImmediate(resolve)).then(() => this.run(id, scan.id));
    this.jobs.add(job);
    void job.finally(() => this.jobs.delete(job));
    return scan;
  }

  /** Used during verification/shutdown to await accepted work. */
  async idle() { await Promise.all(this.jobs); }

  private async progress(id: string, scanId: string, stageId: string, status: ScanStage['status'], details: string) {
    await this.workspace.update(records => {
      const record = this.record(id, records);
      if (record.scan?.id !== scanId) throw new Error('Scan changed');
      record.scan = { ...record.scan, state: 'running', stages: record.scan.stages.map(stage => stage.id === stageId ? { ...stage, status, details } : stage) };
    });
  }

  private async run(id: string, scanId: string): Promise<void> {
    try {
      await this.progress(id, scanId, 'discovery', 'running', 'Inspecting repository metadata.');
      const project = this.record(id).project;
      const discovery = discoveryFor(project.repositoryPath!, await this.execution.discover(project.repositoryPath!));
      await this.workspace.update(records => {
        const record = this.record(id, records);
        record.discovery = discovery;
        record.project = { ...record.project, languages: discovery.languages, mode: discovery.mode, dataSource: 'saved-discovery' };
      });
      await this.progress(id, scanId, 'discovery', 'complete', `Repository discovery finished in ${discovery.mode} mode.`);
      await this.progress(id, scanId, 'static', 'running', 'Running Semgrep on a bounded source snapshot.');
      const current = this.record(id).project;
      const { analysis, framework } = await this.execution.analyze(current);
      const findings = candidateFindings(current, analysis, framework);
      const completed = analysis.status === 'completed';
      const hasResults = completed || analysis.status === 'partial';
      await this.workspace.update(records => {
        const record = this.record(id, records);
        record.findings = findings;
        const frameworkDiagnostics = (framework as typeof framework & { readonly diagnostics?: readonly { readonly code: string; readonly message: string }[] })?.diagnostics ?? [];
        record.modelSource = { version: 1, scanId, capturedAt: new Date().toISOString(), status: analysis.status,
          targetUrl: current.baseUrl, repositoryPath: current.repositoryPath!, allowedOrigins: current.allowedOrigins,
          diagnostics: [...discovery.diagnostics, ...analysis.diagnostics, ...frameworkDiagnostics],
          contributions: [...(framework ? [fromFrameworkAnalysis(framework)] : []), fromStaticAnalysis(analysis)] };
        record.scan = { ...record.scan!, state: 'running',
          summary: `${completed ? 'Static analysis completed' : `Static analysis ${analysis.status}`}. ${findings.length} candidate finding(s). Runtime verification was not run; no vulnerability is confirmed.`,
          diagnostics: [...discovery.diagnostics, ...analysis.diagnostics].map(({ code, message }) => ({ code, message })),
          stages: record.scan!.stages.map(stage => stage.id === 'static'
            ? { ...stage, status: completed ? 'complete' : analysis.status === 'skipped' ? 'unavailable' : 'failed', details: `Semgrep analysis ${analysis.status}. Review diagnostics for incomplete coverage.` }
            : stage.id === 'findings' ? { ...stage, status: hasResults ? 'complete' : 'unavailable', details: hasResults ? `${findings.length} hypotheses saved with recorded evidence and review guidance.` : 'No complete analysis is available. An empty result does not establish safety.' } : stage) };
      });
      let planningAvailable = false;
      try {
        await this.progress(id, scanId, 'hypotheses', 'running', 'Generating evidence-linked questions from the saved application model.');
        const investigation = await generateInvestigation(securityModelFor(this.record(id)), async count => {
          await this.progress(id, scanId, 'hypotheses', 'complete', `${count} grounded hypotheses generated. No vulnerability verdicts were made.`);
          await this.progress(id, scanId, 'planning', 'running', 'Preparing test steps and checking planning prerequisites.');
        });
        await this.workspace.update(records => {
          const record = this.record(id, records);
          record.investigation = investigation;
          const { plans } = investigation.snapshot;
          record.scan = { ...record.scan!, stages: record.scan!.stages.map(stage => stage.id === 'planning'
            ? { ...stage, status: 'complete', details: `${plans.length} test drafts saved. ${plans.filter(plan => plan.readiness === 'BLOCKED').length} blocked by missing prerequisites. No tests were executed.` } : stage) };
        });
        planningAvailable = true;
      } catch {
        await this.workspace.update(records => {
          const record = this.record(id, records);
          record.scan = { ...record.scan!, stages: record.scan!.stages.map(stage => ['hypotheses', 'planning'].includes(stage.id) && stage.status !== 'complete'
            ? { ...stage, status: 'unavailable', details: 'Planning could not finish. Build the CWE rules, hypothesis engine, and test planner. Generate analysis from Hypotheses to retry.' } : stage) };
        });
      }
      await this.workspace.update(records => {
        const record = this.record(id, records);
        record.scan = { ...record.scan!, state: completed ? 'complete' : 'failed', completedAt: new Date().toISOString(),
          summary: `${record.scan!.summary}${planningAvailable ? ' Hypotheses and test drafts are available.' : ' Hypothesis generation or test planning was unavailable.'}` };
      });
    } catch {
      try {
        await this.workspace.update(records => {
          const record = this.record(id, records);
          record.scan = { ...record.scan!, state: 'failed', completedAt: new Date().toISOString(),
            summary: 'Local scan failed. Check repository access and build the discovery, Express, and Semgrep packages, then retry.',
            stages: record.scan!.stages.map(stage => stage.status === 'running'
              ? { ...stage, status: 'failed', details: 'The local execution service could not complete this stage.' }
              : stage.status === 'pending' ? { ...stage, status: 'unavailable', details: 'This stage did not run.' } : stage) };
        });
      } catch { this.storageFailures.add(id); }
    }
  }
}

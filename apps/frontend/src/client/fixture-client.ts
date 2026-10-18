import type { DiscoveryResult } from '@agento/discovery';
import { demoDiscovery } from '../data/demo-discovery.ts';
import { DEMO_PROJECT_ID, demoFindings, demoProject, demoScan, demoWorkflows } from '../data/fixtures.ts';
import { AgentOClientError } from './types.ts';
import type { AgentOClient, BrowserWorkflowInput, BrowserWorkflowResult, ProjectInput, ProjectSummary } from './types.ts';

import { parseSavedDiscovery, validateProjectInput } from './validation.ts';

export interface FixtureClientOptions {
  readonly delayMs?: number;
  /** Test integration failure paths without executing a live transport. */
  readonly failMethods?: readonly (keyof AgentOClient)[];
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function checkRepositoryPath(repositoryPath: string, discovery: DiscoveryResult): void {
  const normalize = (value: string) => value.trim().replace(/\/+$/u, '') || '/';
  if (normalize(repositoryPath) !== normalize(discovery.repositoryPath)) {
    throw new AgentOClientError('INVALID_DISCOVERY', 'The saved discovery repository path must match the project repository path. Use the path recorded by your discovery run.');
  }
}

/** Session-local demo implementation. It never writes storage or contacts targets. */
export function createFixtureClient(options: FixtureClientOptions = {}): AgentOClient {
  const projects = new Map<string, ProjectSummary>([[DEMO_PROJECT_ID, clone(demoProject)]]);
  const discoveries = new Map<string, DiscoveryResult>([[DEMO_PROJECT_ID, clone(demoDiscovery)]]);
  const workflows = new Map<string, BrowserWorkflowResult[]>([[DEMO_PROJECT_ID, clone([...demoWorkflows])]]);
  let projectSequence = 0;


  async function ready(method: keyof AgentOClient): Promise<void> {
    await new Promise<void>((resolve) => setTimeout(resolve, Math.max(0, options.delayMs ?? 180)));
    if (options.failMethods?.includes(method)) {
      throw new AgentOClientError('CLIENT_UNAVAILABLE', 'Project data could not be loaded. Try again.');
    }
  }

  function project(projectId: string): ProjectSummary {
    const result = projects.get(projectId);
    if (!result) throw new AgentOClientError('PROJECT_NOT_FOUND', 'This project is not available in the current session.');
    return result;
  }

  return {
    storage: 'memory',
    async listProjects() {
      await ready('listProjects');
      return clone([...projects.values()]);
    },
    async getProject(projectId) {
      await ready('getProject');
      return clone(project(projectId));
    },
    async createProject(input: ProjectInput, discovery?: DiscoveryResult) {
      await ready('createProject');
      const errors = validateProjectInput(input);
      if (Object.keys(errors).length > 0) {
        throw new AgentOClientError('INVALID_INPUT', 'Check the project fields before continuing.');
      }
      const parsed = discovery === undefined ? undefined : parseSavedDiscovery(discovery);
      if (parsed && !parsed.ok) throw new AgentOClientError('INVALID_DISCOVERY', parsed.error);
      const savedDiscovery = parsed?.ok ? parsed.value : undefined;
      if (savedDiscovery) checkRepositoryPath(input.repositoryPath, savedDiscovery);
      projectSequence += 1;
      const result: ProjectSummary = {
        id: `project-${projectSequence}`,
        name: input.name.trim(),
        repositoryPath: input.repositoryPath.trim(),
        baseUrl: new URL(input.baseUrl.trim()).href,
        allowedOrigins: [...new Set(input.allowedOrigins.map((value) => new URL(value.trim()).origin))],
        languages: savedDiscovery?.languages ?? [],
        mode: savedDiscovery?.mode ?? 'black-box',
        dataSource: savedDiscovery ? 'saved-discovery' : 'project-input',
        createdAt: new Date().toISOString(),
      };
      projects.set(result.id, clone(result));
      if (savedDiscovery) discoveries.set(result.id, clone(savedDiscovery));
      return clone(result);
    },
    async importDiscovery(projectId, discovery) {
      await ready('importDiscovery');
      const currentProject = project(projectId);
      const parsed = parseSavedDiscovery(discovery);
      if (!parsed.ok) throw new AgentOClientError('INVALID_DISCOVERY', parsed.error);
      checkRepositoryPath(currentProject.repositoryPath ?? '', parsed.value);
      const result: ProjectSummary = {
        ...currentProject,
        languages: parsed.value.languages,
        mode: parsed.value.mode,
        dataSource: projectId === DEMO_PROJECT_ID ? 'demo-fixture' : 'saved-discovery',
      };
      discoveries.set(projectId, clone(parsed.value));
      projects.set(projectId, clone(result));
      return clone(result);
    },
    async getDiscovery(projectId) {
      await ready('getDiscovery');
      project(projectId);
      const result = discoveries.get(projectId);
      if (!result) throw new AgentOClientError('DISCOVERY_UNAVAILABLE', 'No saved discovery is attached to this project. Import a saved discovery JSON result from this discovery view.');
      return clone(result);
    },
    async getScan(projectId) {
      await ready('getScan');
      project(projectId);
      if (projectId !== DEMO_PROJECT_ID) throw new AgentOClientError('SCAN_UNAVAILABLE', 'No scan is available for this project. Scan execution is not connected yet.');
      return clone(demoScan);
    },
    async startScan() {
      throw new AgentOClientError('SCAN_UNAVAILABLE', 'Live scans require the local workspace service.');
    },
    async getFindings(projectId) {
      await ready('getFindings');
      project(projectId);
      return projectId === DEMO_PROJECT_ID ? clone(demoFindings) : [];
    },
    async getFinding(projectId, findingId) {
      await ready('getFinding');
      project(projectId);
      const finding = projectId === DEMO_PROJECT_ID ? demoFindings.find((entry) => entry.id === findingId) : undefined;
      if (!finding) throw new AgentOClientError('FINDING_NOT_FOUND', 'This finding is not available for the selected project.');
      return clone(finding);
    },
    async getWorkflows(projectId) {
      await ready('getWorkflows');
      project(projectId);
      return clone(workflows.get(projectId) ?? []);
    },
    async getWorkflow(projectId, workflowId) {
      await ready('getWorkflow');
      project(projectId);
      const list = workflows.get(projectId) ?? [];
      const item = list.find(w => w.id === workflowId);
      if (!item) throw new AgentOClientError('WORKFLOW_NOT_FOUND', 'This workflow observation is not available for the selected project.');
      return clone(item);
    },
    async runWorkflow(projectId, input) {
      await ready('runWorkflow');
      const p = project(projectId);
      if (projectId === DEMO_PROJECT_ID) {
        throw new AgentOClientError('INVALID_INPUT', 'Create a project for live workflows; the demo contains recorded fixture workflows.');
      }
      const newWf: BrowserWorkflowResult = {
        id: `wf-${Date.now()}`,
        projectId,
        goal: input.goal,
        identityId: input.identityId || 'alice',
        personaLabel: input.identityId ? input.identityId[0]!.toUpperCase() + input.identityId.slice(1) : 'Alice',
        targetUrl: p.baseUrl,
        outcome: 'COMPLETED',
        completionType: 'recipe-completed',
        durationMs: 950,
        actionsCount: 5,
        finalUrl: p.baseUrl,
        endpoints: [],
        network: [
          { url: p.baseUrl, method: 'GET', status: 200, resourceType: 'document', blocked: false, timestamp: new Date().toISOString() },
        ],
        diagnostics: [],
        evidence: [],
        sourceType: 'demo-fixture',
        executedAt: new Date().toISOString(),
      };
      const list = workflows.get(projectId) ?? [];
      list.unshift(newWf);
      workflows.set(projectId, list);
      return clone(newWf);
    },
  };
}


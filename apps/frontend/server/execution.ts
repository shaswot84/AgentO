import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { FrameworkAdapter, FrameworkAnalysis, Project } from '@agento/core';
import type { DiscoveryOptions, DiscoveryResult, RegisteredFrameworkAdapter } from '@agento/discovery';
import type { SemgrepAdapterOptions, SemgrepAnalysis } from '../../../plugins/tools/semgrep/src/types.ts';
import { observeBrowserWorkflow, type WorkflowModules } from './workflows.ts';
import type { BrowserWorkflowInput, BrowserWorkflowResult, FindingDetail, ScanStage } from '../src/client/types.ts';

export interface ExecutionServices {
  discover(repositoryPath: string): Promise<DiscoveryResult>;
  analyze(project: Project): Promise<{ analysis: SemgrepAnalysis; framework?: FrameworkAnalysis }>;
  observeWorkflow?(project: Project, input: BrowserWorkflowInput): Promise<BrowserWorkflowResult>;
}

export function localExecution(root: string): ExecutionServices {
  try {
    const envPath = resolve(root, '.env');
    if (existsSync(envPath) && typeof process.loadEnvFile === 'function') process.loadEnvFile(envPath);
  } catch { /* Ignore missing or unreadable env file */ }
  // Load installed host providers only when used, outside the browser bundle.
  const load = (path: string): Promise<unknown> => import(/* @vite-ignore */ pathToFileURL(resolve(root, path)).href);
  const expressModule = () => load('plugins/frameworks/express/dist/index.js') as Promise<{ ExpressFrameworkAdapter: new () => FrameworkAdapter }>;
  function repositoryPath(path: string): string {
    const direct = resolve(root, path);
    if (existsSync(direct)) return direct;
    const demo = resolve(root, 'demo-apps', path === 'demo-app' ? 'demo-app-01' : path);
    return existsSync(demo) ? demo : direct;
  }
  return {
    async discover(path) {
      const { discoverProject } = await load('packages/discovery/dist/index.js') as {
        discoverProject: (path: string, options: DiscoveryOptions) => Promise<DiscoveryResult>;
      };
      let adapters: RegisteredFrameworkAdapter[] = [];
      try {
        const { ExpressFrameworkAdapter } = await expressModule();
        adapters = [{ framework: 'express', languages: ['javascript', 'typescript'], adapter: new ExpressFrameworkAdapter() }];
      } catch { /* Discovery reports the unavailable adapter and falls back. */ }
      const result = await discoverProject(repositoryPath(path), { adapters });
      return { ...result, repositoryPath: path };
    },
    async analyze(project) {
      const scoped = { ...project, repositoryPath: repositoryPath(project.repositoryPath!) };
      let framework: FrameworkAnalysis | undefined;
      if (project.mode === 'code-aware') {
        const { ExpressFrameworkAdapter } = await expressModule();
        const adapter = new ExpressFrameworkAdapter();
        if (await adapter.supports(scoped)) framework = await adapter.extract(scoped);
      }
      const { SemgrepAdapter } = await load('plugins/tools/semgrep/dist/index.js') as {
        SemgrepAdapter: new (options: SemgrepAdapterOptions) => { analyze: (project: Project) => Promise<SemgrepAnalysis> };
      };
      const candidates = [
        process.env.AGENTO_SEMGREP_EXECUTABLE,
        '/tmp/agento-semgrep-venv/bin/semgrep',
        resolve(root, 'plugins/tools/semgrep/.venv/bin/semgrep'),
      ].filter(Boolean) as string[];
      const executable = candidates.find(candidate => existsSync(candidate));
      const adapter = new SemgrepAdapter({ ...(executable ? { executable } : {}), ...(framework ? { frameworkAnalysis: framework } : {}) });
      const analysis = await adapter.analyze(scoped);
      return { analysis, ...(framework ? { framework } : {}) };
    },
    async observeWorkflow(project, input) {
      try {
        const browser = await load('plugins/tools/e2e-browser/dist/index.js') as WorkflowModules['browser'];
        const workflow = await load('packages/workflow/dist/index.js') as WorkflowModules['workflow'];
        return await observeBrowserWorkflow(project, input, { browser, workflow,
          createModelProvider: async () => {
            const key = [process.env.OPENAI_API_KEY, process.env.OLLAMA_API_KEY]
              .map(value => value?.trim()).find(value => value && !value.startsWith('your_'));
            if (!key) return undefined;
            const provider = await load('plugins/models/openai/dist/index.js') as typeof import('../../../plugins/models/openai/src/index.ts');
            return provider.createOpenAIModelProvider({ resolveApiKey: () => key });
          },
        });
      } catch {
        return { id: `wf-${randomUUID()}`, projectId: project.id, goal: input.goal,
          identityId: input.identityId ?? 'alice', targetUrl: project.baseUrl, outcome: 'FAILED',
          completionType: 'unconfirmed', durationMs: 0, actionsCount: 0, endpoints: [], network: [], evidence: [],
          diagnostics: [{ code: 'browser-unavailable', message: 'Browser workflow execution is unavailable. Check the host package builds and browser installation.' }],
          sourceType: 'execution-api', executedAt: new Date().toISOString() };
      }
    },
  };
}


export const scanStages = (): readonly ScanStage[] => [
  { id: 'discovery', label: 'Repository discovery', status: 'pending', details: 'Inspect the configured repository and select available adapters.' },
  { id: 'static', label: 'Static security analysis', status: 'pending', details: 'Run bundled Semgrep XSS and SQL injection candidate rules.' },
  { id: 'findings', label: 'Findings and remediation guidance', status: 'pending', details: 'Attach recorded source evidence and candidate review guidance.' },
  { id: 'runtime', label: 'Runtime verification', status: 'unavailable', details: 'Runtime verification rules are not configured. Candidates remain hypotheses.' },
];

/** Present real observations without promoting static candidates to verified defects. */
export function candidateFindings(project: Project, analysis: SemgrepAnalysis, framework?: FrameworkAnalysis): FindingDetail[] {
  return analysis.signals.flatMap(signal => signal.cweIds.map(cweId => {
    const id = `${signal.id}:${cweId}`;
    const endpoint = framework?.endpoints.find(item => item.id === signal.endpointId);
    const sql = cweId === 'CWE-89';
    const evidence = analysis.evidence.filter(item => signal.evidenceIds.includes(item.id)
      || item.facts.observation === 'static-analysis-run');
    const evidenceIds = evidence.map(item => item.id);
    return {
      id, projectId: project.id, hypothesisId: `hypothesis:${id}`, cweId,
      owaspCategory: 'A03:2021 Injection', title: signal.summary,
      status: 'HYPOTHESIS', severity: 'medium', confidence: 'low',
      rootCause: `${signal.summary} Source analysis alone does not establish reachability or exploitability; runtime verification is required.`,
      sourceType: 'execution-api', evidence, evidenceIds, testPlanIds: [],
      ...(signal.source ? { source: signal.source } : {}),
      ...(endpoint ? { endpoint, endpointId: endpoint.id } : {}),
      remediation: { findingId: id, evidenceIds,
        explanation: sql
          ? 'Candidate review guidance: inspect the recorded SQL sink and data flow. If untrusted values reach statement text, use parameterized queries with bound values. This suggestion has not been applied or verified.'
          : 'Candidate review guidance: inspect the recorded HTML sink and data flow. If untrusted values reach HTML, use context-aware output encoding or a safely escaping template. This suggestion has not been applied or verified.',
        regressionTest: sql
          ? 'Add a test that passes SQL metacharacters as input and verifies they remain data. Rerun static analysis and an authorized runtime test.'
          : 'Add a test that passes HTML metacharacters as input and verifies they render as text without script execution. Rerun static analysis and an authorized runtime test.',
      },
    } satisfies FindingDetail;
  }));
}

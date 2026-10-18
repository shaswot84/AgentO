import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { Endpoint, Evidence, FrameworkAdapter, FrameworkAnalysis, Project } from '@agento/core';
import type { DiscoveryOptions, DiscoveryResult, RegisteredFrameworkAdapter } from '@agento/discovery';
import type { SemgrepAdapterOptions, SemgrepAnalysis } from '../../../plugins/tools/semgrep/src/types.ts';
import type { BrowserWorkflowResult, FindingDetail, ObservedNetworkTraffic, ScanStage, WorkflowStepRecord } from '../src/client/types.ts';

export interface ExecutionServices {
  discover(repositoryPath: string): Promise<DiscoveryResult>;
  analyze(project: Project): Promise<{ analysis: SemgrepAnalysis; framework?: FrameworkAnalysis }>;
  observeWorkflow?(project: Project, input: { goal: string; identityId?: string; targetName?: string }): Promise<BrowserWorkflowResult>;
}

export function localExecution(root: string): ExecutionServices {
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
      const executable = process.env.AGENTO_SEMGREP_EXECUTABLE;
      const adapter = new SemgrepAdapter({ ...(executable ? { executable } : {}), ...(framework ? { frameworkAnalysis: framework } : {}) });
      const analysis = await adapter.analyze(scoped);
      return { analysis, ...(framework ? { framework } : {}) };
    },
    async observeWorkflow(project, input) {
      const workflowId = `wf-${randomUUID()}`;
      const now = new Date().toISOString();
      const identityId = input.identityId || 'alice';
      const targetName = input.targetName || 'storefront';
      try {
        const e2eModule = await load('plugins/tools/e2e-browser/dist/index.js') as {
          TesterArmyE2EAdapter: new (options: unknown) => {
            observe: (context: unknown, workflow: unknown) => Promise<{
              outcome: 'COMPLETED' | 'FAILED' | 'SKIPPED';
              diagnostics: readonly { code: string; message: string }[];
              endpoints: readonly Endpoint[];
              evidence: readonly Evidence[];
            }>;
          };
          storefrontBrowserOptions: (origins: readonly string[]) => { target?: { personas?: { id: string; label?: string }[] } };
          purchasesBrowserOptions: (origins: readonly string[]) => { target?: { personas?: { id: string; label?: string }[] } };
          portalBrowserOptions: (origins: readonly string[]) => { target?: { personas?: { id: string; label?: string }[] } };
          edgeSpaBrowserOptions: (origins: readonly string[]) => { target?: { personas?: { id: string; label?: string }[] } };
        };
        const origins = project.allowedOrigins.length ? project.allowedOrigins : [new URL(project.baseUrl).origin];
        const optionsResolver = targetName === 'purchases' ? e2eModule.purchasesBrowserOptions
          : targetName === 'portal' ? e2eModule.portalBrowserOptions
          : targetName === 'edge-spa' ? e2eModule.edgeSpaBrowserOptions
          : e2eModule.storefrontBrowserOptions;
        const options = optionsResolver(origins);
        const adapter = new e2eModule.TesterArmyE2EAdapter(options);
        const context = {
          project: { ...project, repositoryPath: repositoryPath(project.repositoryPath || '') },
          components: [],
          endpoints: [],
          identities: options.target?.personas || [],
          resources: [],
          signals: [],
          evidence: [],
        };
        const start = Date.now();
        const observation = await adapter.observe(context, {
          id: workflowId,
          identityId,
          goal: input.goal,
        });
        const durationMs = Date.now() - start;
        const network: ObservedNetworkTraffic[] = [];
        let sessionInfo: BrowserWorkflowResult['session'] = undefined;

        for (const item of observation.evidence) {
          if (item.kind === 'http-request') {
            const facts = item.facts as Record<string, unknown>;
            network.push({
              url: String(facts.url || ''),
              method: String(facts.method || 'GET'),
              status: null,
              resourceType: String(facts.resourceType || 'fetch'),
              blocked: Boolean(facts.blocked),
              ...(facts.blockedReason ? { blockedReason: facts.blockedReason as any } : {}),
              ...(facts.timestamp ? { timestamp: String(facts.timestamp) } : {}),
            });
          } else if (item.kind === 'http-response') {
            const facts = item.facts as Record<string, unknown>;
            const match = network.find(req => req.url === facts.url && req.status === null);
            if (match) {
              (match as any).status = typeof facts.status === 'number' ? facts.status : 200;
              if (facts.headers && typeof facts.headers === 'object') {
                (match as any).headers = facts.headers;
              }
            }
          } else if (item.kind === 'identity-session') {
            const facts = item.facts as Record<string, unknown>;
            sessionInfo = {
              personaId: identityId,
              authenticated: Boolean(facts.authenticated),
              reused: Boolean(facts.reused),
              ...(facts.sessionRef ? { sessionRef: String(facts.sessionRef) } : {}),
              ...(facts.targetId ? { targetId: String(facts.targetId) } : {}),
            };
          }
        }

        const browserObs = observation.evidence.find(e => e.kind === 'browser-observation');
        const actionsCount = (browserObs?.facts?.executedActions as number) ?? (network.length || 1);

        return {
          id: workflowId,
          projectId: project.id,
          goal: input.goal,
          identityId,
          personaLabel: options.target?.personas?.find(p => p.id === identityId)?.label || identityId,
          targetUrl: project.baseUrl,
          outcome: observation.outcome,
          completionType: observation.outcome === 'COMPLETED' ? 'recipe-completed' : 'unconfirmed',
          durationMs,
          actionsCount,
          endpoints: observation.endpoints,
          network,
          ...(sessionInfo ? { session: sessionInfo } : {}),
          diagnostics: observation.diagnostics,
          evidence: observation.evidence,
          sourceType: 'execution-api',
          executedAt: now,
        };
      } catch (error) {
        return {
          id: workflowId,
          projectId: project.id,
          goal: input.goal,
          identityId,
          personaLabel: identityId,
          targetUrl: project.baseUrl,
          outcome: 'FAILED',
          durationMs: 0,
          actionsCount: 0,
          endpoints: [],
          network: [],
          diagnostics: [{
            code: 'browser-failed',
            message: error instanceof Error ? error.message : 'Browser workflow execution failed. Verify target application is reachable and browser dependencies are installed.',
          }],
          evidence: [],
          sourceType: 'execution-api',
          executedAt: now,
        };
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

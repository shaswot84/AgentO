import { randomUUID } from 'node:crypto';
import type { AnalysisContext, BrowserExecutionObservation, Identity, ModelProvider, Project } from '@agento/core';
import type { BrowserWorkflowInput, BrowserWorkflowResult, ObservedNetworkTraffic } from '../src/client/types.ts';
import { workflowProfiles } from '../src/workflow-catalog.ts';

export interface WorkflowModules {
  readonly browser: typeof import('../../../plugins/tools/e2e-browser/src/index.ts');
  readonly workflow: typeof import('../../../packages/workflow/src/index.ts');
  /** Lazy: recognized recipes never load a model or require an API key. */
  readonly createModelProvider: () => Promise<ModelProvider | undefined>;
}

export async function observeBrowserWorkflow(project: Project, input: BrowserWorkflowInput,
  modules: WorkflowModules): Promise<BrowserWorkflowResult> {
  const profile = workflowProfiles.find(item => item.id === (input.targetName ?? 'storefront'));
  const identityId = input.identityId ?? profile?.personas[0]?.id ?? 'alice';
  const base = { id: `wf-${randomUUID()}`, projectId: project.id, goal: input.goal.trim(), identityId,
    targetUrl: project.baseUrl, sourceType: 'execution-api' as const, executedAt: new Date().toISOString() };
  const skipped = (code: string, message: string): BrowserWorkflowResult => ({ ...base, outcome: 'SKIPPED',
    completionType: 'unconfirmed', durationMs: 0, actionsCount: 0, endpoints: [], network: [],
    diagnostics: [{ code, message }], evidence: [] });
  if (!profile) return skipped('invalid-profile', 'Choose a supported application profile.');
  if (!['automatic', 'recipes'].includes(input.planningMode ?? 'automatic')) {
    return skipped('invalid-workflow', 'Choose automatic planning or recipes only.');
  }
  const browser = modules.browser;
  const resolvers = { storefront: browser.storefrontBrowserOptions, purchases: browser.purchasesBrowserOptions,
    portal: browser.portalBrowserOptions, 'edge-spa': browser.edgeSpaBrowserOptions, 'ops-console': browser.opsConsoleBrowserOptions };
  const options = resolvers[profile.id as keyof typeof resolvers](project.allowedOrigins);
  const target = options.target!;
  const persona = target.personas?.find(item => item.id === identityId);
  if (!persona) return skipped('invalid-persona', 'Choose a persona supported by the selected application profile.');
  // Fixture profiles contain seeded credentials, so they are only usable with loopback projects.
  if (![project.baseUrl, ...project.allowedOrigins].every(value => ['localhost', '127.0.0.1', '[::1]'].includes(new URL(value).hostname))) {
    return skipped('scope-denied', 'Built-in demo profiles require localhost target URLs and allowed origins.');
  }
  const context: AnalysisContext = { project, components: [], endpoints: [], identities: target.personas ?? [],
    resources: [], signals: [], evidence: [] };
  const request = { id: base.id, identityId, goal: base.goal };
  const recipe = options.resolveGoal?.(context, request);
  const knownPlannerGoal = Boolean(options.workflowPlanner && profile.recipeGoals.includes(base.goal.toLowerCase()));
  let provider: ModelProvider | undefined;
  if (!recipe && !knownPlannerGoal) {
    if (input.planningMode === 'recipes') return skipped('unsupported-goal', 'This goal has no registered recipe. Choose automatic planning or use a listed recipe.');
    try { provider = await modules.createModelProvider(); }
    catch { return skipped('planner-unavailable', 'The model provider could not be configured. Check the backend model settings.'); }
    if (!provider) return skipped('planner-unavailable', 'Natural-language goals need a backend model API key. Configure OPENAI_API_KEY or OLLAMA_API_KEY and restart the local service, or use a listed recipe.');
  }
  const driver = new browser.TesterArmyE2EAdapter({ ...options, timeoutMs: 120_000, maxWorkflowActions: 40 });
  const orchestrator = new modules.workflow.BrowserWorkflowOrchestrator({ driver, target,
    ...(recipe ? { resolveGoal: () => recipe } : {}),
    ...(knownPlannerGoal ? { workflowPlanner: options.workflowPlanner! } : {}),
    ...(provider ? { semanticPlanner: new modules.workflow.LLMWorkflowPlanner(provider, {
      maxModelCalls: 8, maxTotalTokens: 16_000, callTimeoutMs: 30_000,
    }) } : {}),
    budgets: { maxActions: 40, maxWorkflowMs: 120_000, maxRecoveryAttempts: 1 },
  });
  const started = Date.now();
  const observation = await orchestrator.observe(context, request);
  return resultFromObservation(base, persona, observation, Date.now() - started);
}

function resultFromObservation(base: { id: string; projectId: string; goal: string; identityId: string;
  targetUrl: string; sourceType: 'execution-api'; executedAt: string }, persona: Identity,
  observation: BrowserExecutionObservation, durationMs: number): BrowserWorkflowResult {
  const network: ObservedNetworkTraffic[] = [];
  const requests = new Map<string, number>();
  let session: BrowserWorkflowResult['session'];
  for (const item of observation.evidence) {
    const facts = item.facts;
    if (item.kind === 'http-request') {
      requests.set(item.id, network.length);
      network.push({ url: String(facts.url ?? ''), method: String(facts.method ?? 'GET'), status: null,
        resourceType: String(facts.resourceType ?? 'fetch'), blocked: facts.blocked === true,
        ...(typeof facts.blockedReason === 'string' ? { blockedReason: facts.blockedReason as ObservedNetworkTraffic['blockedReason'] & string } : {}),
        ...(typeof facts.timestamp === 'string' ? { timestamp: facts.timestamp } : {}),
        ...(typeof facts.initiatingPage === 'string' ? { initiatingPage: facts.initiatingPage } : {}) });
    } else if (item.kind === 'http-response') {
      const index = typeof facts.requestEvidenceId === 'string' ? requests.get(facts.requestEvidenceId) : undefined;
      const request = index === undefined ? undefined : network[index];
      if (request) network[index!] = { ...request, status: typeof facts.status === 'number' ? facts.status : null,
        ...(facts.headers && typeof facts.headers === 'object' && !Array.isArray(facts.headers)
          ? { headers: Object.fromEntries(Object.entries(facts.headers).filter((entry): entry is [string, string] => typeof entry[1] === 'string')) } : {}) };
    } else if (item.kind === 'identity-session') {
      session = { personaId: base.identityId, authenticated: facts.authenticated === true, reused: facts.reused === true,
        ...(typeof facts.sessionRef === 'string' ? { sessionRef: facts.sessionRef } : {}),
        ...(typeof facts.targetId === 'string' ? { targetId: facts.targetId } : {}) };
    }
  }
  const browser = observation.evidence.find(item => item.kind === 'browser-observation' && typeof item.facts.executedActions === 'number')?.facts;
  const planning = observation.evidence.find(item => item.facts.workflowId === base.id)?.facts;
  const number = (value: unknown) => typeof value === 'number' ? value : 0;
  const finalUrl = browser?.url ?? planning?.url;
  const history = Array.isArray(planning?.history) ? planning.history : [];
  const rawSummary = planning?.pageModelSummary;
  const summary = rawSummary && typeof rawSummary === 'object' && !Array.isArray(rawSummary)
    ? rawSummary as Readonly<Record<string, unknown>> : undefined;
  return { ...base, personaLabel: persona.label, outcome: observation.outcome, durationMs,
    completionType: typeof planning?.completion === 'string' ? planning.completion : 'unconfirmed',
    actionsCount: number(browser?.executedActions), modelCalls: number(planning?.modelCalls), modelTokens: number(planning?.modelTokens),
    recoveryAttempts: number(planning?.recoveryAttempts), ...(typeof finalUrl === 'string' ? { finalUrl } : {}),
    steps: history.flatMap(item => item && typeof item === 'object' && !Array.isArray(item)
      && typeof item.actionType === 'string' && ['completed', 'failed', 'rejected'].includes(String(item.outcome))
      ? [{ pageId: String(item.pageId), actionType: item.actionType, outcome: item.outcome as 'completed' | 'failed' | 'rejected',
        url: String(item.url), ...(typeof item.code === 'string' ? { code: item.code } : {}) }] : []),
    ...(summary && typeof summary === 'object' && !Array.isArray(summary) ? { pageModelSummary: {
      title: String(summary.title ?? ''), headings: Array.isArray(summary.headings) ? summary.headings.filter((item): item is string => typeof item === 'string') : [],
      interactiveElementCount: number(summary.interactiveElementCount),
    } } : {}),
    endpoints: observation.endpoints, resources: observation.resources, signals: observation.signals,
    identities: [{ id: persona.id, label: persona.label, roles: persona.roles, authentication: persona.authentication }],
    network, ...(session ? { session } : {}), diagnostics: observation.diagnostics, evidence: observation.evidence };
}

import type {
  BrowserWorkflowDriver, CWEPlugin, FrameworkAdapter, ReasoningModel,
  RemediationProvider, RemediationSuggestion, ScanRequest, SecurityScanner, StaticAnalyzer,
} from './contracts.js';
import type {
  AnalysisContext, Evidence, Finding, SecurityHypothesis, SecurityTestPlan, SecurityTestResult,
} from './domain.js';

export interface CoreProviders {
  readonly plugins: readonly CWEPlugin[];
  readonly staticAnalyzer?: StaticAnalyzer;
  readonly frameworkAdapter?: FrameworkAdapter;
  readonly browser?: BrowserWorkflowDriver;
  readonly scanner?: SecurityScanner;
  readonly reasoning?: ReasoningModel;
  readonly remediation?: RemediationProvider;
}

export interface ScanReport {
  readonly context: AnalysisContext;
  readonly hypotheses: readonly SecurityHypothesis[];
  readonly plans: readonly SecurityTestPlan[];
  readonly results: readonly SecurityTestResult[];
  readonly findings: readonly Finding[];
  readonly remediation: readonly RemediationSuggestion[];
}

/** Minimal wiring skeleton. No discovery, tool registry, policy, or verification implementation. */
export class AgentOOrchestrator {
  private readonly plugins: ReadonlyMap<string, CWEPlugin>;

  constructor(private readonly providers: CoreProviders) {
    const plugins = new Map<string, CWEPlugin>();
    for (const plugin of providers.plugins) {
      if (plugins.has(plugin.cweId)) throw new Error(`Duplicate plugin: ${plugin.cweId}`);
      plugins.set(plugin.cweId, plugin);
    }
    this.plugins = plugins;
  }

  async run(request: ScanRequest): Promise<ScanReport> {
    if (request.workflows?.length && !this.providers.browser) {
      throw new Error('Browser workflows require a browser provider');
    }
    if (request.suggestRemediation && !this.providers.remediation) {
      throw new Error('Remediation requested without a remediation provider');
    }
    let context: AnalysisContext = {
      project: request.project, identities: request.identities,
      components: [], endpoints: [], resources: [], signals: [], evidence: [],
    };
    if (request.project.mode === 'code-aware') {
      if (this.providers.frameworkAdapter && await this.providers.frameworkAdapter.supports(request.project)) {
        const extracted = await this.providers.frameworkAdapter.extract(request.project);
        context = { ...context, ...extracted };
      }
      if (this.providers.staticAnalyzer) {
        const analysis = await this.providers.staticAnalyzer.analyze(request.project);
        context = { ...context, signals: [...context.signals, ...analysis.signals],
          evidence: [...context.evidence, ...analysis.evidence] };
      }
    }
    for (const workflow of request.workflows ?? []) {
      if (!context.identities.some(identity => identity.id === workflow.identityId)) {
        throw new Error(`Unknown workflow identity: ${workflow.identityId}`);
      }
      const observation = await this.providers.browser!.observe(context, workflow);
      context = { ...context,
        endpoints: [...context.endpoints, ...observation.endpoints],
        resources: [...context.resources, ...observation.resources],
        signals: [...context.signals, ...observation.signals],
        evidence: [...context.evidence, ...observation.evidence],
      };
    }
    validateEvidence(context);
    for (const signal of context.signals) {
      if (signal.projectId !== request.project.id) throw new Error('Signal project mismatch');
      validateReferences(signal.evidenceIds, context.evidence);
    }
    let hypotheses: readonly SecurityHypothesis[] = [];
    for (const plugin of this.plugins.values()) {
      const candidates = await plugin.detectCandidates(context);
      if (candidates.some(candidate => candidate.cweId !== plugin.cweId)) {
        throw new Error(`Plugin returned a different CWE: ${plugin.cweId}`);
      }
      hypotheses = [...hypotheses, ...candidates];
    }
    if (this.providers.reasoning) {
      hypotheses = await this.providers.reasoning.reviewHypotheses(context, hypotheses);
    }
    const hypothesisIds = new Set<string>();
    for (const hypothesis of hypotheses) {
      if (!this.plugins.has(hypothesis.cweId)) throw new Error(`No plugin for ${hypothesis.cweId}`);
      if (hypothesisIds.has(hypothesis.id)) throw new Error(`Duplicate hypothesis: ${hypothesis.id}`);
      hypothesisIds.add(hypothesis.id);
      if (hypothesis.projectId !== request.project.id || hypothesis.status !== 'HYPOTHESIS') {
        throw new Error('Invalid hypothesis project or status');
      }
      validateReferences(hypothesis.evidenceIds, context.evidence);
    }
    const plans: SecurityTestPlan[] = [];
    const results: SecurityTestResult[] = [];
    const findings: Finding[] = [];
    const remediation: RemediationSuggestion[] = [];
    for (const hypothesis of hypotheses) {
      const plugin = this.plugins.get(hypothesis.cweId)!;
      const generated = await plugin.generateTests(context, hypothesis);
      const hypothesisResults: SecurityTestResult[] = [];
      for (const plan of generated) {
        if (plan.hypothesisId !== hypothesis.id || plan.cweId !== hypothesis.cweId) {
          throw new Error('Plan does not match its hypothesis');
        }
        if (plans.some(existing => existing.id === plan.id)) throw new Error(`Duplicate plan: ${plan.id}`);
        if (plan.identityIds.some(id => !context.identities.some(identity => identity.id === id))) {
          throw new Error('Plan references an unknown identity');
        }
        plans.push(plan);
        const result = await this.execute(context, plan);
        if (result.planId !== plan.id) throw new Error('Result does not match its plan');
        if (results.some(existing => existing.id === result.id)) throw new Error(`Duplicate result: ${result.id}`);
        results.push(result);
        hypothesisResults.push(result);
        context = { ...context, evidence: [...context.evidence, ...result.evidence] };
        validateEvidence(context);
      }
      const finding = await plugin.evaluateEvidence(context, hypothesis, hypothesisResults);
      if (finding.hypothesisId !== hypothesis.id || finding.cweId !== hypothesis.cweId
        || finding.projectId !== request.project.id) throw new Error('Finding does not match its hypothesis');
      if (findings.some(existing => existing.id === finding.id)) throw new Error(`Duplicate finding: ${finding.id}`);
      validateReferences(finding.evidenceIds, context.evidence);
      if (finding.testPlanIds.some(id => !generated.some(plan => plan.id === id))) {
        throw new Error('Finding references an unrelated test plan');
      }
      if (finding.status === 'CONFIRMED' && finding.evidenceIds.length === 0) {
        throw new Error('Confirmed finding requires evidence');
      }
      findings.push(finding);
      if (request.suggestRemediation && finding.status === 'CONFIRMED') {
        const suggestion = await this.providers.remediation!.suggest(context, finding);
        if (suggestion.findingId !== finding.id) throw new Error('Remediation does not match its finding');
        validateReferences(suggestion.evidenceIds, context.evidence);
        remediation.push(suggestion);
      }
    }
    return { context, hypotheses, plans, results, findings, remediation };
  }

  private async execute(context: AnalysisContext, plan: SecurityTestPlan): Promise<SecurityTestResult> {
    const provider = plan.executor === 'browser' ? this.providers.browser : this.providers.scanner;
    if (!provider || plan.requiredCapabilities.some(capability => !provider.capabilities.includes(capability))) {
      return {
        id: `core:skipped:${plan.id}`, planId: plan.id, producerId: 'agento-core',
        outcome: 'SKIPPED', summary: 'No configured provider satisfies the required capabilities', evidence: [],
      };
    }
    try {
      return await provider.execute(context, plan);
    } catch {
      // Adapter errors may contain secrets/raw output; do not forward their messages.
      return {
        id: `core:failed:${plan.id}`, planId: plan.id, producerId: provider.id,
        outcome: 'FAILED', summary: 'Provider execution failed', evidence: [],
        error: { code: 'PROVIDER_EXECUTION_FAILED', message: 'Provider execution failed' },
      };
    }
  }
}

function validateReferences(ids: readonly string[], evidence: readonly Evidence[]): void {
  const known = new Set(evidence.map(item => item.id));
  for (const id of ids) if (!known.has(id)) throw new Error(`Unknown evidence reference: ${id}`);
}

function validateEvidence(context: AnalysisContext): void {
  const ids = new Set<string>();
  for (const evidence of context.evidence) {
    if (ids.has(evidence.id)) throw new Error(`Duplicate evidence: ${evidence.id}`);
    if (evidence.projectId !== context.project.id) throw new Error('Evidence project mismatch');
    ids.add(evidence.id);
  }
}

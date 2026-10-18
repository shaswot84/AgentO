import type {
  AnalysisContext, Component, CWEId, Endpoint, Evidence, Finding, Identity,
  Project, Resource, SecurityHypothesis, SecuritySignal, SecurityTestPlan, SecurityTestResult,
} from './domain.js';

export interface ProviderMetadata {
  readonly id: string;
  readonly capabilities: readonly string[];
}

export interface StaticAnalysis {
  readonly signals: readonly SecuritySignal[];
  readonly evidence: readonly Evidence[];
}

export interface StaticAnalyzer extends ProviderMetadata {
  analyze(project: Project): Promise<StaticAnalysis>;
}

export interface FrameworkAnalysis extends StaticAnalysis {
  readonly components: readonly Component[];
  readonly endpoints: readonly Endpoint[];
  readonly resources: readonly Resource[];
}

export interface FrameworkAdapter extends ProviderMetadata {
  supports(project: Project): Promise<boolean>;
  extract(project: Project): Promise<FrameworkAnalysis>;
}

export interface BrowserWorkflow {
  readonly id: string;
  readonly goal: string;
  readonly identityId: string;
}

export interface BrowserObservation {
  readonly endpoints: readonly Endpoint[];
  readonly resources: readonly Resource[];
  readonly signals: readonly SecuritySignal[];
  readonly evidence: readonly Evidence[];
}

export interface BrowserWorkflowDriver extends ProviderMetadata {
  observe(context: AnalysisContext, workflow: BrowserWorkflow): Promise<BrowserObservation>;
  execute(context: AnalysisContext, plan: SecurityTestPlan): Promise<SecurityTestResult>;
}

export interface SecurityScanner extends ProviderMetadata {
  execute(context: AnalysisContext, plan: SecurityTestPlan): Promise<SecurityTestResult>;
}

export interface CWEPlugin {
  readonly cweId: CWEId;
  detectCandidates(context: AnalysisContext): Promise<readonly SecurityHypothesis[]>;
  generateTests(context: AnalysisContext, hypothesis: SecurityHypothesis): Promise<readonly SecurityTestPlan[]>;
  evaluateEvidence(context: AnalysisContext, hypothesis: SecurityHypothesis,
    results: readonly SecurityTestResult[]): Promise<Finding>;
}

/** Builds structured plans; implementations must omit drafts with unmet planning prerequisites. */
export interface TestPlanner {
  generateTests(context: AnalysisContext, hypothesis: SecurityHypothesis): Promise<readonly SecurityTestPlan[]>;
}

/** Implementations return structured, evidence-referenced hypotheses, never executable prose. */
export interface ReasoningModel extends ProviderMetadata {
  reviewHypotheses(context: AnalysisContext,
    hypotheses: readonly SecurityHypothesis[]): Promise<readonly SecurityHypothesis[]>;
}

export interface RemediationSuggestion {
  readonly findingId: string;
  readonly explanation: string;
  readonly patch?: string;
  readonly regressionTest?: string;
  readonly evidenceIds: readonly string[];
}

/** Suggestions only; applying patches is outside this contract. */
export interface RemediationProvider extends ProviderMetadata {
  suggest(context: AnalysisContext, finding: Finding): Promise<RemediationSuggestion>;
}

export interface ScanRequest {
  readonly project: Project;
  readonly identities: readonly Identity[];
  readonly workflows?: readonly BrowserWorkflow[];
  readonly suggestRemediation?: boolean;
}

import type {
  AnalysisContext, Component, CWEId, Endpoint, Evidence, Finding, Identity,
  Project, Resource, SecurityHypothesis, SecuritySignal, SecurityTestPlan, SecurityTestResult,
} from './domain.js';

export interface ProviderMetadata {
  readonly id: string;
  readonly capabilities: readonly string[];
}

/** Host attribution at the evidence boundary, independent of vendor objects. */
export interface EvidenceCaptureContext {
  readonly project: Project;
  readonly capabilityIds: readonly string[];
  readonly probeId?: string;
  readonly targetUrl?: string;
  readonly environmentId?: string;
}

/** Synchronous, append-only retention. Implementations must redact, copy, and deeply freeze records. */
export interface EvidenceStore {
  capture(evidence: readonly Evidence[], context: EvidenceCaptureContext): readonly Evidence[];
  get(id: string): Evidence | undefined;
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
  readonly discovery?: EndpointDiscoveryReport;
}

export interface EndpointDiscoveryDiagnostic {
  readonly code: 'tool-unavailable' | 'tool-version' | 'tool-failed' | 'tool-timeout' | 'tool-output-limit'
    | 'cancelled' | 'invalid-output' | 'invalid-endpoint' | 'invalid-source' | 'source-selection';
  readonly message: string;
}

/** A completed invocation does not assert complete application coverage. */
export interface EndpointDiscoveryReport {
  readonly providerId: string;
  readonly status: 'completed' | 'partial' | 'unavailable' | 'failed';
  readonly diagnostics: readonly EndpointDiscoveryDiagnostic[];
}

/** Providers return AgentO records only. Vendor output and execution capabilities stay outside this port. */
export interface EndpointDiscoveryProvider extends ProviderMetadata {
  discover(project: Project, options?: { readonly signal?: AbortSignal }): Promise<FrameworkAnalysis & {
    readonly discovery: EndpointDiscoveryReport;
  }>;
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

/** Optional final evidence gate. Implementations must ground verdicts in retained runtime proof. */
export interface VerificationEngine {
  verify(context: AnalysisContext, hypothesis: SecurityHypothesis, plans: readonly SecurityTestPlan[],
    results: readonly SecurityTestResult[]): Promise<Finding>;
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

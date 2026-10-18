/** Deliberate public projection. Never send raw plans, scope, bindings or sessions. */
export interface InvestigationEvidence {
  readonly id: string;
  readonly kind: string;
  readonly producerId: string;
  readonly capturedAt: string;
  readonly summary: string;
}

export interface InvestigationHypothesis {
  readonly id: string;
  readonly cweId: string;
  readonly title: string;
  readonly reason: string;
  readonly origin: 'deterministic' | 'model-assisted';
  readonly endpoint: { readonly method: string; readonly path: string } | null;
  readonly supports: readonly { readonly statement: string; readonly evidenceIds: readonly string[] }[];
  readonly evidence: readonly InvestigationEvidence[];
  readonly limitations: readonly string[];
}

export interface InvestigationPlan {
  readonly id: string;
  readonly hypothesisId: string;
  readonly cweId: string;
  readonly title: string;
  readonly probeId: string;
  readonly readiness: 'READY' | 'BLOCKED';
  readonly testedInput?: { readonly name: string; readonly location: string };
  readonly prerequisites: readonly { readonly code: string; readonly parameter?: { readonly name: string; readonly location: string } }[];
  readonly requiredCapabilities: readonly string[];
  readonly optionalCapabilities: readonly string[];
  readonly steps: readonly { readonly id: string; readonly action: string; readonly dependsOn: readonly string[]; readonly expectedObservation: string }[];
  readonly verification: { readonly strategy: string; readonly evidenceRequirements: readonly string[] };
  readonly limitations: readonly string[];
  readonly execution: 'not-run';
}

export interface InvestigationCoverage {
  readonly cweId: string;
  readonly title: string;
  readonly probeId: string;
  readonly requiredCapabilities: readonly string[];
  readonly optionalCapabilities: readonly string[];
}

export interface InvestigationSnapshot {
  readonly projectId: string;
  readonly sourceType: 'demo-fixture' | 'execution-api';
  readonly state: 'empty' | 'ready' | 'partial' | 'stale' | 'unavailable';
  readonly generatedAt: string | null;
  readonly sourceUpdatedAt: string | null;
  readonly sourceState: 'empty' | 'ready' | 'partial' | 'stale';
  readonly hypotheses: readonly InvestigationHypothesis[];
  readonly plans: readonly InvestigationPlan[];
  readonly coverage: readonly InvestigationCoverage[];
  readonly diagnostics: readonly string[];
  readonly modelReview: 'disabled';
  readonly execution: 'not-configured';
}

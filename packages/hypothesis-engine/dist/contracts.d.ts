import type { CWEId, CWEPlugin, Evidence, ModelProvider, ModelUsage, Resource, SecurityHypothesis, SecuritySignal } from '@agento/core';
import type { ApplicationSecurityModel, ModelEndpoint, ModelFact } from '@agento/security-model';
export interface HypothesisSupport {
    readonly id: string;
    readonly kind: string;
    /** Trusted rule text describing observations, never a vulnerability verdict. */
    readonly statement: string;
    readonly evidenceIds: readonly string[];
    readonly strength: 'candidate' | 'context';
}
export interface HypothesisContext {
    readonly model: ApplicationSecurityModel;
    readonly candidate: SecurityHypothesis;
    readonly endpoint: ModelEndpoint;
    readonly facts: readonly ModelFact[];
    readonly signals: readonly SecuritySignal[];
    readonly resources: readonly Resource[];
    readonly evidence: readonly Evidence[];
}
/** Rules reason over public observations. They never collect evidence or execute tests. */
export interface HypothesisContextRule {
    readonly cweId: CWEId;
    gather(context: HypothesisContext): readonly HypothesisSupport[];
}
export interface GroundedHypothesis extends SecurityHypothesis {
    readonly origin: 'deterministic' | 'model-assisted';
    readonly rationale: readonly HypothesisSupport[];
    readonly limitations: readonly string[];
}
export interface HypothesisDiagnostic {
    readonly code: 'invalid-candidate' | 'unsupported-cwe' | 'rule-failed' | 'candidate-provider-failed' | 'candidate-limit' | 'context-limit' | 'hypothesis-limit' | 'model-input-limit' | 'model-context-limit' | 'model-output-limit' | 'model-failed' | 'model-timeout' | 'model-refused' | 'invalid-model-output' | 'model-token-limit';
}
export interface HypothesisResult {
    readonly hypotheses: readonly GroundedHypothesis[];
    readonly diagnostics: readonly HypothesisDiagnostic[];
    readonly review: 'disabled' | 'skipped' | 'completed' | 'failed';
    readonly usage: {
        readonly modelCalls: number;
        readonly tokens: ModelUsage;
    };
}
export interface HypothesisLimits {
    readonly maxCandidates?: number;
    readonly maxHypotheses?: number;
    readonly maxSupportsPerCandidate?: number;
    readonly maxInputChars?: number;
    readonly maxOutputChars?: number;
    readonly maxOutputTokens?: number;
    readonly maxTotalTokens?: number;
    readonly timeoutMs?: number;
}
export interface HypothesisEngineOptions {
    readonly plugins: readonly Pick<CWEPlugin, 'cweId' | 'detectCandidates'>[];
    readonly provider?: ModelProvider;
    /** Replaces the default context rules; register custom CWEs here and in plugins. */
    readonly rules?: readonly HypothesisContextRule[];
    readonly sensitiveCookieNames?: readonly string[];
    readonly untrustedOrigins?: readonly string[];
    readonly limits?: HypothesisLimits;
}

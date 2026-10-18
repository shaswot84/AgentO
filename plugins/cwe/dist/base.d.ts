import type { AnalysisContext, CWEId, Finding, SecurityHypothesis, SecurityTestResult } from '@agento/core';
import type { CWEMetadata, CWEHypothesis, CWEPlugin, CWEVerdict, EvaluationScope, NormalizedProbeEvidence, ProbeEvidenceCatalog, ProbeTestPlan, RuleOptions } from './contracts.js';
import { type CandidateContext } from './candidates.js';
import { type Decision } from './shared.js';
export declare abstract class EvidenceCWEPlugin<P extends keyof ProbeEvidenceCatalog> implements CWEPlugin {
    readonly cweId: CWEId;
    private readonly definition;
    private readonly options;
    protected constructor(metadata: CWEMetadata & {
        readonly probeId: P;
    }, options?: RuleOptions);
    metadata(): CWEMetadata;
    detectCandidates(context: AnalysisContext): Promise<readonly CWEHypothesis[]>;
    generateTests(hypothesis: CWEHypothesis): Promise<readonly ProbeTestPlan[]>;
    generateTests(context: AnalysisContext, hypothesis: SecurityHypothesis): Promise<readonly ProbeTestPlan[]>;
    evaluate(evidence: readonly NormalizedProbeEvidence[], scope: EvaluationScope): Promise<CWEVerdict>;
    protected abstract interpret(evidence: ProbeEvidenceCatalog[P], scope: EvaluationScope): Decision;
    protected abstract isCandidate(candidate: CandidateContext): boolean;
    evaluateEvidence(context: AnalysisContext, supplied: SecurityHypothesis, results: readonly SecurityTestResult[]): Promise<Finding>;
    private bind;
}

import { detect, referencesMatch } from './candidates.js';
import { fromCoreEvidence, isProbeEvidence } from './evidence.js';
import { freeze, identifier, unknown, url } from './shared.js';
export class EvidenceCWEPlugin {
    cweId;
    definition;
    options;
    constructor(metadata, options = {}) {
        this.cweId = metadata.cweId;
        this.definition = freeze(structuredClone(metadata));
        this.options = freeze(structuredClone(options));
    }
    metadata() { return this.definition; }
    async detectCandidates(context) {
        return detect(this.definition, context, this.options, candidate => this.isCandidate(candidate));
    }
    async generateTests(contextOrHypothesis, supplied) {
        const hypothesis = supplied ? this.bind(contextOrHypothesis, supplied) : contextOrHypothesis;
        if (hypothesis.cweId !== this.cweId || hypothesis.status !== 'HYPOTHESIS'
            || hypothesis.projectId !== hypothesis.scope?.projectId)
            throw new Error('Invalid rule hypothesis');
        url(hypothesis.scope.targetUrl);
        const scope = structuredClone(hypothesis.scope);
        const injection = this.definition.probeId === 'xss' || this.definition.probeId === 'sql-injection';
        if (!(injection ? ['GET', 'POST'] : ['GET', 'HEAD']).includes(scope.method) || injection && !scope.parameter)
            return [];
        const policy = scope.authorization;
        const identityIds = policy ? [policy.ownerIdentityId, policy.attackerIdentityId] : [...(scope.identityIds ?? [])];
        const authentication = identityIds.length && this.definition.probeId !== 'authorization'
            ? ['authentication-manager', ...(this.definition.probeId === 'cookie-security' ? ['cookie-inspector'] : [])] : [];
        return freeze([{
                id: `plan:${identifier(hypothesis.id, this.definition.probeId)}`, hypothesisId: hypothesis.id, cweId: this.cweId,
                // Existing core's tool-neutral execution port. A host must explicitly supply a probe-capable provider.
                executor: 'scanner', probeId: this.definition.probeId, scope,
                requiredCapabilities: [...new Set([`probe:${this.definition.probeId}`, ...this.definition.requiredCapabilities, ...authentication])],
                risk: ['cookie-security', 'authorization'].includes(this.definition.probeId) ? 'passive' : 'active',
                targetUrl: scope.targetUrl, identityIds,
                steps: [{ id: 'collect', action: 'probe.collect', parameters: {
                            probeId: this.definition.probeId, scope: JSON.parse(JSON.stringify(scope)),
                        }, expectedObservation: 'Normalized observations bound to this target and investigation.' }],
            }]);
    }
    async evaluate(evidence, scope) {
        const records = new Map();
        const conflicts = new Set();
        for (const item of evidence) {
            if (!isProbeEvidence(item) || item.projectId !== scope.projectId || item.probeId !== this.definition.probeId)
                continue;
            const previous = records.get(item.id);
            if (previous && JSON.stringify(previous) !== JSON.stringify(item))
                conflicts.add(item.id);
            records.set(item.id, item);
        }
        const decisions = [...records.values()].filter(item => !conflicts.has(item.id)).map(item => ({ item,
            decision: this.interpret(item, scope) }));
        const positives = decisions.filter(({ decision }) => decision.status === 'CONFIRMED');
        const negatives = decisions.filter(({ decision }) => decision.status === 'REJECTED');
        const inconclusive = decisions.filter(({ decision }) => decision.status === 'NOT_REPRODUCED');
        let decision = positives[0]?.decision ?? inconclusive[0]?.decision ?? negatives[0]?.decision
            ?? unknown('No usable evidence for this rule and target.');
        if (!positives.length && (conflicts.size || negatives.length && inconclusive.length)) {
            decision = unknown('Evidence is conflicting or incomplete; the vulnerability was not established.');
        }
        const selected = positives.length ? positives : decisions;
        const limitations = [...new Set([...(decision.limitations ?? []),
                ...selected.flatMap(({ item, decision }) => [...(decision.limitations ?? []),
                    ...(item.outcome === 'PARTIAL' ? ['Probe coverage is partial.'] : [])]),
                ...(conflicts.size ? ['Conflicting evidence IDs were excluded.'] : [])])];
        return freeze({ cweId: this.cweId, status: decision.status,
            confidence: decision.status === 'CONFIRMED' ? 'high' : decision.status === 'REJECTED' ? 'medium' : 'low',
            summary: decision.summary, evidenceIds: selected.map(({ item }) => item.id).sort(), limitations });
    }
    async evaluateEvidence(context, supplied, results) {
        const hypothesis = this.bind(context, supplied);
        const plans = await this.generateTests(context, supplied);
        const ids = new Set(plans.map(plan => plan.id));
        const accepted = results.filter(result => ids.has(result.planId));
        const records = accepted.filter(result => result.outcome === 'COMPLETED').flatMap(result => result.evidence)
            .filter(item => item.projectId === context.project.id && referencesMatch(item, hypothesis.endpointId, context))
            .flatMap(item => { const probe = fromCoreEvidence(item); return probe ? [probe] : []; });
        const verdict = await this.evaluate(records, hypothesis.scope);
        return freeze({ id: `finding:${identifier(hypothesis.id, this.cweId)}`, projectId: context.project.id,
            hypothesisId: hypothesis.id, cweId: this.cweId, owaspCategory: this.definition.owaspCategory,
            title: this.definition.title, status: verdict.status, severity: this.definition.severity,
            confidence: verdict.confidence, rootCause: verdict.summary,
            ...(hypothesis.endpointId ? { endpointId: hypothesis.endpointId } : {}),
            ...(hypothesis.source ? { source: hypothesis.source } : {}), evidenceIds: verdict.evidenceIds,
            testPlanIds: [...new Set(accepted.map(result => result.planId))] });
    }
    bind(context, hypothesis) {
        if (hypothesis.projectId !== context.project.id || hypothesis.cweId !== this.cweId || hypothesis.status !== 'HYPOTHESIS') {
            throw new Error('Invalid rule hypothesis');
        }
        // Reconstruct policy and target from current application knowledge instead of trusting added JSON fields.
        const known = detect(this.definition, context, this.options, candidate => this.isCandidate(candidate)).find(candidate => candidate.id === hypothesis.id);
        if (!known || known.endpointId !== hypothesis.endpointId)
            throw new Error('Unknown rule hypothesis');
        return known;
    }
}

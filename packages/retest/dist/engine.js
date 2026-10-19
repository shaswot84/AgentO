import { randomUUID } from 'node:crypto';
import { fromCoreEvidence, toCoreEvidence } from '@agento/cwe';
import { RetestError } from './contracts.js';
import { canonical, checkedRecord, freeze, loopbackOrigin, sha256 } from './value.js';
/** No execution occurs until the original finding, retained proof, plan and patch bindings pass. */
export class RetestEngine {
    #options;
    constructor(options) {
        if (!options?.evidenceStore?.get || !options.evidenceStore.capture || !options.environment?.create
            || !Array.isArray(options.rules) || !options.rules.length
            || new Set(options.rules.map(rule => rule.cweId)).size !== options.rules.length
            || !Number.isSafeInteger(options.timeoutMs ?? 60_000) || (options.timeoutMs ?? 60_000) < 1
            || (options.timeoutMs ?? 60_000) > 300_000)
            throw new RetestError('invalid-options');
        this.#options = { ...options, rules: [...options.rules] };
    }
    async run(input, signal) {
        let snapshot;
        try {
            snapshot = freeze(structuredClone(input));
        }
        catch {
            throw new RetestError('invalid-input');
        }
        let before;
        try {
            before = await this.#validate(snapshot);
        }
        catch (error) {
            if (error instanceof RetestError)
                throw error;
            throw new RetestError('invalid-input');
        }
        const { context, finding, plan, remediation } = snapshot;
        const id = `retest:${randomUUID()}`;
        const controller = new AbortController();
        const abort = () => controller.abort();
        signal?.addEventListener('abort', abort, { once: true });
        if (signal?.aborted)
            abort();
        const timer = setTimeout(abort, this.#options.timeoutMs ?? 60_000);
        let session, afterIds = [], status = 'FIX_INCONCLUSIVE';
        let regression = { security: 'NOT_RUN', normalFlow: 'NOT_RUN' };
        let reason = 'execution-failed', environmentId = id, targetUrl = plan.targetUrl;
        try {
            if (controller.signal.aborted)
                throw new Error();
            // Host callbacks must honor cancellation and settle after terminating their work.
            session = await this.#options.environment.create(snapshot, controller.signal);
            if (controller.signal.aborted)
                throw new Error();
            const origin = loopbackOrigin(session.baseUrl);
            if (!session.id || session.id === before[0].provenance.environment.id)
                throw new Error();
            environmentId = session.id;
            const target = new URL(plan.targetUrl);
            targetUrl = origin + target.pathname + target.search;
            regression = freeze(structuredClone(await session.runRegression(controller.signal)));
            if (!['PASSED', 'FAILED', 'NOT_RUN'].includes(regression.security)
                || !['PASSED', 'FAILED', 'NOT_RUN'].includes(regression.normalFlow) || controller.signal.aborted)
                throw new Error();
            const probe = freeze(structuredClone(await session.replay(plan, targetUrl, controller.signal)));
            if (controller.signal.aborted || !fromCoreEvidence(toCoreEvidence(probe)) || probe.projectId !== finding.projectId
                || probe.probeId !== plan.probeId || !before.some(record => replayBinding(fromCoreEvidence(record)) === replayBinding(probe))
                || !probeTargets(probe).length || probeTargets(probe).some(url => !sameEndpoint(url, targetUrl)))
                throw new Error();
            const publicProbe = fromCoreEvidence(toCoreEvidence({ ...probe, id: `${id}:probe` }));
            const records = this.#options.evidenceStore.capture([toCoreEvidence(publicProbe, finding.endpointId)], {
                project: { ...context.project, baseUrl: origin, allowedOrigins: [origin] },
                targetUrl, environmentId, probeId: plan.probeId, capabilityIds: plan.requiredCapabilities,
            });
            afterIds = records.map(record => record.id);
            const retainedProbe = fromCoreEvidence(checkedRecord(records[0]));
            if (!retainedProbe || retainedProbe.outcome !== 'COMPLETED' || retainedProbe.diagnostics.length)
                throw new Error();
            const verdict = await this.#options.rules.find(rule => rule.cweId === finding.cweId).evaluate([retainedProbe], { ...plan.scope, targetUrl });
            if (verdict.status === 'CONFIRMED') {
                status = 'FIX_FAILED';
                reason = 'exploit-reproduced';
            }
            else if ((verdict.status === 'REJECTED' || blockedSqlControls(before.map(record => fromCoreEvidence(record)), retainedProbe)) && regression.security === 'PASSED' && regression.normalFlow === 'PASSED'
                && healthy(retainedProbe)) {
                status = 'FIX_VERIFIED';
                reason = 'exploit-blocked-normal-flow-passed';
            }
            else
                reason = 'insufficient-proof-or-regression-failed';
            if (controller.signal.aborted) {
                status = 'FIX_INCONCLUSIVE';
                reason = 'cancelled-or-timeout';
            }
        }
        catch {
            reason = controller.signal.aborted ? 'cancelled-or-timeout' : 'execution-failed';
            status = 'FIX_INCONCLUSIVE';
        }
        finally {
            try {
                await session?.dispose();
            }
            catch {
                status = 'FIX_INCONCLUSIVE';
                reason = 'cleanup-failed';
            }
            clearTimeout(timer);
            signal?.removeEventListener('abort', abort);
        }
        if (controller.signal.aborted) {
            status = 'FIX_INCONCLUSIVE';
            reason = 'cancelled-or-timeout';
        }
        // Retain a comparative record only after cleanup. Existing finding and records never change.
        const beforeIds = before.map(record => record.id);
        const comparison = { id: `${id}:comparison`, projectId: finding.projectId,
            kind: 'configuration', producerId: 'retest-engine', capturedAt: new Date().toISOString(),
            summary: 'Original probe and isolated repair comparison.',
            ...(finding.endpointId === undefined ? {} : { endpointId: finding.endpointId }),
            facts: { observation: 'fix-verification', retestId: id, findingId: finding.id, cweId: finding.cweId, planId: plan.id,
                status, reason, beforeEvidenceIds: beforeIds, afterEvidenceIds: afterIds,
                patchSha256: sha256(remediation.patch), regressionTestSha256: sha256(remediation.regressionTest),
                originalPlanSha256: sha256(canonical(plan)), securityRegression: regression.security, normalFlow: regression.normalFlow,
                beforeDigests: before.map(record => record.digest) } };
        this.#options.evidenceStore.capture([comparison], { project: context.project, targetUrl,
            environmentId, probeId: 'fix-verification', capabilityIds: ['isolated-patch', 'regression-test', plan.probeId] });
        return freeze({ id, findingId: finding.id, projectId: finding.projectId, cweId: finding.cweId, status,
            comparisonEvidenceId: comparison.id, beforeEvidenceIds: beforeIds, afterEvidenceIds: afterIds });
    }
    async #validate({ context, finding, plan, originalResult, remediation }) {
        if (!context?.project || !finding || finding.status !== 'CONFIRMED')
            throw new RetestError('not-confirmed');
        const rule = this.#options.rules.find(rule => rule.cweId === finding.cweId);
        if (!rule || finding.projectId !== context.project.id || !finding.evidenceIds.length
            || plan.hypothesisId !== finding.hypothesisId || plan.cweId !== finding.cweId || !finding.testPlanIds.includes(plan.id)
            || plan.probeId !== rule.metadata().probeId || plan.scope.projectId !== finding.projectId
            || plan.scope.targetUrl !== plan.targetUrl || new URL(plan.targetUrl).origin !== new URL(context.project.baseUrl).origin
            || !context.project.allowedOrigins.includes(new URL(plan.targetUrl).origin)
            || originalResult.planId !== plan.id || originalResult.outcome !== 'COMPLETED' || originalResult.error
            || !originalResult.evidence.length || remediation.findingId !== finding.id || remediation.validation !== 'NOT_RUN'
            || remediation.status !== 'SUGGESTED' || typeof remediation.patch !== 'string' || !remediation.patch
            || typeof remediation.regressionTest !== 'string' || !remediation.regressionTest
            || canonical([...remediation.evidenceIds].sort()) !== canonical([...finding.evidenceIds].sort())
            || rule.metadata().requiredCapabilities.some(id => !plan.requiredCapabilities.includes(id)))
            throw new RetestError('invalid-input');
        const records = new Map(context.evidence.map(item => [item.id, item]));
        if (records.size !== context.evidence.length)
            throw new RetestError('invalid-input');
        const resolve = (supplied) => {
            const stored = this.#options.evidenceStore.get(supplied.id);
            if (!stored || canonical(stored) !== canonical(supplied) || canonical(records.get(supplied.id)) !== canonical(stored))
                throw new RetestError('unrelated-evidence');
            const record = checkedRecord(stored);
            if (record.projectId !== finding.projectId)
                throw new RetestError('unrelated-evidence');
            return record;
        };
        for (const id of [...finding.evidenceIds, ...remediation.sourceEvidenceIds]) {
            const record = records.get(id);
            if (!record)
                throw new RetestError('unrelated-evidence');
            resolve(record);
        }
        const before = originalResult.evidence.map(resolve);
        if (new Set(before.map(item => item.id)).size !== before.length)
            throw new RetestError('unrelated-evidence');
        const probes = before.map(record => {
            const probe = fromCoreEvidence(record);
            if (!finding.evidenceIds.includes(record.id) || !probe || probe.probeId !== plan.probeId
                || probe.outcome !== 'COMPLETED' || probe.diagnostics.length || record.endpointId !== finding.endpointId
                || record.provenance.probeId !== plan.probeId || !sameEndpoint(record.provenance.environment.targetUrl, plan.targetUrl)
                || record.provenance.environment.baseUrl !== context.project.baseUrl
                || plan.requiredCapabilities.some(id => !record.provenance.capabilityIds.includes(id))
                || probeTargets(probe).some(url => !sameEndpoint(url, plan.targetUrl)))
                throw new RetestError('unrelated-evidence');
            return probe;
        });
        const verdict = await rule.evaluate(probes, plan.scope);
        if (verdict.status !== 'CONFIRMED')
            throw new RetestError('not-confirmed');
        return before;
    }
}
function sameEndpoint(a, b) {
    const left = new URL(a), right = new URL(b);
    return left.origin === right.origin && left.pathname === right.pathname;
}
export function probeTargets(probe) {
    switch (probe.probeId) {
        case 'authorization': {
            const p = probe;
            return [p.owner.url, p.attacker.url, p.anonymous.url];
        }
        case 'cookie-security': return probe.observations.map(item => item.response.url);
        case 'cross-origin': return probe.observations.flatMap(item => [item.preflight.response.url, item.actual.response.url]);
        case 'xss': {
            const p = probe;
            return [p.baseline.url, p.injected.url, ...(p.browser ? [p.browser.url] : [])];
        }
        case 'sql-injection': {
            const p = probe;
            return [p.baseline.url, ...p.observations.map(item => item.response.url)];
        }
        default: return [];
    }
}
function healthy(probe) {
    const success = (item) => item.status >= 200 && item.status < 300;
    switch (probe.probeId) {
        case 'authorization': return success(probe.owner);
        case 'cookie-security': {
            const p = probe;
            return p.observations.length > 0 && p.observations.every(item => success(item.response));
        }
        case 'cross-origin': {
            const p = probe;
            return p.observations.length > 0 && p.observations.every(item => success(item.actual.response));
        }
        case 'xss': {
            const p = probe;
            return [p.baseline, p.injected].every(success);
        }
        case 'sql-injection': {
            const p = probe;
            return [p.baseline, ...p.observations.map(item => item.response)].every(success);
        }
        default: return false;
    }
}
/** The original true/false SQL proof disappears when both literal mutations return the same result set.
 * Detection rules need not reinterpret this as a general negative: this is paired fix verification only. */
function blockedSqlControls(before, after) {
    if (after.probeId !== 'sql-injection')
        return false;
    const probe = after, controls = probe.projectedControls;
    const variants = new Set(probe.observations.map(item => item.variant));
    if (!controls || variants.size !== 3 || probe.observations.length !== 3 || probe.scanner?.observedDifference !== false
        || controls.trueControl !== controls.falseControl || controls.trueControl !== sha256('[]') || probe.observations.some(item => item.errorIndicators.length
        || item.response.body.truncated) || probe.baseline.body.truncated)
        return false;
    return before.some(item => {
        if (item.probeId !== 'sql-injection')
            return false;
        const original = item, prior = original.projectedControls;
        return prior && prior.pointer === controls.pointer && prior.baseline === controls.baseline && original.parameter.name === probe.parameter.name
            && original.parameter.location === probe.parameter.location && prior.baseline === prior.trueControl
            && prior.trueControl !== prior.falseControl;
    });
}
/** Check retained public input bindings too; private values remain the trusted replay port's responsibility. */
function replayBinding(probe) {
    switch (probe.probeId) {
        case 'authorization': {
            const p = probe;
            return canonical([p.probeId, p.resourceId, p.ownerIdentityId, p.attackerIdentityId]);
        }
        case 'cookie-security': {
            const p = probe;
            return canonical([p.probeId, p.observations.map(item => [item.context, item.identityId]).sort()]);
        }
        case 'cross-origin': {
            const p = probe;
            return canonical([p.probeId, p.observations.map(item => [item.requestedOrigin, item.identityId, item.credentialMode]).sort()]);
        }
        case 'xss': {
            const p = probe;
            return canonical([p.probeId, p.parameter, p.canary]);
        }
        case 'sql-injection': {
            const p = probe;
            return canonical([p.probeId, p.parameter, p.projectedControls?.pointer ?? null, p.observations.map(item => item.variant).sort()]);
        }
        default: return '';
    }
}

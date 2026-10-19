import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, randomUUID } from 'node:crypto';
import { bindCapabilities } from './bindings.js';
import { PolicyError } from './contracts.js';
import { configuration, freeze, identifier, origins, parseUrl, risks, severities } from './validation.js';
/** Local policy authority. Approval methods and adapter registrations belong to the trusted host. */
export class PolicyEngine {
    options;
    config;
    records = [];
    pending = new Map();
    approvals = new Map();
    requests = [];
    toolContext = new AsyncLocalStorage();
    lastTime = -Infinity;
    constructor(config, options = {}) {
        this.options = options;
        this.config = configuration(config);
    }
    audit() { return freeze([...this.records]); }
    review(request, selection) {
        this.prune();
        const checked = this.check(request, selection);
        const required = checked.code === 'allowed' && this.needsApproval(checked);
        const decision = this.record({ operation: 'plan', outcome: required ? 'APPROVAL_REQUIRED' : checked.code === 'allowed' ? 'ALLOW' : 'DENY',
            code: required ? 'approval-required' : checked.code, risk: checked.risk, severity: checked.severity,
            ...(checked.digest ? { planFingerprint: checked.digest } : {}),
            ...(checked.origin ? { origin: checked.origin } : {}) });
        if (required)
            this.pending.set(decision.id, { digest: checked.digest, expiresAt: this.time() + this.config.approval.ttlMs });
        return decision;
    }
    /** Call only after a human accepts the reviewed plan. No target-supplied approval data is accepted. */
    approve(decisionId, approverId) {
        this.prune();
        const pending = this.pending.get(decisionId);
        if (!pending || !identifier(approverId)) {
            this.record({ operation: 'approval', outcome: 'DENY', code: 'approval-invalid', risk: 'active', severity: 'medium' });
            throw new PolicyError('approval-invalid');
        }
        const decision = this.records.find(item => item.id === decisionId);
        const token = `approval:${randomUUID()}`;
        this.record({ operation: 'approval', outcome: 'ALLOW', code: 'allowed', risk: decision.risk, severity: decision.severity,
            reviewId: decisionId, planFingerprint: pending.digest, reviewerHash: createHash('sha256').update(approverId).digest('hex') });
        this.pending.delete(decisionId);
        this.approvals.set(token, pending);
        return token;
    }
    revokeApproval(approvalId) { this.approvals.delete(approvalId); }
    async run(request, resolution, execute, options = {}) {
        this.prune();
        // Snapshot before any callback can change the plan, target or selected tool set.
        let input, selection;
        try {
            input = structuredClone(request);
            selection = structuredClone(resolution.report);
        }
        catch {
            this.deny('invalid-request');
        }
        const checked = this.check(input, selection);
        const reject = (code) => this.deny(code, checked);
        if (checked.code !== 'allowed')
            reject(checked.code);
        if (!resolution.capabilities)
            reject('selection-unavailable');
        for (const selected of selection.selections)
            if (selected.selectedToolId && !resolution.capabilities.has(selected.capability))
                reject('selection-unavailable');
        if (options.signal?.aborted)
            reject('cancelled');
        if (this.needsApproval(checked)) {
            const approval = options.approvalId ? this.approvals.get(options.approvalId) : undefined;
            if (!approval || approval.digest !== checked.digest || approval.expiresAt <= this.time())
                reject(options.approvalId ? 'approval-invalid' : 'approval-required');
            this.approvals.delete(options.approvalId); // One execution only.
        }
        const executionId = `execution:${randomUUID()}`, deadline = this.time() + this.config.executionTtlMs;
        const controller = new AbortController();
        const cancel = () => controller.abort();
        options.signal?.addEventListener('abort', cancel, { once: true });
        const timer = setTimeout(cancel, this.config.executionTtlMs);
        timer.unref();
        let active = true, count = 0;
        const toolCounts = new Map();
        const decision = (operation, code, fields = {}) => {
            const record = this.record({ ...fields, executionId, planFingerprint: checked.digest, operation, code, outcome: code === 'allowed' ? 'ALLOW' : 'DENY',
                risk: checked.risk, severity: checked.severity });
            if (code !== 'allowed')
                throw new PolicyError(record.code);
        };
        const assertActive = () => {
            if (!active || this.time() >= deadline)
                decision('execution', 'execution-closed');
            if (controller.signal.aborted)
                decision('execution', 'cancelled');
        };
        const validate = (value, toolIds, method) => {
            let url;
            try {
                url = parseUrl(value);
            }
            catch {
                decision('request', 'target-denied');
                throw new PolicyError('target-denied');
            }
            if (url.origin !== checked.origin)
                decision('request', 'target-denied', { origin: url.origin });
            for (const toolId of toolIds) {
                const rule = this.config.tools[toolId];
                if (!rule || rule.allowedOrigins && !rule.allowedOrigins.includes(url.origin))
                    decision('request', 'tool-denied', { toolId });
                if (method && rule.allowedMethods && !rule.allowedMethods.includes(method))
                    decision('request', 'method-denied', { toolId });
            }
            if (method && !this.config.allowedMethods.includes(method))
                decision('request', 'method-denied');
            return url;
        };
        const guardFor = (toolId) => {
            if (!checked.toolIds.includes(toolId))
                reject('tool-denied');
            return Object.freeze({ assertActive, signal: controller.signal,
                assertRequest: ({ url, method }) => {
                    assertActive();
                    if (typeof method !== 'string' || !this.config.allowedMethods.includes(method))
                        decision('request', 'method-denied', { toolId });
                    const ids = [...new Set([toolId, ...(this.toolContext.getStore() ? [this.toolContext.getStore()] : [])])];
                    const target = validate(url, ids, method);
                    const now = this.time();
                    let expired = 0;
                    while (expired < this.requests.length && this.requests[expired] <= now - this.config.rateLimit.windowMs)
                        expired++;
                    if (expired)
                        this.requests.splice(0, expired);
                    if (this.requests.length >= this.config.rateLimit.maxRequests)
                        decision('request', 'rate-limited', { toolId });
                    if (count >= this.config.maxRequestsPerExecution || ids.some(id => (toolCounts.get(id) ?? 0) >= this.config.tools[id].maxRequests))
                        decision('request', 'request-limit', { toolId });
                    decision('request', 'allowed', { toolId, origin: target.origin, method });
                    this.requests.push(now);
                    count++;
                    for (const id of ids)
                        toolCounts.set(id, (toolCounts.get(id) ?? 0) + 1);
                },
                assertRedirect: (from, destination) => {
                    assertActive();
                    try {
                        const ids = [...new Set([toolId, ...(this.toolContext.getStore() ? [this.toolContext.getStore()] : [])])];
                        const source = validate(from, ids);
                        validate(parseUrl(destination, source.href).href, ids);
                    }
                    catch {
                        decision('redirect', 'redirect-denied', { toolId });
                    }
                    decision('redirect', 'allowed', { toolId });
                },
            });
        };
        let binding;
        let abortWait;
        try {
            assertActive();
            binding = bindCapabilities({ ...resolution, report: selection }, { guardFor, signal: controller.signal,
                allowedOrigins: [checked.origin], tool: (toolId, operation) => {
                    assertActive();
                    decision('tool', 'allowed', { toolId });
                    return this.toolContext.run(toolId, operation);
                } });
            decision('execution', 'allowed', { stage: 'start' });
            const aborted = new Promise((_resolve, reject) => {
                abortWait = () => {
                    try {
                        decision('execution', this.time() >= deadline ? 'execution-closed' : 'cancelled');
                    }
                    catch (error) {
                        reject(error);
                    }
                };
                controller.signal.addEventListener('abort', abortWait, { once: true });
            });
            const result = await Promise.race([aborted, execute(Object.freeze({ id: executionId, capabilities: binding.capabilities,
                    allowedOrigins: Object.freeze([checked.origin]), signal: controller.signal, guardFor }))]);
            assertActive();
            decision('execution', 'allowed', { stage: 'finish' });
            return result;
        }
        catch (error) {
            if (error instanceof PolicyError && error.code === 'guard-unsupported')
                decision('execution', 'guard-unsupported');
            throw error;
        }
        finally {
            if (abortWait)
                controller.signal.removeEventListener('abort', abortWait);
            active = false;
            controller.abort();
            clearTimeout(timer);
            options.signal?.removeEventListener('abort', cancel);
            await binding?.close();
        }
    }
    check(input, selection) {
        let risk = 'active', severity = 'medium';
        let digest = '';
        const invalid = (code, origin) => ({ code, risk, severity, digest, toolIds: [], ...(origin ? { origin } : {}) });
        try {
            digest = createHash('sha256').update(JSON.stringify({ input, selection })).digest('hex');
            const plan = input.plan, project = input.project;
            if (!identifier(project.id) || !identifier(plan.id) || !risks.includes(plan.risk)
                || !severities.includes(input.severity ?? 'info') || plan.projectId !== undefined && plan.projectId !== project.id
                || !Array.isArray(plan.requiredCapabilities) || !plan.requiredCapabilities.every(identifier)
                || plan.readiness !== undefined && !['READY', 'BLOCKED'].includes(plan.readiness))
                return invalid('invalid-request');
            const declared = origins(project.allowedOrigins), target = parseUrl(plan.targetUrl), base = parseUrl(project.baseUrl);
            const origin = target.origin;
            if (!declared.includes(origin) || !declared.includes(base.origin) || !this.config.allowedOrigins.includes(origin)
                || !this.config.allowedOrigins.includes(base.origin))
                return invalid('target-denied', origin);
            if (plan.readiness === 'BLOCKED')
                return invalid('plan-blocked', origin);
            if (selection.status !== 'READY' || !Array.isArray(selection.selections) || !risks.includes(selection.risk))
                return invalid('selection-unavailable', origin);
            const markers = plan.requiredCapabilities.filter(id => id.startsWith('probe:')).map(id => id.slice(6));
            if (markers.length > 1 || plan.probeId && markers.some(id => id !== plan.probeId)
                || (plan.probeId ?? markers[0] ?? null) !== selection.probeId)
                return invalid('invalid-request', origin);
            const selected = selection.selections.filter(item => item.selectedToolId !== null);
            if (new Set(selection.selections.map(item => item.capability)).size !== selection.selections.length
                || plan.requiredCapabilities.filter(id => !id.startsWith('probe:')).some(id => !selected.some(item => item.capability === id))
                || selection.selections.some(item => item.required && !item.selectedToolId))
                return invalid('selection-unavailable', origin);
            const toolIds = [...new Set(selected.map(item => item.selectedToolId))].sort();
            let active = plan.risk === 'active' || selection.risk === 'active' || !!selection.probeId
                || selected.some(item => ['request-executor', 'browser-controller', 'authentication-manager', 'xss-scanner', 'sql-scanner', 'security-scanner'].includes(item.capability))
                || !!plan.request && !['GET', 'HEAD', 'OPTIONS'].includes(plan.request.method);
            for (const item of selected) {
                const rule = this.config.tools[item.selectedToolId], candidate = item.candidates.find((candidate) => candidate.toolId === item.selectedToolId);
                if (!identifier(item.selectedToolId) || !identifier(item.capability) || !rule
                    || rule.capabilities && !rule.capabilities.includes(item.capability)
                    || rule.allowedOrigins && !rule.allowedOrigins.includes(origin))
                    return invalid('tool-denied', origin);
                if (!candidate || candidate.code !== 'available' || !risks.includes(candidate.risk))
                    return invalid('selection-unavailable', origin);
                if (candidate.risk === 'active')
                    active = true;
                if (candidate.risk === 'active' && rule.maxRisk === 'passive')
                    return invalid('risk-denied', origin);
            }
            risk = active ? 'active' : 'passive';
            severity = severities[Math.max(severities.indexOf(input.severity ?? 'info'), risk === 'active' ? 2 : 0)];
            if (risk === 'active' && this.config.maxRisk === 'passive')
                return invalid('risk-denied', origin);
            if (risk === 'active' && toolIds.some(id => this.config.tools[id].maxRisk === 'passive'))
                return invalid('risk-denied', origin);
            if (plan.request && (!this.config.allowedMethods.includes(plan.request.method)
                || toolIds.some(id => this.config.tools[id].allowedMethods && !this.config.tools[id].allowedMethods.includes(plan.request.method))))
                return invalid('method-denied', origin);
            return { code: 'allowed', risk, severity, origin, digest, toolIds };
        }
        catch {
            return invalid('invalid-request');
        }
    }
    needsApproval(checked) {
        return this.config.approval.risks.includes(checked.risk) || this.config.approval.severities.includes(checked.severity);
    }
    deny(code, checked) {
        this.record({ operation: 'execution', outcome: code === 'approval-required' ? 'APPROVAL_REQUIRED' : 'DENY', code,
            risk: checked?.risk ?? 'active', severity: checked?.severity ?? 'medium', ...(checked?.digest ? { planFingerprint: checked.digest } : {}) });
        throw new PolicyError(code);
    }
    record(input) {
        if (this.records.length >= this.config.maxAuditRecords)
            throw new PolicyError('audit-unavailable');
        const record = freeze({ ...input, id: `policy:${randomUUID()}`, sequence: this.records.length + 1, recordedAt: new Date(this.time()).toISOString() });
        try {
            const result = this.options.auditSink?.(record);
            if (result && ['object', 'function'].includes(typeof result) && typeof result.then === 'function') {
                void Promise.resolve(result).catch(() => undefined);
                throw new Error();
            }
        }
        catch {
            throw new PolicyError('audit-unavailable');
        }
        this.records.push(record);
        return record;
    }
    time() {
        let value;
        try {
            value = (this.options.now ?? Date.now)();
        }
        catch {
            throw new PolicyError('audit-unavailable');
        }
        if (!Number.isFinite(value) || value < 0 || value > 8_640_000_000_000_000 || value < this.lastTime)
            throw new PolicyError('audit-unavailable');
        this.lastTime = value;
        return value;
    }
    prune() {
        const now = this.time();
        for (const entries of [this.pending, this.approvals])
            for (const [id, entry] of entries)
                if (entry.expiresAt <= now)
                    entries.delete(id);
    }
}

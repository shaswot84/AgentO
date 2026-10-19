import { CapabilityRegistry as BoundCapabilities } from '@agento/runtime';
import { checkAvailability, executableAvailable, validExecutable } from './availability.js';
/** Selects adapters, then binds their existing runtime ports. It does not execute probes or tools. */
export class CapabilityRegistry {
    tools = new Map();
    timeoutMs;
    probes;
    constructor(options = {}) {
        this.timeoutMs = options.availabilityTimeoutMs ?? 2_000;
        if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 30_000) {
            throw new Error('Invalid availability timeout');
        }
        this.probes = options.probes;
    }
    register(adapter) {
        // Project only declared metadata, even if the caller supplies extra private fields.
        const source = adapter.metadata;
        if (!source || !identifier(source.id) || this.tools.has(source.id) || !identifiers(source.capabilities)
            || !source.capabilities.length || new Set(source.capabilities).size !== source.capabilities.length
            || source.capabilities.some(capability => capability.startsWith('probe:'))
            || source.supportedCwes !== 'all' && (!Array.isArray(source.supportedCwes) || !source.supportedCwes.length
                || !source.supportedCwes.every(cwe => typeof cwe === 'string' && /^CWE-\d+$/.test(cwe)))
            || !Array.isArray(source.protocols) || !source.protocols.length || !source.protocols.every(protocol => ['http', 'https'].includes(protocol))
            || !risk(source.risk) || source.priority !== undefined && (!Number.isSafeInteger(source.priority) || Math.abs(source.priority) > 1_000_000)
            || adapter.executable !== undefined && !validExecutable(adapter.executable)
            || adapter.checkAvailability !== undefined && typeof adapter.checkAvailability !== 'function')
            throw new Error('Invalid tool registration');
        const keys = Object.keys(adapter.capabilities ?? {});
        if (keys.length !== source.capabilities.length || keys.some(key => !source.capabilities.includes(key))
            || source.capabilities.some(key => !adapter.capabilities[key]
                || !['object', 'function'].includes(typeof adapter.capabilities[key])))
            throw new Error('Invalid capability ports');
        const metadata = freeze({ id: source.id, capabilities: [...source.capabilities].sort(),
            supportedCwes: source.supportedCwes === 'all' ? 'all' : [...new Set(source.supportedCwes)].sort(),
            protocols: [...new Set(source.protocols)].sort(), risk: source.risk, priority: source.priority ?? 0 });
        const executable = adapter.executable, custom = adapter.checkAvailability?.bind(adapter);
        this.tools.set(metadata.id, { metadata, ports: Object.freeze({ ...adapter.capabilities }), check: async (signal) => {
                if (signal.aborted)
                    return 'cancelled';
                if (executable && !await executableAvailable(executable))
                    return 'not-installed';
                if (signal.aborted)
                    return 'cancelled';
                if (custom && await custom(signal) !== true)
                    return 'not-configured';
                return signal.aborted ? 'cancelled' : 'available';
            } });
        return this;
    }
    list() { return freeze(this.entries().map(entry => entry.metadata)); }
    /** Returns all compatible candidates in stable preference order, without running checks. */
    lookup(request) {
        if (!identifier(request.capability) || !/^CWE-\d+$/.test(request.cweId) || !['http', 'https'].includes(request.protocol)) {
            throw new Error('Invalid capability lookup');
        }
        return freeze(this.entries().filter(entry => entry.metadata.capabilities.includes(request.capability)
            && !incompatible(entry.metadata, request)).map(entry => entry.metadata));
    }
    /** Fresh checks on each call; the report contains no executable paths or callback output. */
    async preflight(options = {}) {
        return freeze(await this.check(this.entries(), options.signal));
    }
    async resolvePlan(plan, options = {}) {
        return this.resolve(plan, options);
    }
    async resolveProbe(probeId, request, options = {}) {
        return this.resolve({ ...request, probeId, requiredCapabilities: request.requiredCapabilities ?? [] }, options);
    }
    async resolve(input, options = {}) {
        // Do not retain URLs, steps or private planner bindings in diagnostics.
        const empty = (status, code) => ({
            report: freeze({ status, risk: input?.risk === 'passive' ? 'passive' : 'active', probeId: null,
                selections: [], availability: [], diagnostics: [{ code }] }), capabilities: null,
        });
        let request, protocol;
        try {
            if (!input || !/^CWE-\d+$/.test(input.cweId) || !risk(input.risk) || !identifiers(input.requiredCapabilities)
                || input.optionalCapabilities !== undefined && !identifiers(input.optionalCapabilities)
                || input.probeId !== undefined && !identifier(input.probeId)
                || input.readiness !== undefined && !['READY', 'BLOCKED'].includes(input.readiness))
                return empty('BLOCKED', 'invalid-request');
            const url = new URL(input.targetUrl);
            if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password)
                return empty('BLOCKED', 'invalid-request');
            protocol = url.protocol === 'https:' ? 'https' : 'http';
            // A caller cannot mutate a pending selection by changing a plan array.
            request = { cweId: input.cweId, risk: input.risk, targetUrl: url.href,
                requiredCapabilities: [...input.requiredCapabilities], optionalCapabilities: [...(input.optionalCapabilities ?? [])],
                ...(input.probeId ? { probeId: input.probeId } : {}) };
        }
        catch {
            return empty('BLOCKED', 'invalid-request');
        }
        if (options.signal?.aborted)
            return empty('CANCELLED', 'cancelled');
        if (input.readiness === 'BLOCKED')
            return empty('BLOCKED', 'plan-blocked');
        const markers = [...new Set(request.requiredCapabilities.filter(id => id.startsWith('probe:')).map(id => id.slice(6)))];
        if (markers.length > 1 || request.probeId && markers.some(id => id !== request.probeId))
            return empty('BLOCKED', 'invalid-request');
        const probeId = request.probeId ?? markers[0] ?? null;
        let probe;
        try {
            const found = this.probes?.list().find(item => item.id === probeId);
            if (found && identifier(found.id) && identifiers(found.requiredCapabilities) && identifiers(found.optionalCapabilities)
                && [...found.requiredCapabilities, ...found.optionalCapabilities].every(id => !id.startsWith('probe:')))
                probe = found;
        }
        catch { /* An invalid external probe registration must not leak its exception. */ }
        const diagnostics = [];
        if (probeId && !probe)
            diagnostics.push({ code: 'probe-unavailable', capability: `probe:${probeId}` });
        const required = [...new Set([...request.requiredCapabilities.filter(id => !id.startsWith('probe:')), ...(probe?.requiredCapabilities ?? [])])];
        const optional = [...new Set([...(request.optionalCapabilities ?? []), ...(probe?.optionalCapabilities ?? [])])].filter(id => !required.includes(id));
        // Reserve the probe namespace: optional markers cannot be satisfied by a tool port either.
        if (optional.some(id => id.startsWith('probe:')))
            return empty('BLOCKED', 'invalid-request');
        const requirements = [...required, ...optional];
        const entries = this.entries(); // Stable snapshot; later registrations affect only later resolutions.
        const relevant = entries.filter(entry => entry.metadata.capabilities.some(id => requirements.includes(id))
            && !incompatible(entry.metadata, { cweId: request.cweId, protocol }));
        const availability = await this.check(relevant, options.signal);
        const checked = new Map(availability.map(item => [item.toolId, item]));
        const selections = requirements.map(capability => {
            const candidates = entries.filter(entry => entry.metadata.capabilities.includes(capability)).map(({ metadata }) => ({
                toolId: metadata.id, risk: metadata.risk,
                code: incompatible(metadata, { cweId: request.cweId, protocol }) ?? checked.get(metadata.id).code,
            }));
            const selectedToolId = candidates.find(candidate => candidate.code === 'available')?.toolId ?? null;
            const isRequired = required.includes(capability);
            if (!selectedToolId)
                diagnostics.push({ code: isRequired ? 'capability-unavailable' : 'optional-unavailable', capability });
            return { capability, required: isRequired, selectedToolId, candidates };
        });
        const cancelled = options.signal?.aborted || availability.some(item => item.code === 'cancelled');
        if (cancelled)
            diagnostics.push({ code: 'cancelled' });
        const ready = !cancelled && !diagnostics.some(item => item.code !== 'optional-unavailable');
        const selected = selections.filter(item => item.selectedToolId !== null);
        // A probe can send requests or establish sessions. Treat it conservatively, even if a caller understates risk.
        const selectedRisk = probeId !== null || request.risk === 'active' || selected.some(item => entries.find(entry => entry.metadata.id === item.selectedToolId).metadata.risk === 'active') ? 'active' : 'passive';
        const bindings = ready ? new BoundCapabilities() : null;
        for (const selection of selected) {
            if (!bindings)
                break;
            const id = selection.capability;
            const port = entries.find(entry => entry.metadata.id === selection.selectedToolId).ports[id];
            bindings.register(id, port);
        }
        return { report: freeze({ status: cancelled ? 'CANCELLED' : ready ? 'READY' : 'UNAVAILABLE', risk: selectedRisk,
                probeId, selections, availability, diagnostics }), capabilities: bindings };
    }
    entries() {
        return [...this.tools.values()].sort((a, b) => Number(a.metadata.risk === 'active') - Number(b.metadata.risk === 'active')
            || (b.metadata.priority ?? 0) - (a.metadata.priority ?? 0) || compare(a.metadata.id, b.metadata.id));
    }
    async check(entries, signal) {
        // Bound concurrency and check each adapter once per operation, even when it offers several ports.
        const results = new Array(entries.length);
        let cursor = 0;
        await Promise.all(Array.from({ length: Math.min(8, entries.length) }, async () => {
            while (cursor < entries.length) {
                const index = cursor++, entry = entries[index];
                results[index] = await checkAvailability(entry.metadata.id, entry.check, this.timeoutMs, signal);
            }
        }));
        return results;
    }
}
function incompatible(metadata, request) {
    if (!metadata.protocols.includes(request.protocol))
        return 'protocol-unsupported';
    if (metadata.supportedCwes !== 'all' && !metadata.supportedCwes.includes(request.cweId))
        return 'cwe-unsupported';
    return undefined;
}
function compare(left, right) { return left < right ? -1 : left > right ? 1 : 0; }
function risk(value) { return value === 'passive' || value === 'active'; }
function identifier(value) {
    return typeof value === 'string' && value.length <= 128 && /^[a-z][a-z0-9]*(?:[-:.][a-z0-9]+)*$/.test(value);
}
function identifiers(value) { return Array.isArray(value) && value.length <= 128 && value.every(identifier); }
function freeze(value) {
    if (value && typeof value === 'object') {
        for (const item of Object.values(value))
            freeze(item);
        Object.freeze(value);
    }
    return value;
}

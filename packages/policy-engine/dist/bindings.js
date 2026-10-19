import { CapabilityRegistry } from '@agento/runtime';
import { PolicyError } from './contracts.js';
export function bindCapabilities(resolution, host) {
    const bound = new CapabilityRegistry(), cleanup = [];
    const reads = { 'response-collector': ['collect', 'evidence'], 'header-analyzer': ['analyze'],
        'cookie-analyzer': ['analyze'], 'cookie-inspector': ['inspect'], 'response-comparator': ['compare'] };
    for (const selection of resolution.report.selections) {
        if (!selection.selectedToolId)
            continue;
        const id = selection.capability, toolId = selection.selectedToolId;
        const source = resolution.capabilities.get(id), guard = host.guardFor(toolId);
        let port;
        if (id === 'request-executor')
            port = executor(source, guard, host.signal);
        else if (id === 'authentication-manager' || id === 'browser-controller') {
            const provider = source;
            if (typeof provider.withGuard !== 'function')
                throw new PolicyError('guard-unsupported');
            try {
                port = provider.withGuard(guard);
            }
            catch {
                throw new PolicyError('guard-unsupported');
            }
            if (!port || port === source)
                throw new PolicyError('guard-unsupported');
            if (id === 'authentication-manager') {
                const manager = port;
                if (!manager.close)
                    throw new PolicyError('guard-unsupported');
                cleanup.push(() => manager.close());
            }
            port = guardedMethods(port, guard, id === 'authentication-manager' ? ['establishSession'] : ['withSession']);
        }
        else if (id === 'xss-scanner' || id === 'sql-scanner') {
            const scanner = source;
            port = Object.freeze({ scan: (input) => host.tool(toolId, async () => {
                    guard.assertActive();
                    // The executor is already guarded. The ambient tool binding adds this scanner's restrictions.
                    return scanner.scan({ ...input, project: { ...input.project, allowedOrigins: [...host.allowedOrigins] },
                        signal: input.signal ? AbortSignal.any([input.signal, host.signal]) : host.signal });
                }) });
        }
        else if (Object.hasOwn(reads, id))
            port = guardedMethods(source, guard, reads[id]);
        else
            throw new PolicyError('guard-unsupported');
        bound.register(id, port);
    }
    return { capabilities: bound, close: async () => { await Promise.all(cleanup.map(close => close())); } };
}
function executor(source, guard, signal) {
    return Object.freeze({ execute: async (input) => {
            const request = { ...input, ...(input.headers ? { headers: { ...input.headers } } : {}) };
            guard.assertActive();
            if (request.signal?.aborted)
                throw new PolicyError('cancelled');
            guard.assertRequest({ url: request.url, method: request.method ?? 'GET' });
            const response = await source.execute({ ...request, signal: request.signal ? AbortSignal.any([request.signal, signal]) : signal });
            guard.assertActive();
            if (response.url !== request.url)
                guard.assertRedirect(request.url, response.url);
            if (response.status >= 300 && response.status < 400) {
                for (const [key, values] of Object.entries(response.headers))
                    if (key.toLowerCase() === 'location') {
                        for (const value of values)
                            guard.assertRedirect(request.url, value);
                    }
            }
            return response;
        } });
}
function guardedMethods(source, guard, methods) {
    const target = source;
    return Object.freeze(Object.fromEntries(methods.map(name => {
        if (typeof target[name] !== 'function')
            throw new PolicyError('guard-unsupported');
        return [name, (...args) => { guard.assertActive(); return target[name].apply(source, args); }];
    })));
}

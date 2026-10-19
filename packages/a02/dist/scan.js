import { randomUUID } from 'node:crypto';
import { discoverProject } from '@agento/discovery';
import { ExpressFrameworkAdapter } from '@agento/framework-express';
import { buildApplicationSecurityModel, fromFrameworkAnalysis } from '@agento/security-model';
import { SecurityHypothesisEngine } from '@agento/hypothesis-engine';
import { SecurityTestPlanner } from '@agento/test-planner';
import { CWE1004Plugin, CWE614Plugin, CWE942Plugin, toCoreEvidence } from '@agento/cwe';
import { MemoryEvidenceStore } from '@agento/evidence';
import { CapabilityRegistry } from '@agento/capability-registry';
import { PolicyEngine, PolicyError } from '@agento/policy-engine';
import { CookieSecurityProbe, CrossOriginProbe, DeterministicRequestExecutor, NormalizedCookieAnalyzer, NormalizedHeaderAnalyzer, NormalizedResponseCollector, ProbeRegistry } from '@agento/runtime';
import { VerificationJudge } from '@agento/verifier';
import { A02Error } from './contracts.js';
/** Bounded host composition for three rules. No vulnerability logic is implemented here. */
export async function runA02Scan(options) {
    const config = validate(options);
    const active = () => { if (options.signal?.aborted)
        throw new A02Error('cancelled'); };
    active();
    const adapter = options.frameworkAdapter ?? new ExpressFrameworkAdapter();
    const discovery = await discoverProject(config.project.repositoryPath, {
        adapters: [{ framework: 'express', languages: ['typescript', 'javascript'], adapter }],
    });
    active();
    if (discovery.mode !== 'code-aware' || !await adapter.supports(config.project))
        throw new A02Error('discovery-unavailable');
    const project = { ...config.project, mode: 'code-aware', languages: [...discovery.languages] };
    const extracted = await adapter.extract(project);
    active();
    const endpoints = extracted.endpoints.filter(endpoint => endpoint.method === 'GET' && config.paths.includes(endpoint.path));
    if (config.paths.some(path => !endpoints.some(endpoint => endpoint.path === path)))
        throw new A02Error('route-unavailable');
    const ownStore = options.evidenceStore ? null : new MemoryEvidenceStore();
    const store = options.evidenceStore ?? ownStore;
    try {
        const retained = store.capture(extracted.evidence.filter(item => !item.endpointId
            || endpoints.some(endpoint => endpoint.id === item.endpointId)), { project, capabilityIds: adapter.capabilities });
        const model = buildApplicationSecurityModel({ project, identities: config.identities, contributions: [fromFrameworkAnalysis({
                    ...extracted, endpoints, resources: extracted.resources.filter(resource => endpoints.some(endpoint => endpoint.id === resource.endpointId)),
                    signals: extracted.signals.filter(signal => endpoints.some(endpoint => endpoint.id === signal.endpointId)), evidence: retained,
                })] });
        const rules = { sensitiveCookieNames: config.sensitiveCookieNames, untrustedOrigins: config.untrustedOrigins };
        const plugins = [new CWE1004Plugin(rules), new CWE614Plugin(rules), new CWE942Plugin(rules)];
        const hypotheses = await new SecurityHypothesisEngine({ plugins, ...rules }).generate(model, options.signal ? { signal: options.signal } : {});
        const planner = new SecurityTestPlanner({ plugins });
        const diagnostics = [...discovery.diagnostics.map(item => item.code), ...model.diagnostics.map(item => item.code),
            ...hypotheses.diagnostics.map(item => item.code),
            ...(!config.sensitiveCookieNames.length ? ['sensitive-cookie-names-required'] : []),
            ...(!config.untrustedOrigins.length ? ['untrusted-origins-required'] : [])];
        for (const plugin of plugins)
            if (!hypotheses.hypotheses.some(item => item.cweId === plugin.cweId))
                diagnostics.push(`no-hypothesis:${plugin.cweId}`);
        const plans = [];
        for (const hypothesis of hypotheses.hypotheses) {
            const planned = await planner.plan(model, hypothesis, { allowAnonymous: config.allowAnonymous });
            plans.push(...planned.plans);
            diagnostics.push(...planned.diagnostics.map(item => item.code));
        }
        const cookie = new CookieSecurityProbe(), cors = new CrossOriginProbe();
        const registry = new CapabilityRegistry({ probes: new ProbeRegistry().register('cookie-security', cookie).register('cross-origin', cors) });
        const executor = new DeterministicRequestExecutor({ baseUrl: project.baseUrl, allowedOrigins: project.allowedOrigins,
            ...(options.transport ? { transport: options.transport } : {}) });
        registry.register({ metadata: { id: 'a02-http', supportedCwes: ['CWE-1004', 'CWE-614', 'CWE-942'],
                capabilities: ['request-executor', 'response-collector', 'cookie-analyzer', 'header-analyzer'], protocols: ['http', 'https'], risk: 'active' },
            capabilities: { 'request-executor': executor, 'response-collector': new NormalizedResponseCollector(),
                'cookie-analyzer': new NormalizedCookieAnalyzer(), 'header-analyzer': new NormalizedHeaderAnalyzer() } });
        if (options.authentication)
            registry.register({ metadata: { id: 'a02-auth', supportedCwes: ['CWE-1004', 'CWE-614', 'CWE-942'],
                    capabilities: ['authentication-manager', 'cookie-inspector'], protocols: ['http', 'https'], risk: 'active' },
                capabilities: { 'authentication-manager': options.authentication, 'cookie-inspector': { inspect: session => session.cookies() } } });
        const policy = new PolicyEngine(config.policy);
        const results = [], executions = [], evidence = [...model.evidence];
        const cache = new Map();
        for (const plan of plans) {
            active();
            if (plan.probeId !== 'cookie-security' && plan.probeId !== 'cross-origin')
                throw new A02Error('invalid-options');
            const key = JSON.stringify([plan.probeId, plan.endpointId, plan.targetUrl, plan.request.method, [...plan.identityIds].sort(),
                [...plan.requiredCapabilities].sort(), plan.scope.untrustedOrigins ?? []]);
            let collectionId = null, reused = false, code = 'collected', outcome = 'SKIPPED';
            let proof = [];
            if (plan.readiness !== 'READY')
                code = plan.prerequisites.map(item => item.code).join(',');
            else {
                const resolution = await registry.resolvePlan(plan, options.signal ? { signal: options.signal } : {});
                const request = { project, plan };
                const decision = policy.review(request, resolution.report);
                if (decision.outcome !== 'ALLOW')
                    code = decision.code;
                else if (cache.has(key)) {
                    const cached = cache.get(key);
                    ({ collectionId, code } = cached);
                    proof = cached.result.evidence;
                    outcome = cached.result.outcome;
                    reused = true;
                }
                else {
                    collectionId = `a02-collection:${randomUUID()}`;
                    try {
                        const observation = await policy.run(request, resolution, async (execution) => {
                            const common = { project: { ...project, allowedOrigins: execution.allowedOrigins },
                                capabilities: execution.capabilities, signal: execution.signal,
                                request: { url: plan.targetUrl, method: plan.request.method } };
                            const identities = plan.identityIds.map(id => config.identities.find(identity => identity.id === id));
                            return plan.probeId === 'cookie-security' ? cookie.execute({ ...common, identities })
                                : cors.execute({ ...common, ...(identities[0] ? { identity: identities[0] } : {}), origins: plan.scope.untrustedOrigins ?? [] });
                        }, options.signal ? { signal: options.signal } : {});
                        proof = store.capture([toCoreEvidence(observation, plan.endpointId)], {
                            project, targetUrl: plan.targetUrl, probeId: plan.probeId, capabilityIds: plan.requiredCapabilities,
                        });
                        evidence.push(...proof);
                        outcome = 'COMPLETED';
                    }
                    catch (error) {
                        active();
                        outcome = 'FAILED';
                        code = error instanceof PolicyError ? error.code : 'probe-failed';
                    }
                    cache.set(key, { collectionId, code, result: result(plan, outcome, proof) });
                }
            }
            results.push(result(plan, outcome, proof));
            executions.push({ planId: plan.id, probeId: plan.probeId, collectionId, reused, outcome, code });
        }
        active();
        const context = { ...model, evidence };
        const judge = new VerificationJudge({ plugins, evidenceStore: store });
        const decisions = [];
        for (const hypothesis of hypotheses.hypotheses)
            decisions.push(await judge.judge({ context, hypothesis,
                plans: plans.filter(plan => plan.hypothesisId === hypothesis.id),
                results: results.filter(item => plans.some(plan => plan.hypothesisId === hypothesis.id && plan.id === item.planId)) }));
        return freeze({ schemaVersion: 1, category: 'A02:2025',
            discovery: { mode: discovery.mode, frameworks: [...discovery.frameworks], adapterId: adapter.id },
            diagnostics: [...new Set(diagnostics)], context, hypotheses: hypotheses.hypotheses, plans, results, executions, decisions,
            findings: decisions.map(item => item.finding), audit: policy.audit() });
    }
    finally {
        ownStore?.close();
    }
}
function result(plan, outcome, evidence) {
    return { id: `a02-result:${plan.id}`, planId: plan.id, producerId: 'agento-a02', outcome,
        summary: outcome === 'COMPLETED' ? 'Normalized probe evidence collected.' : 'Runtime investigation is incomplete.', evidence };
}
function validate(options) {
    try {
        const project = structuredClone(options.project), paths = [...options.paths], identities = structuredClone(options.identities);
        const base = new URL(project.baseUrl), sensitiveCookieNames = [...options.sensitiveCookieNames], untrustedOrigins = [...options.untrustedOrigins];
        if (!project.id || !project.repositoryPath || !['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash
            || !project.allowedOrigins.includes(base.origin) || !paths.length || paths.length > 32 || new Set(paths).size !== paths.length
            || paths.some(path => !path.startsWith('/') || path.startsWith('//') || /[\\?#:*(){}\s%]/.test(path) || new URL(path, base).pathname !== path)
            || identities.length > 10 || new Set(identities.map(identity => identity.id)).size !== identities.length
            || identities.some(identity => !identity.id || identity.authentication === 'anonymous')
            || sensitiveCookieNames.some(name => !/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/.test(name))
            || untrustedOrigins.length > 8 || new Set(untrustedOrigins).size !== untrustedOrigins.length
            || untrustedOrigins.some(origin => origin !== 'null' && (!['http:', 'https:'].includes(new URL(origin).protocol)
                || new URL(origin).origin !== origin || origin === base.origin)))
            throw new Error();
        return { project, paths, identities, sensitiveCookieNames, untrustedOrigins, allowAnonymous: options.allowAnonymous ?? false,
            policy: structuredClone(options.policy) };
    }
    catch {
        throw new A02Error('invalid-options');
    }
}
function freeze(value) {
    if (value && typeof value === 'object' && !Object.isFrozen(value)) {
        for (const child of Object.values(value))
            freeze(child);
        Object.freeze(value);
    }
    return value;
}

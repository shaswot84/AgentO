import { randomUUID } from 'node:crypto';
import { isEndpointTestable } from '@agento/core';
import { discoverProject } from '@agento/discovery';
import { ExpressFrameworkAdapter } from '@agento/framework-express';
import { TesterArmyE2EAdapter } from '@agento/tool-e2e-browser';
import { buildApplicationSecurityModel, fromFrameworkAnalysis, resolveEndpoint } from '@agento/security-model';
import { SecurityHypothesisEngine } from '@agento/hypothesis-engine';
import { SecurityTestPlanner } from '@agento/test-planner';
import { CWE639Plugin, CWE862Plugin, toCoreEvidence } from '@agento/cwe';
import { MemoryEvidenceStore } from '@agento/evidence';
import { CapabilityRegistry } from '@agento/capability-registry';
import { PolicyEngine, PolicyError } from '@agento/policy-engine';
import { AuthorizationProbe, DeterministicRequestExecutor, NormalizedResponseCollector, NormalizedResponseComparator, ProbeRegistry, RuntimeAuthenticationManager, WorkflowBrowserController } from '@agento/runtime';
import { VerificationJudge } from '@agento/verifier';
import { A01Error } from './contracts.js';
/** Host composition only. The probe collects comparisons; the CWE rules decide verdicts. */
export async function runA01Scan(options) {
    const config = validate(options);
    const active = () => { if (options.signal?.aborted)
        throw new A01Error('cancelled'); };
    active();
    const adapter = options.frameworkAdapter ?? new ExpressFrameworkAdapter();
    const discovery = await discoverProject(config.project.repositoryPath, {
        adapters: [{ framework: 'express', languages: ['typescript', 'javascript'], adapter }],
    });
    active();
    if (discovery.mode !== 'code-aware' || !await adapter.supports(config.project))
        throw new A01Error('discovery-unavailable');
    const project = { ...config.project, mode: 'code-aware', languages: [...discovery.languages] };
    const extracted = await adapter.extract(project);
    active();
    if (extracted.discovery?.status === 'failed' || extracted.discovery?.status === 'unavailable')
        throw new A01Error('discovery-unavailable');
    const endpoints = extracted.endpoints.filter(endpoint => isEndpointTestable(endpoint) && endpoint.method === 'GET' && config.targets.some(target => target.path === endpoint.path));
    if (config.targets.some(target => !endpoints.some(endpoint => endpoint.path === target.path)))
        throw new A01Error('route-unavailable');
    const ownStore = options.evidenceStore ? null : new MemoryEvidenceStore();
    const store = options.evidenceStore ?? ownStore;
    try {
        const selected = (item) => !item.endpointId || endpoints.some(endpoint => endpoint.id === item.endpointId);
        const framework = { ...extracted, endpoints, resources: extracted.resources.filter(selected), signals: extracted.signals.filter(selected),
            evidence: store.capture(extracted.evidence.filter(selected), { project, capabilityIds: adapter.capabilities }) };
        // Host declarations express the intended access boundary, not an observed enforcement result.
        // Concrete keys and content markers are deliberately excluded from this public contribution.
        const declared = config.targets.map(target => {
            const endpointId = endpoints.find(endpoint => endpoint.path === target.path).id;
            const record = { id: `a01-policy:${randomUUID()}`, projectId: project.id, kind: 'configuration',
                producerId: 'agento-a01', capturedAt: new Date().toISOString(), endpointId,
                summary: 'The host declares the expected resource owner and forbidden access controls.',
                facts: { resourceId: target.resourceId, ownerIdentityId: target.ownerIdentityId, attackerIdentityId: target.attackerIdentityId,
                    attackerIsUnauthorized: target.attackerIsUnauthorized, anonymousIsUnauthorized: target.anonymousIsUnauthorized } };
            const evidence = store.capture([record], { project, capabilityIds: ['access-policy-declaration'] });
            const resource = { id: target.resourceId, projectId: project.id, type: target.cweId === 'CWE-639' ? 'owned-object' : 'protected-route',
                externalKey: target.resourceId, endpointId, evidenceIds: evidence.map(item => item.id) };
            return { source: 'declared', evidence, resources: [resource], facts: [{ kind: 'ownership', endpointIds: [endpointId],
                        evidenceIds: evidence.map(item => item.id), details: { resourceId: target.resourceId, ownerIdentityId: target.ownerIdentityId } }] };
        });
        const model = buildApplicationSecurityModel({ project, identities: config.personas.map(({ id, label, roles, authentication }) => ({ id, label, roles, authentication })),
            contributions: [fromFrameworkAnalysis(framework), ...declared] });
        const authorizationPolicies = config.targets.map(({ resourceId, ownerIdentityId, attackerIdentityId, attackerIsUnauthorized, anonymousIsUnauthorized }) => ({ resourceId, ownerIdentityId, attackerIdentityId, attackerIsUnauthorized, anonymousIsUnauthorized }));
        const plugins = [new CWE639Plugin({ authorizationPolicies }), new CWE862Plugin({ authorizationPolicies })];
        const generated = await new SecurityHypothesisEngine({ plugins }).generate(model, options.signal ? { signal: options.signal } : {});
        const candidates = (await Promise.all(plugins.map(plugin => plugin.detectCandidates(model)))).flat();
        const hypotheses = generated.hypotheses.filter(hypothesis => {
            const policy = candidates.find(candidate => candidate.id === hypothesis.id)?.scope.authorization;
            return config.targets.some(target => target.cweId === hypothesis.cweId && target.resourceId === policy?.resourceId
                && hypothesis.endpointId && resolveEndpoint(model, hypothesis.endpointId)?.path === target.path);
        });
        const diagnostics = [...discovery.diagnostics.map(item => item.code), ...model.diagnostics.map(item => item.code), ...generated.diagnostics.map(item => item.code)];
        for (const target of config.targets)
            if (!hypotheses.some(item => item.cweId === target.cweId
                && candidates.find(candidate => candidate.id === item.id)?.scope.authorization?.resourceId === target.resourceId)) {
                diagnostics.push(`no-hypothesis:${target.cweId}:${target.resourceId}`);
            }
        const planner = new SecurityTestPlanner({ plugins }), plans = [];
        for (const hypothesis of hypotheses) {
            const target = config.targets.find(target => target.resourceId === candidates.find(candidate => candidate.id === hypothesis.id).scope.authorization.resourceId);
            const planned = await planner.plan(model, hypothesis, { inputs: Object.keys(target.pathValues ?? {}).map(name => ({ name, location: 'path', valueRef: `a01-path:${name}` })) });
            plans.push(...planned.plans);
            diagnostics.push(...planned.diagnostics.map(item => item.code));
        }
        const probe = new AuthorizationProbe();
        const registry = new CapabilityRegistry({ probes: new ProbeRegistry().register('authorization', probe) });
        const http = { baseUrl: project.baseUrl, allowedOrigins: project.allowedOrigins, ...(options.transport ? { transport: options.transport } : {}) };
        const browser = options.browser ?? new WorkflowBrowserController({ context: model, target: config.target,
            driver: options.browserDriver ?? new TesterArmyE2EAdapter(options.credentials ? { credentials: options.credentials } : {}) });
        const authentication = new RuntimeAuthenticationManager({ browser, http, identities: config.personas });
        registry.register({ metadata: { id: 'a01-http', supportedCwes: ['CWE-639', 'CWE-862'],
                capabilities: ['request-executor', 'response-collector', 'response-comparator'], protocols: ['http', 'https'], risk: 'active' },
            capabilities: { 'request-executor': new DeterministicRequestExecutor(http), 'response-collector': new NormalizedResponseCollector(),
                'response-comparator': new NormalizedResponseComparator() } });
        registry.register({ metadata: { id: 'a01-auth', supportedCwes: ['CWE-639', 'CWE-862'], capabilities: ['authentication-manager'],
                protocols: ['http', 'https'], risk: 'active' }, capabilities: { 'authentication-manager': authentication } });
        const policy = new PolicyEngine(config.policy), evidence = [...model.evidence];
        const results = [], executions = [];
        try {
            for (const plan of plans) {
                active();
                let code = 'collected', outcome = 'SKIPPED', proof = [];
                if (plan.readiness !== 'READY')
                    code = plan.prerequisites.map(item => item.code).join(',');
                else {
                    const resolution = await registry.resolvePlan(plan, options.signal ? { signal: options.signal } : {});
                    const decision = policy.review({ project, plan }, resolution.report);
                    if (decision.outcome !== 'ALLOW')
                        code = decision.code;
                    else
                        try {
                            const target = config.targets.find(target => target.resourceId === plan.scope.authorization.resourceId);
                            const observation = await policy.run({ project, plan }, resolution, execution => probe.execute({
                                project: { ...project, allowedOrigins: execution.allowedOrigins }, capabilities: execution.capabilities, signal: execution.signal,
                                owner: config.personas.find(identity => identity.id === target.ownerIdentityId),
                                attacker: config.personas.find(identity => identity.id === target.attackerIdentityId),
                                resource: { id: target.resourceId, ownerIdentityId: target.ownerIdentityId,
                                    request: { url: concreteUrl(target, project.baseUrl), method: 'GET' }, ownerMarkers: target.ownerMarkers },
                            }), options.signal ? { signal: options.signal } : {});
                            proof = store.capture([toCoreEvidence(observation, plan.endpointId)], { project, targetUrl: concreteUrl(target, project.baseUrl),
                                probeId: 'authorization', capabilityIds: plan.requiredCapabilities });
                            evidence.push(...proof);
                            outcome = 'COMPLETED';
                            if (observation.outcome === 'PARTIAL') {
                                code = 'partial-collection';
                                diagnostics.push(`partial-collection:${plan.id}`);
                            }
                        }
                        catch (error) {
                            active();
                            outcome = 'FAILED';
                            code = error instanceof PolicyError ? error.code : 'probe-failed';
                        }
                }
                results.push({ id: `a01-result:${plan.id}`, planId: plan.id, producerId: 'agento-a01', outcome,
                    summary: outcome === 'COMPLETED' ? 'Normalized authorization comparisons collected.' : 'Authorization investigation is incomplete.', evidence: proof });
                executions.push({ planId: plan.id, probeId: 'authorization', outcome, code });
            }
        }
        finally {
            await authentication.close();
        }
        active();
        const context = { ...model, evidence }, judge = new VerificationJudge({ plugins, evidenceStore: store }), decisions = [];
        for (const hypothesis of hypotheses)
            decisions.push(await judge.judge({ context, hypothesis,
                plans: plans.filter(plan => plan.hypothesisId === hypothesis.id),
                results: results.filter(result => plans.some(plan => plan.hypothesisId === hypothesis.id && plan.id === result.planId)) }));
        return freeze({ schemaVersion: 1, category: 'A01:2025', discovery: { mode: discovery.mode, frameworks: [...discovery.frameworks], adapterId: adapter.id },
            diagnostics: [...new Set(diagnostics)], context, hypotheses, plans, results, executions, decisions, findings: decisions.map(item => item.finding), audit: policy.audit() });
    }
    finally {
        ownStore?.close();
    }
}
function validate(options) {
    try {
        const project = structuredClone(options.project), targets = structuredClone(options.targets), personas = structuredClone(options.target.personas ?? []);
        const base = new URL(project.baseUrl), id = (value) => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}$/.test(value);
        if (!id(project.id) || !project.repositoryPath || !['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash
            || !project.allowedOrigins.includes(base.origin) || !id(options.target.id) || !options.target.baseOrigins.includes(base.origin)
            || !targets.length || targets.length > 32 || new Set(targets.map(target => target.resourceId)).size !== targets.length
            || personas.length < 2 || personas.length > 10 || new Set(personas.map(persona => persona.id)).size !== personas.length
            || personas.some(persona => !id(persona.id) || persona.authentication !== 'session-cookie' || !Array.isArray(persona.roles)
                || persona.roles.some(role => !id(role)) || typeof persona.label !== 'string')
            || targets.some(target => !id(target.resourceId) || !['CWE-639', 'CWE-862'].includes(target.cweId)
                || target.ownerIdentityId === target.attackerIdentityId || ![target.ownerIdentityId, target.attackerIdentityId].every(value => personas.some(persona => persona.id === value))
                || typeof target.attackerIsUnauthorized !== 'boolean' || typeof target.anonymousIsUnauthorized !== 'boolean'
                || (target.cweId === 'CWE-639' ? !target.attackerIsUnauthorized : !target.attackerIsUnauthorized && !target.anonymousIsUnauthorized)
                || !Array.isArray(target.ownerMarkers) || !target.ownerMarkers.length || target.ownerMarkers.length > 16
                || target.ownerMarkers.some(marker => typeof marker !== 'string' || !marker.trim() || marker.length > 4096)))
            throw new Error();
        for (const target of targets)
            concreteUrl(target, base.href);
        return { project, targets, personas, policy: structuredClone(options.policy), target: { ...options.target, personas } };
    }
    catch {
        throw new A01Error('invalid-options');
    }
}
function concreteUrl(target, baseUrl) {
    const path = target.path, values = target.pathValues ?? {}, names = [];
    if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || /[\\?#*(){}\s%]/.test(path)
        || typeof values !== 'object' || Array.isArray(values))
        throw new A01Error('invalid-options');
    const segments = path.split('/').map(segment => {
        if (!segment.includes(':'))
            return segment;
        if (!/^:[A-Za-z_][A-Za-z0-9_]*$/.test(segment))
            throw new A01Error('invalid-options');
        const name = segment.slice(1), value = values[name];
        names.push(name);
        if (!Object.hasOwn(values, name) || typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(value))
            throw new A01Error('invalid-options');
        return value;
    });
    const concrete = segments.join('/'), result = new URL(concrete, baseUrl);
    if (new Set(names).size !== names.length || Object.keys(values).some(name => !names.includes(name))
        || result.origin !== new URL(baseUrl).origin || result.pathname !== concrete)
        throw new A01Error('invalid-options');
    return result.href;
}
function freeze(value) {
    if (value && typeof value === 'object' && !Object.isFrozen(value)) {
        for (const child of Object.values(value))
            freeze(child);
        Object.freeze(value);
    }
    return value;
}

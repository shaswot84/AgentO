import { isEndpointTestable } from '@agento/core';
import { discoverProject } from '@agento/discovery';
import { ExpressFrameworkAdapter } from '@agento/framework-express';
import { SemgrepAdapter } from '@agento/tool-semgrep';
import { TesterArmyE2EAdapter } from '@agento/tool-e2e-browser';
import { DalfoxAdapter, SqlmapAdapter } from '@agento/security-scanners';
import { buildApplicationSecurityModel, fromFrameworkAnalysis, fromStaticAnalysis, resolveEndpoint } from '@agento/security-model';
import { SecurityHypothesisEngine } from '@agento/hypothesis-engine';
import { SecurityTestPlanner } from '@agento/test-planner';
import { CWE79Plugin, CWE89Plugin, toCoreEvidence } from '@agento/cwe';
import { MemoryEvidenceStore } from '@agento/evidence';
import { CapabilityRegistry } from '@agento/capability-registry';
import { PolicyEngine, PolicyError } from '@agento/policy-engine';
import { DeterministicRequestExecutor, NormalizedResponseCollector, NormalizedResponseComparator, ProbeRegistry, SQLInjectionProbe, WorkflowBrowserController, XSSProbe } from '@agento/runtime';
import { VerificationJudge } from '@agento/verifier';
import { A05Error } from './contracts.js';
/** Bounded host composition. Rules retain responsibility for every security verdict. */
export async function runA05Scan(options) {
    const config = validate(options);
    const active = () => { if (options.signal?.aborted)
        throw new A05Error('cancelled'); };
    active();
    const adapter = options.frameworkAdapter ?? new ExpressFrameworkAdapter();
    const discovery = await discoverProject(config.project.repositoryPath, {
        adapters: [{ framework: 'express', languages: ['typescript', 'javascript'], adapter }],
    });
    active();
    if (discovery.mode !== 'code-aware' || !await adapter.supports(config.project))
        throw new A05Error('discovery-unavailable');
    const project = { ...config.project, mode: 'code-aware', languages: [...discovery.languages] };
    const extracted = await adapter.extract(project);
    active();
    if (extracted.discovery?.status === 'failed' || extracted.discovery?.status === 'unavailable')
        throw new A05Error('discovery-unavailable');
    const endpoints = extracted.endpoints.filter(endpoint => isEndpointTestable(endpoint) && endpoint.method === 'GET' && config.targets.some(target => target.path === endpoint.path));
    if (config.targets.some(target => !endpoints.some(endpoint => endpoint.path === target.path)))
        throw new A05Error('route-unavailable');
    const analyzer = options.staticAnalyzer ?? new SemgrepAdapter({ frameworkAnalysis: extracted,
        ...(options.semgrepExecutable ? { executable: options.semgrepExecutable } : {}) });
    const analysis = await analyzer.analyze(project);
    active();
    const ownStore = options.evidenceStore ? null : new MemoryEvidenceStore();
    const store = options.evidenceStore ?? ownStore;
    try {
        const selected = (item) => !item.endpointId || endpoints.some(endpoint => endpoint.id === item.endpointId);
        const framework = { ...extracted, endpoints,
            resources: extracted.resources.filter(selected), signals: extracted.signals.filter(selected),
            evidence: store.capture(extracted.evidence.filter(selected), { project, capabilityIds: adapter.capabilities }) };
        const statics = { ...analysis, signals: analysis.signals.filter(signal => signal.endpointId && selected(signal)),
            evidence: store.capture(analysis.evidence.filter(selected), { project, capabilityIds: analyzer.capabilities }) };
        const anonymous = { id: 'a05-anonymous', label: 'Anonymous', authentication: 'anonymous', roles: [] };
        const model = buildApplicationSecurityModel({ project, identities: [...config.identities, anonymous],
            contributions: [fromFrameworkAnalysis(framework), fromStaticAnalysis(statics)] });
        const plugins = [new CWE79Plugin(), new CWE89Plugin()];
        const generated = await new SecurityHypothesisEngine({ plugins }).generate(model, options.signal ? { signal: options.signal } : {});
        const diagnostics = [...discovery.diagnostics.map(item => item.code), ...model.diagnostics.map(item => item.code),
            ...generated.diagnostics.map(item => item.code)];
        // Retain analysis completion explicitly. An empty/failed static scan is never a clean dynamic result.
        const run = analysis.evidence.find(item => item.facts.observation === 'static-analysis-run');
        if (run?.facts.status !== 'completed')
            diagnostics.push('static-analysis-incomplete');
        const candidates = (await Promise.all(plugins.map(plugin => plugin.detectCandidates(model)))).flat();
        const hypotheses = generated.hypotheses.filter(hypothesis => {
            const endpoint = hypothesis.endpointId && resolveEndpoint(model, hypothesis.endpointId);
            if (!endpoint)
                return false;
            const target = config.targets.find(item => item.path === endpoint.path && item.cweId === hypothesis.cweId);
            if (!target)
                return false;
            const point = candidates.find(candidate => candidate.id === hypothesis.id)?.scope.parameter;
            // Require source-to-input attribution as well as endpoint association; do not fan out to every route input.
            return point?.location === 'query' && model.signals.some(signal => signal.producerId === analyzer.id
                && signal.cweIds.includes(hypothesis.cweId) && signal.endpointId === endpoint.id
                && signal.evidenceIds.some(id => {
                    const item = model.evidence.find(record => record.id === id);
                    return Array.isArray(item?.facts.sources) && item.facts.sources.some(source => source && typeof source === 'object'
                        && !Array.isArray(source) && source.kind === 'request-query' && source.parameterName === point.name);
                }));
        });
        for (const target of config.targets)
            if (!hypotheses.some(item => item.cweId === target.cweId
                && resolveEndpoint(model, item.endpointId)?.path === target.path))
                diagnostics.push(`no-grounded-input:${target.cweId}:${target.path}`);
        const planner = new SecurityTestPlanner({ plugins });
        const plans = [];
        for (const hypothesis of hypotheses) {
            const endpoint = resolveEndpoint(model, hypothesis.endpointId);
            const target = config.targets.find(item => item.path === endpoint.path && item.cweId === hypothesis.cweId);
            const inputs = endpoint.parameters.filter(point => point.location === 'query' && Object.hasOwn(target.inputs, point.name))
                .map((point, index) => ({ name: point.name, location: 'query', valueRef: `a05-input:${index}` }));
            const planned = await planner.plan(model, hypothesis, { allowAnonymous: config.allowAnonymous, inputs });
            // These ports are mandatory for the complete injection slice; unavailable tools cannot silently disappear.
            plans.push(...planned.plans.map(plan => ({ ...plan, requiredCapabilities: [...new Set([...plan.requiredCapabilities,
                        ...(plan.probeId === 'xss' ? ['browser-controller', 'xss-scanner'] : ['sql-scanner'])])] })));
            diagnostics.push(...planned.diagnostics.map(item => item.code));
        }
        const xss = new XSSProbe(), sql = new SQLInjectionProbe();
        const registry = new CapabilityRegistry({ probes: new ProbeRegistry().register('xss', xss).register('sql-injection', sql) });
        registry.register({ metadata: { id: 'a05-http', supportedCwes: ['CWE-79', 'CWE-89'],
                capabilities: ['request-executor', 'response-collector', 'response-comparator'], protocols: ['http', 'https'], risk: 'active' },
            capabilities: { 'request-executor': new DeterministicRequestExecutor({ baseUrl: project.baseUrl, allowedOrigins: project.allowedOrigins,
                    ...(options.transport ? { transport: options.transport } : {}) }),
                'response-collector': new NormalizedResponseCollector(), 'response-comparator': new NormalizedResponseComparator() } });
        const browser = options.browser ?? new WorkflowBrowserController({ context: model,
            driver: new TesterArmyE2EAdapter(), target: { id: 'a05-target', baseOrigins: project.allowedOrigins, personas: [anonymous] } });
        registry.register({ metadata: { id: 'a05-browser', supportedCwes: ['CWE-79'], capabilities: ['browser-controller'],
                protocols: ['http', 'https'], risk: 'active' }, capabilities: { 'browser-controller': browser } });
        if (options.authentication)
            registry.register({ metadata: { id: 'a05-auth', supportedCwes: ['CWE-79', 'CWE-89'],
                    capabilities: ['authentication-manager'], protocols: ['http', 'https'], risk: 'active' },
                capabilities: { 'authentication-manager': options.authentication } });
        for (const scanner of options.scanners ?? [new DalfoxAdapter().registration(), new SqlmapAdapter().registration()])
            registry.register(scanner);
        const policy = new PolicyEngine(config.policy), evidence = [...model.evidence];
        const results = [], executions = [];
        for (const plan of plans) {
            active();
            if (plan.probeId !== 'xss' && plan.probeId !== 'sql-injection')
                throw new A05Error('invalid-options');
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
                        const target = config.targets.find(item => item.path === new URL(plan.targetUrl).pathname && item.cweId === plan.cweId);
                        const url = new URL(plan.targetUrl);
                        for (const parameter of plan.request.parameters)
                            if (parameter.location === 'query' && parameter.source)
                                url.searchParams.set(parameter.name, target.inputs[parameter.name]);
                        const observation = await policy.run({ project, plan }, resolution, async (execution) => {
                            const common = { project: { ...project, allowedOrigins: execution.allowedOrigins }, capabilities: execution.capabilities,
                                signal: execution.signal, request: { url: url.href, method: 'GET' },
                                parameter: { name: plan.scope.parameter.name, location: 'query' },
                                maxScannerRequests: config.maxScannerRequests,
                                ...(plan.identityIds[0] ? { identity: config.identities.find(identity => identity.id === plan.identityIds[0]) } : { anonymousIdentity: anonymous }),
                                ...(target.sqlBooleanContext ? { sqlBooleanContext: target.sqlBooleanContext } : {}),
                                ...(target.responseJsonPointer ? { responseJsonPointer: target.responseJsonPointer } : {}) };
                            return plan.probeId === 'xss' ? xss.execute(common) : sql.execute(common);
                        }, options.signal ? { signal: options.signal } : {});
                        proof = store.capture([toCoreEvidence(observation, plan.endpointId)], { project, targetUrl: plan.targetUrl,
                            probeId: plan.probeId, capabilityIds: plan.requiredCapabilities });
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
            results.push({ id: `a05-result:${plan.id}`, planId: plan.id, producerId: 'agento-a05', outcome,
                summary: outcome === 'COMPLETED' ? 'Normalized injection observations collected.' : 'Injection investigation is incomplete.', evidence: proof });
            executions.push({ planId: plan.id, probeId: plan.probeId, outcome, code });
        }
        active();
        const context = { ...model, evidence }, judge = new VerificationJudge({ plugins, evidenceStore: store });
        const decisions = [];
        for (const hypothesis of hypotheses)
            decisions.push(await judge.judge({ context, hypothesis,
                plans: plans.filter(plan => plan.hypothesisId === hypothesis.id),
                results: results.filter(result => plans.some(plan => plan.hypothesisId === hypothesis.id && result.planId === plan.id)) }));
        return freeze({ schemaVersion: 1, category: 'A05:2025', discovery: { mode: discovery.mode,
                frameworks: [...discovery.frameworks], adapterId: adapter.id }, diagnostics: [...new Set(diagnostics)], context,
            hypotheses, plans, results, executions, decisions, findings: decisions.map(item => item.finding), audit: policy.audit() });
    }
    finally {
        ownStore?.close();
    }
}
function validate(options) {
    try {
        const project = structuredClone(options.project), targets = structuredClone(options.targets), identities = structuredClone(options.identities ?? []);
        const base = new URL(project.baseUrl), maxScannerRequests = options.maxScannerRequests ?? 128;
        if (options.allowAnonymous !== undefined && typeof options.allowAnonymous !== 'boolean' || !project.id || !project.repositoryPath || !['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash
            || !project.allowedOrigins.includes(base.origin) || !targets.length || targets.length > 32
            || new Set(targets.map(target => `${target.cweId}:${target.path}`)).size !== targets.length
            || targets.some(target => !['CWE-79', 'CWE-89'].includes(target.cweId) || !target.path.startsWith('/') || target.path.startsWith('//')
                || /[\\?#:*(){}\s%]/.test(target.path) || new URL(target.path, base).pathname !== target.path
                || !target.inputs || typeof target.inputs !== 'object' || Array.isArray(target.inputs) || Object.keys(target.inputs).length > 32
                || Object.entries(target.inputs).some(([name, value]) => !/^[A-Za-z_][A-Za-z0-9_-]{0,127}$/.test(name) || typeof value !== 'string' || value.length > 4096)
                || target.sqlBooleanContext !== undefined && !['quoted-string', 'like-pattern'].includes(target.sqlBooleanContext)
                || target.responseJsonPointer !== undefined && !/^\/(?:[A-Za-z0-9_-]+)(?:\/[A-Za-z0-9_-]+)*$/.test(target.responseJsonPointer))
            || identities.length > 10 || new Set(identities.map(identity => identity.id)).size !== identities.length
            || identities.some(identity => !identity.id || identity.id === 'a05-anonymous' || identity.authentication === 'anonymous')
            || !Number.isSafeInteger(maxScannerRequests) || maxScannerRequests < 1 || maxScannerRequests > 512)
            throw new Error();
        return { project, targets, identities, maxScannerRequests, allowAnonymous: options.allowAnonymous ?? false, policy: structuredClone(options.policy) };
    }
    catch {
        throw new A05Error('invalid-options');
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

import type { AnalysisContext, Endpoint, SecurityHypothesis, SecurityTestPlan, TestPlanner } from '@agento/core';
import { isEndpointTestable } from '@agento/core';
import { buildApplicationSecurityModel, fromAnalysisContext, resolveEndpoint } from '@agento/security-model';
import type { ApplicationSecurityModel, ModelEndpoint } from '@agento/security-model';
import type {
  AccessPolicy, InputBinding, PlannedParameter, PlanPrerequisite, PlanScope, PlanningBindings, PlanningDiagnostic,
  PlanningPlugin, PlanningResult, ProbeId, StructuredTestPlan, TestPlannerOptions,
} from './contracts.js';
import { steps, verification } from './templates.js';

const probes: Readonly<Record<string, ProbeId>> = {
  'CWE-639': 'authorization', 'CWE-862': 'authorization', 'CWE-942': 'cross-origin',
  'CWE-1004': 'cookie-security', 'CWE-614': 'cookie-security', 'CWE-79': 'xss', 'CWE-89': 'sql-injection',
};
const required: Readonly<Record<ProbeId, readonly string[]>> = {
  authorization: ['request-executor', 'response-collector', 'authentication-manager', 'response-comparator'],
  'cookie-security': ['request-executor', 'response-collector', 'cookie-analyzer'],
  'cross-origin': ['request-executor', 'response-collector', 'header-analyzer'],
  xss: ['request-executor', 'response-collector'],
  'sql-injection': ['request-executor', 'response-collector', 'response-comparator'],
};
const optional: Readonly<Record<ProbeId, readonly string[]>> = {
  authorization: ['browser-controller'], 'cookie-security': ['browser-controller'], 'cross-origin': [],
  xss: ['browser-controller', 'xss-scanner'], 'sql-injection': ['sql-scanner'],
};
interface Seed { readonly id: string; readonly probeId: ProbeId; readonly scope: PlanScope; readonly requiredCapabilities: readonly string[] }

/** Pure planning: no sessions, transport, capability selection, evidence collection, or verdicts. */
export class SecurityTestPlanner implements TestPlanner {
  private readonly plugins: ReadonlyMap<string, PlanningPlugin>;
  private readonly maxPlans: number;
  constructor(options: TestPlannerOptions) {
    const plugins = new Map<string, PlanningPlugin>();
    for (const plugin of options.plugins) {
      if (!/^CWE-\d+$/.test(plugin.cweId)) throw new Error('Invalid planning plugin');
      if (plugins.has(plugin.cweId)) throw new Error('Duplicate planning plugin');
      plugins.set(plugin.cweId, plugin);
    }
    this.plugins = plugins;
    this.maxPlans = options.maxPlans ?? 64;
    if (!Number.isSafeInteger(this.maxPlans) || this.maxPlans < 1 || this.maxPlans > 1_000) throw new Error('Invalid planning limit');
  }

  /** The core port exposes only plans with satisfied planning prerequisites. Inspect plan() for blocked drafts. */
  async generateTests(context: AnalysisContext, hypothesis: SecurityHypothesis): Promise<readonly StructuredTestPlan[]> {
    return freeze((await this.plan(context, hypothesis)).plans.filter(plan => plan.readiness === 'READY'));
  }

  async plan(input: AnalysisContext, supplied: SecurityHypothesis, suppliedBindings: PlanningBindings = {}): Promise<PlanningResult> {
    const result = (plans: readonly StructuredTestPlan[], code?: PlanningDiagnostic['code']): PlanningResult =>
      freeze({ plans, diagnostics: code ? [{ code }] : [] });
    let context: AnalysisContext, model: ApplicationSecurityModel, hypothesis: SecurityHypothesis, bindings: PlanningBindings;
    try {
      context = freeze(structuredClone(input));
      model = freeze('schemaVersion' in context && context.schemaVersion === 1 ? context as ApplicationSecurityModel
        : buildApplicationSecurityModel({ project: context.project, identities: context.identities, contributions: [fromAnalysisContext(context)] }));
      hypothesis = freeze(structuredClone(supplied));
      bindings = freeze(structuredClone(suppliedBindings));
    } catch { return result([], 'invalid-hypothesis'); }
    const endpoint = validHypothesis(model, hypothesis);
    if (!endpoint) return result([], 'invalid-hypothesis');
    if (!isEndpointTestable(endpoint)) return result([], 'endpoint-unvalidated');
    const plugin = this.plugins.get(hypothesis.cweId), probe = probes[hypothesis.cweId];
    if (!plugin || !probe) return result([], 'unsupported-cwe');
    if (!validBindings(bindings, endpoint)) return result([], 'invalid-bindings');
    const injection = probe === 'xss' || probe === 'sql-injection';
    if (!(injection ? ['GET', 'POST'] : ['GET', 'HEAD']).includes(endpoint.method)) return result([], 'unsupported-method');
    let generated: readonly SecurityTestPlan[];
    // Keep the plugin's original endpoint/candidate identity when the caller used a flat core context.
    try { generated = structuredClone(await plugin.generateTests(context, hypothesis)); }
    catch { return result([], 'plugin-failed'); }
    if (!Array.isArray(generated)) return result([], 'invalid-plan');
    if (!generated.length) return result([], 'no-plans');
    const ids = new Set<string>();
    const seeds: Seed[] = [];
    // Validate the complete response before retaining any plan, including duplicate identities/IDs and foreign scopes.
    for (const plan of generated) {
      const seed = readSeed(plan, model, endpoint, hypothesis, probe);
      if (!seed || ids.has(seed.id)) return result([], 'invalid-plan');
      ids.add(seed.id); seeds.push(seed);
    }
    if (seeds.some(seed => seed.scope.parameter?.location === 'body' && endpoint.method !== 'POST')) return result([], 'unsupported-method');
    const plans = seeds.slice(0, this.maxPlans).map(seed => assemble(model, endpoint, hypothesis, seed, bindings));
    return result(plans, seeds.length > this.maxPlans ? 'plan-limit' : undefined);
  }
}

function validHypothesis(model: ApplicationSecurityModel, hypothesis: SecurityHypothesis): ModelEndpoint | undefined {
  if (!hypothesis || !text(hypothesis.id) || hypothesis.projectId !== model.project.id || hypothesis.status !== 'HYPOTHESIS'
    || !text(hypothesis.cweId) || !hypothesis.endpointId || !strings(hypothesis.evidenceIds) || !hypothesis.evidenceIds.length) return;
  const endpoint = resolveEndpoint(model, hypothesis.endpointId);
  if (!endpoint || !safeTarget(endpoint.path, endpoint.origin, model.project.allowedOrigins)) return;
  const linked = new Set([...endpoint.evidenceIds,
    ...model.signals.filter(signal => signal.cweIds.includes(hypothesis.cweId)
      && signal.endpointId && resolveEndpoint(model, signal.endpointId)?.id === endpoint.id).flatMap(signal => signal.evidenceIds),
    ...[...model.cookies, ...model.corsConfigurations, ...model.dataFlows, ...model.databaseOperations, ...model.observedOwnership, ...model.resourceTypes]
      .filter(fact => fact.endpointIds.includes(endpoint.id) || !fact.endpointIds.length && ['cookie', 'cors'].includes(fact.kind))
      .flatMap(fact => fact.evidenceIds),
    ...model.resources.filter(resource => resource.projectId === model.project.id && resource.endpointId
      && resolveEndpoint(model, resource.endpointId)?.id === endpoint.id).flatMap(resource => resource.evidenceIds)]);
  const evidence = new Map(model.evidence.map(item => [item.id, item]));
  if (hypothesis.evidenceIds.some(id => evidence.get(id)?.projectId !== model.project.id
    || !linked.has(id) && (!evidence.get(id)?.endpointId || resolveEndpoint(model, evidence.get(id)!.endpointId!)?.id !== endpoint.id))) return;
  return endpoint;
}

function safeTarget(path: string, origin: string, allowedOrigins: readonly string[]): string | undefined {
  try {
    if (!path.startsWith('/') || path.startsWith('//') || /[\\?#()*{}\s]/.test(path)
      || path.split('/').some(segment => segment.includes(':') && !/^:[A-Za-z_][A-Za-z0-9_]*$/.test(segment))) return;
    const base = new URL(origin), url = new URL(path, base);
    if (!['https:', 'http:'].includes(url.protocol) || base.username || base.password || base.search || base.hash
      || url.origin !== base.origin || !allowedOrigins.includes(url.origin) || url.pathname !== path) return;
    return url.href;
  } catch { return; }
}

function readSeed(plan: SecurityTestPlan, model: ApplicationSecurityModel, endpoint: ModelEndpoint,
  hypothesis: SecurityHypothesis, probe: ProbeId): Seed | undefined {
  if (!record(plan)) return;
  const raw = plan as unknown as Record<string, unknown>, s = raw.scope;
  if (!text(plan.id) || plan.hypothesisId !== hypothesis.id || plan.cweId !== hypothesis.cweId || raw.probeId !== probe
    || !record(s) || s.projectId !== model.project.id || s.method !== endpoint.method
    || plan.targetUrl !== safeTarget(endpoint.path, endpoint.origin, model.project.allowedOrigins) || s.targetUrl !== plan.targetUrl
    || !strings(plan.identityIds) || new Set(plan.identityIds).size !== plan.identityIds.length
    || !strings(s.identityIds) || JSON.stringify(s.identityIds) !== JSON.stringify(plan.identityIds)
    || !strings(plan.requiredCapabilities)) return;
  let parameter: PlanScope['parameter'];
  if (s.parameter !== undefined) {
    const point = s.parameter;
    if (!record(point) || !text(point.name) || !['query', 'body'].includes(point.location as string)
      || !endpoint.parameters.some(item => item.name === point.name && item.location === point.location)) return;
    parameter = { name: point.name, location: point.location as 'query' | 'body' };
  }
  if ((probe === 'xss' || probe === 'sql-injection') && !parameter) return;
  let authorization: AccessPolicy | undefined;
  if (s.authorization !== undefined) {
    const policy = s.authorization;
    if (!record(policy) || !text(policy.resourceId) || !text(policy.ownerIdentityId) || !text(policy.attackerIdentityId)
      || typeof policy.attackerIsUnauthorized !== 'boolean' || typeof policy.anonymousIsUnauthorized !== 'boolean') return;
    authorization = { resourceId: policy.resourceId, ownerIdentityId: policy.ownerIdentityId, attackerIdentityId: policy.attackerIdentityId,
      attackerIsUnauthorized: policy.attackerIsUnauthorized, anonymousIsUnauthorized: policy.anonymousIsUnauthorized };
    if (JSON.stringify(plan.identityIds) !== JSON.stringify([authorization.ownerIdentityId, authorization.attackerIdentityId])) return;
  }
  if (s.sensitiveCookieNames !== undefined && !strings(s.sensitiveCookieNames)
    || s.untrustedOrigins !== undefined && (!strings(s.untrustedOrigins) || !s.untrustedOrigins.every(value => validOrigin(value, endpoint.origin)))) return;
  return { id: plan.id, probeId: probe, requiredCapabilities: [...plan.requiredCapabilities], scope: {
    projectId: model.project.id, targetUrl: plan.targetUrl, method: endpoint.method, identityIds: [...plan.identityIds],
    ...(parameter ? { parameter } : {}), ...(authorization ? { authorization } : {}),
    ...(probe === 'cookie-security' ? { sensitiveCookieNames: [...new Set(s.sensitiveCookieNames as string[] ?? [])] } : {}),
    ...(probe === 'cross-origin' ? { untrustedOrigins: [...new Set(s.untrustedOrigins as string[] ?? [])] } : {}),
  } };
}

function validBindings(bindings: PlanningBindings, endpoint: Endpoint): boolean {
  if (!record(bindings) || bindings.identityId !== undefined && !text(bindings.identityId)
    || bindings.allowAnonymous !== undefined && typeof bindings.allowAnonymous !== 'boolean'
    || bindings.bodyEncoding !== undefined && !['json-body', 'form-body'].includes(bindings.bodyEncoding as string)) return false;
  const seen = new Set<string>();
  if (bindings.inputs !== undefined && !Array.isArray(bindings.inputs)) return false;
  return (bindings.inputs ?? []).every((input: InputBinding) => {
    if (!record(input) || !text(input.name) || !text(input.valueRef) || input.valueRef.length > 256
      || !(endpoint.parameters.some(parameter => parameter.name === input.name && parameter.location === input.location)
        || input.location === 'path' && endpoint.path.split('/').includes(`:${input.name}`))
      || input.location === 'cookie' || input.location === 'header' && /^(authorization|cookie|host|origin)$/i.test(input.name)) return false;
    const key = JSON.stringify([input.location, input.name]);
    if (seen.has(key)) return false;
    seen.add(key); return true;
  });
}

function assemble(model: ApplicationSecurityModel, endpoint: ModelEndpoint, hypothesis: SecurityHypothesis,
  seed: Seed, bindings: PlanningBindings): StructuredTestPlan {
  const prerequisites: PlanPrerequisite[] = [];
  const need = (code: PlanPrerequisite['code']) => { if (!prerequisites.some(item => item.code === code)) prerequisites.push({ code }); };
  let scope = structuredClone(seed.scope);
  const probe = seed.probeId, policy = scope.authorization;
  if (probe !== 'authorization' && bindings.identityId !== undefined) {
    if (!scope.identityIds.includes(bindings.identityId)) need('eligible-identity-required');
    else scope = { ...scope, identityIds: [bindings.identityId] };
  }
  const authenticated = (id: string) => model.identities.find(identity => identity.id === id && identity.authentication !== 'anonymous');
  if (probe === 'authorization') {
    if (!policy) need('authorization-policy-required');
    else {
      const owner = authenticated(policy.ownerIdentityId), attacker = authenticated(policy.attackerIdentityId);
      if (!owner || !attacker || owner.id === attacker.id) need('distinct-authenticated-identities-required');
      if (owner && !endpoint.roles.every(role => owner.roles.includes(role))) need('eligible-identity-required');
      if (hypothesis.cweId === 'CWE-639' ? !policy.attackerIsUnauthorized : !policy.attackerIsUnauthorized && !policy.anonymousIsUnauthorized) need('unauthorized-control-required');
      const resources = model.resources.filter(resource => resource.id === policy.resourceId && resource.projectId === model.project.id
        && resource.endpointId && resolveEndpoint(model, resource.endpointId)?.id === endpoint.id);
      const ownership = model.observedOwnership.filter(fact => fact.details.resourceId === policy.resourceId && fact.endpointIds.includes(endpoint.id));
      if (!resources.length || !ownership.some(fact => fact.details.ownerIdentityId === policy.ownerIdentityId)) need('owned-resource-required');
      if (resources.some(resource => resource.ownerIdentityId && resource.ownerIdentityId !== policy.ownerIdentityId)
        || ownership.some(fact => fact.details.ownerIdentityId !== policy.ownerIdentityId)) need('conflicting-ownership');
    }
  } else {
    if (scope.identityIds.some(id => !authenticated(id))) need('eligible-identity-required');
    if ((endpoint.authentication === 'required' || endpoint.roles.length) && !scope.identityIds.some(id => {
      const identity = authenticated(id); return identity && endpoint.roles.every(role => identity.roles.includes(role));
    })) need('eligible-identity-required');
    if (endpoint.authentication === 'unknown' && !scope.identityIds.length && !bindings.allowAnonymous) need('authentication-unknown');
  }
  if (probe === 'cookie-security' && !scope.sensitiveCookieNames?.length) need('sensitive-cookie-names-required');
  if (probe === 'cross-origin' && !scope.untrustedOrigins?.length) need('untrusted-origins-required');
  if (hypothesis.cweId === 'CWE-614' && new URL(scope.targetUrl).protocol !== 'https:') need('https-required');
  const parameters: PlannedParameter[] = endpoint.parameters.map(parameter => {
    const input = bindings.inputs?.find(item => item.name === parameter.name && item.location === parameter.location);
    // Probes need an explicit original value even when the tested injection parameter is optional to the application.
    const isRequired = parameter.required || parameter.location === 'path'
      || scope.parameter?.name === parameter.name && scope.parameter.location === parameter.location;
    if (isRequired && !input) prerequisites.push({ code: 'input-required', parameter: { name: parameter.name, location: parameter.location } });
    return { name: parameter.name, location: parameter.location, required: isRequired,
      source: input ? { kind: 'private-input', ref: input.valueRef } : null };
  });
  // Route placeholders must have declarations and bindings, even when an extractor omitted a parameter.
  for (const segment of endpoint.path.split('/').filter(segment => segment.startsWith(':'))) {
    const name = segment.slice(1);
    if (!parameters.some(parameter => parameter.name === name && parameter.location === 'path')) {
      const input = bindings.inputs?.find(item => item.name === name && item.location === 'path');
      parameters.push({ name, location: 'path', required: true, source: input ? { kind: 'private-input', ref: input.valueRef } : null });
      if (!input) prerequisites.push({ code: 'input-required', parameter: { name, location: 'path' } });
    }
  }
  if ((scope.parameter?.location === 'body' || parameters.some(parameter => parameter.location === 'body' && parameter.source))
    && !bindings.bodyEncoding) need('body-encoding-required');
  const capabilities = [...new Set([`probe:${probe}`, ...required[probe], ...seed.requiredCapabilities,
    ...(scope.identityIds.length ? ['authentication-manager', ...(probe === 'cookie-security' ? ['cookie-inspector'] : [])] : [])])];
  const limitations = [
    'Planning readiness does not approve execution or establish capability availability.',
    'Private input references must be resolved and the exact target scope checked by the execution host.',
    ...(probe === 'authorization' ? ['Owner content markers must be established privately; HTTP success or body equality alone is insufficient.'] : []),
    ...(probe === 'cross-origin' ? ['Credentialed wildcard responses establish a configuration issue; browsers reject wildcard credentialed reads.'] : []),
    ...(probe === 'xss' ? ['Reflection and visible canaries do not establish script execution; missing execution coverage is inconclusive.'] : []),
    ...(probe === 'sql-injection' ? ['Generic errors, timing differences and scanner difference flags alone do not establish injection.'] : []),
  ];
  return freeze({ schemaVersion: 1, id: seed.id, projectId: model.project.id, endpointId: endpoint.id,
    hypothesisId: hypothesis.id, cweId: hypothesis.cweId, probeId: probe, executor: 'scanner',
    scope, targetUrl: scope.targetUrl, identityIds: scope.identityIds,
    identities: probe === 'authorization' ? { owner: policy?.ownerIdentityId ?? null, attacker: policy?.attackerIdentityId ?? null, anonymous: null }
      : { primary: scope.identityIds[0] ?? null },
    // Authentication and apparently read-only endpoints may change server state; planning never treats them as passive approval.
    risk: 'active', readiness: prerequisites.length ? 'BLOCKED' : 'READY', prerequisites,
    requiredCapabilities: capabilities, optionalCapabilities: optional[probe].filter(capability => !capabilities.includes(capability)),
    request: { method: endpoint.method, urlTemplate: scope.targetUrl, parameters,
      ...(bindings.bodyEncoding ? { bodyEncoding: bindings.bodyEncoding } : {}) },
    steps: steps(probe, scope), verification: verification(probe, hypothesis.cweId, scope),
    evidenceIds: [...hypothesis.evidenceIds], limitations });
}

function validOrigin(value: string, targetOrigin: string): boolean {
  if (value === 'null') return true;
  try { const origin = new URL(value); return ['http:', 'https:'].includes(origin.protocol)
    && origin.origin === value && value !== targetOrigin; } catch { return false; }
}
function text(value: unknown): value is string { return typeof value === 'string' && value.length > 0 && !/[\r\n\0]/.test(value); }
function strings(value: unknown): value is string[] { return Array.isArray(value) && value.every(text); }
function record(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function freeze<T>(value: T): T {
  if (value && typeof value === 'object') { for (const item of Object.values(value)) freeze(item); Object.freeze(value); }
  return value;
}

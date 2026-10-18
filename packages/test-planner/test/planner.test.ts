import { describe, expect, it, vi } from 'vitest';
import { MVP_CWES, type SecurityTestPlan } from '@agento/core';
import { SecurityHypothesisEngine } from '@agento/hypothesis-engine';
import { SecurityTestPlanner, type PlanningBindings } from '../src/index.js';
import { bindings, candidate, evidence, flatModel, model, plugins, policy, project, ruleOptions } from './helpers.js';

describe('structured security planning', () => {
  for (const fixed of [false, true]) {
    it.each(MVP_CWES)('creates a deterministic plan for %s (fixed target: ' + fixed + ')', async cwe => {
      const { planner, context, hypothesis, rule } = await candidate(cwe, model(fixed));
      const before = JSON.stringify(context);
      const result = await planner.plan(context, hypothesis, bindings);
      expect(result.diagnostics).toEqual([]); expect(result.plans).toHaveLength(1);
      const plan = result.plans[0]!;
      expect(plan).toMatchObject({ schemaVersion: 1, hypothesisId: hypothesis.id, cweId: cwe, readiness: 'READY', prerequisites: [] });
      expect(plan.id).toBe((await rule.generateTests(context, hypothesis))[0]!.id);
      expect(plan.request.urlTemplate).toBe('https://shop.test/orders/:id');
      expect(plan.requiredCapabilities).toContain(`probe:${plan.probeId}`);
      expect(plan.steps.length).toBeGreaterThan(2);
      expect(plan.steps.at(-1)!.action).toBe('verify');
      for (const [index, step] of plan.steps.entries()) {
        expect(step.dependsOn).toEqual(index ? [plan.steps[index - 1]!.id] : []);
        expect(step.onFailure).toBe('INCONCLUSIVE'); expect(step.parameters).toBeTypeOf('object');
      }
      expect(plan.verification.otherwise).toBe('INCONCLUSIVE');
      expect(plan.evidenceIds).toEqual(hypothesis.evidenceIds);
      expect(JSON.parse(JSON.stringify(plan))).toEqual(plan);
      expect(Object.isFrozen(plan.steps[0]!.parameters)).toBe(true);
      expect(await planner.plan(context, hypothesis, bindings)).toEqual(result);
      expect(JSON.stringify(context)).toBe(before);
      expect(JSON.stringify(plan)).not.toMatch(/PRIVATE_|curl|axios|Dalfox|sqlmap|playwright|puppeteer|sessionRef/);
    });
  }

  it('declares owner, attacker and anonymous control requests with structured comparison criteria', async () => {
    const { planner, context, hypothesis } = await candidate();
    const plan = (await planner.plan(context, hypothesis, bindings)).plans[0]!;
    expect(plan.identities).toEqual({ owner: 'alice', attacker: 'bob', anonymous: null });
    expect(plan.steps.map(step => step.action)).toEqual(['session.establish', 'resource.identify', 'request.baseline',
      'session.establish', 'request.as-attacker', 'request.anonymous', 'responses.compare', 'verify']);
    expect(plan.verification).toMatchObject({ strategy: 'authorization', controls: ['attacker'],
      violation: { ownerMarkersMatch: true, statusRange: [200, 299] }, secure: { deniedStatuses: [401, 403, 404] } });
    const other = await candidate('CWE-862');
    expect((await other.planner.plan(other.context, other.hypothesis, bindings)).plans[0]!.verification)
      .toMatchObject({ controls: ['attacker', 'anonymous'] });
  });

  it('selects HttpOnly and Secure independently and requires actual CORS responses', async () => {
    for (const [cwe, attribute] of [['CWE-1004', 'httpOnly'], ['CWE-614', 'secure']]) {
      const { planner, context, hypothesis } = await candidate(cwe);
      expect((await planner.plan(context, hypothesis, bindings)).plans[0]!.verification)
        .toMatchObject({ strategy: 'cookie-attribute', attribute, cookieNames: ['sid'] });
    }
    const { planner, context, hypothesis } = await candidate('CWE-942');
    const plan = (await planner.plan(context, hypothesis, bindings)).plans[0]!;
    expect(plan.steps.map(step => step.action)).toContain('cors.actual');
    expect(plan.verification.evidenceRequirements).toContain('actual-response-required');
    expect(plan.limitations.join(' ')).toContain('browsers reject');
  });

  it('requires execution proof for XSS and balanced SQL controls', async () => {
    const xss = await candidate('CWE-79');
    const xssPlan = (await xss.planner.plan(xss.context, xss.hypothesis, bindings)).plans[0]!;
    expect(xssPlan.verification).toMatchObject({ violation: { executionConfirmed: true }, secure: { executionConfirmed: false, domSinkReached: false } });
    expect(xssPlan.optionalCapabilities).toContain('xss-scanner');
    const sql = await candidate('CWE-89');
    const sqlPlan = (await sql.planner.plan(sql.context, sql.hypothesis, bindings)).plans[0]!;
    expect(sqlPlan.steps.filter(step => step.action.startsWith('sql.')).map(step => step.action))
      .toEqual(['sql.syntax', 'sql.boolean-true', 'sql.boolean-false']);
    expect(sqlPlan.verification).toMatchObject({ strategy: 'sql-injection', baseline: { complete: true },
      secure: { allBodiesEqualBaseline: true, scannerObservedDifference: false } });
  });

  it('accepts grounded hypothesis-engine output and strips arbitrary hypothesis fields', async () => {
    const context = model(), rules = plugins();
    const hypotheses = await new SecurityHypothesisEngine({ plugins: rules, sensitiveCookieNames: ['sid'],
      untrustedOrigins: ['https://untrusted.test'] }).generate(context);
    expect(new Set(hypotheses.hypotheses.map(h => h.cweId))).toEqual(new Set(MVP_CWES));
    for (const hypothesis of hypotheses.hypotheses) {
      const result = await new SecurityTestPlanner({ plugins: rules }).plan(context,
        { ...hypothesis, scope: { targetUrl: 'https://evil.test', sessionRef: 'PRIVATE_HANDLE' } } as typeof hypothesis, bindings);
      expect(result.diagnostics).toEqual([]); expect(result.plans[0]!.readiness).toBe('READY');
      expect(result.plans[0]!.targetUrl).toBe('https://shop.test/orders/:id');
    }
  });

  it('works with a flat core context as well as the application model', async () => {
    const flat = flatModel(model());
    const rules = plugins(), hypothesis = (await rules[0]!.detectCandidates(flat))[0]!;
    const result = await new SecurityTestPlanner({ plugins: rules }).plan(flat, hypothesis, bindings);
    expect(result.diagnostics).toEqual([]); expect(result.plans[0]!.readiness).toBe('READY');
  });
});

describe('missing planning prerequisites', () => {
  it.each([
    ['CWE-639', {}, 'authorization-policy-required'],
    ['CWE-1004', {}, 'sensitive-cookie-names-required'],
    ['CWE-942', {}, 'untrusted-origins-required'],
    ['CWE-639', { ...ruleOptions, authorizationPolicies: [{ ...policy, attackerIsUnauthorized: false }] }, 'unauthorized-control-required'],
  ] as const)('blocks %s without %s', async (cwe, options, code) => {
    const { planner, context, hypothesis } = await candidate(cwe, model(), plugins(options));
    const result = await planner.plan(context, hypothesis, bindings);
    expect(result.plans[0]!.readiness).toBe('BLOCKED'); expect(result.plans[0]!.prerequisites).toContainEqual({ code });
    expect(await planner.generateTests(context, hypothesis)).toEqual([]);
  });

  it('keeps unresolved route parameters out of executable core plans', async () => {
    const { planner, context, hypothesis } = await candidate();
    const plan = (await planner.plan(context, hypothesis)).plans[0]!;
    expect(plan.readiness).toBe('BLOCKED');
    expect(plan.prerequisites).toContainEqual({ code: 'input-required', parameter: { name: 'id', location: 'path' } });
    expect(await planner.generateTests(context, hypothesis)).toEqual([]);
  });

  it('requires a baseline input for an optional injection parameter', async () => {
    const { planner, context, hypothesis } = await candidate('CWE-79');
    const result = await planner.plan(context, hypothesis, { inputs: [bindings.inputs![0]!] });
    expect(result.plans[0]!.readiness).toBe('BLOCKED');
    expect(result.plans[0]!.prerequisites).toContainEqual({ code: 'input-required', parameter: { name: 'q', location: 'query' } });
  });

  it('rejects body injection on a GET route supported only for POST bodies by the runtime', async () => {
    const { planner, context, hypothesis } = await candidate('CWE-79', model(false, { parameters: [{ name: 'q', location: 'body', required: false }] }));
    expect((await planner.plan(context, hypothesis)).diagnostics).toEqual([{ code: 'unsupported-method' }]);
  });

  it('does not introduce an identity outside the rule selection', async () => {
    const { planner, context, hypothesis } = await candidate('CWE-89');
    const result = await planner.plan(context, hypothesis, { ...bindings, identityId: 'bob' });
    expect(result.plans[0]!.readiness).toBe('BLOCKED');
    expect(result.plans[0]!.prerequisites).toContainEqual({ code: 'eligible-identity-required' });
    expect(result.plans[0]!.identityIds).toEqual(['alice']);
  });

  it('does not guess route placeholder bindings when extraction omits them', async () => {
    const { planner, context, hypothesis } = await candidate('CWE-639', model(false, { parameters: [] }));
    expect((await planner.plan(context, hypothesis)).plans[0]!.prerequisites)
      .toContainEqual({ code: 'input-required', parameter: { name: 'id', location: 'path' } });
    expect((await planner.plan(context, hypothesis, { inputs: [bindings.inputs![0]!] })).plans[0]!.readiness).toBe('READY');
  });

  it('requires HTTPS for Secure-cookie assessment without inventing a new origin', async () => {
    const target = { ...project, baseUrl: 'http://shop.test', allowedOrigins: ['http://shop.test'] };
    const { planner, context, hypothesis } = await candidate('CWE-614', model(false, {}, target));
    const plan = (await planner.plan(context, hypothesis, bindings)).plans[0]!;
    expect(plan.targetUrl).toBe('http://shop.test/orders/:id'); expect(plan.prerequisites).toContainEqual({ code: 'https-required' });
  });

  it('requires authenticated identities, role eligibility, and consistent ownership', async () => {
    const base = model();
    const cases = [
      { ...base, identities: [base.identities[0]!] },
      { ...base, identities: base.identities.map(identity => ({ ...identity, roles: [] })) },
      { ...base, resources: base.resources.map(resource => ({ ...resource, ownerIdentityId: 'bob' })) },
      { ...base, observedOwnership: [] },
    ];
    const codes = ['distinct-authenticated-identities-required', 'eligible-identity-required', 'conflicting-ownership', 'owned-resource-required'];
    for (const [index, context] of cases.entries()) {
      const rules = plugins(), hypothesis = (await rules[0]!.detectCandidates(context))[0]!;
      const result = await new SecurityTestPlanner({ plugins: rules }).plan(context, hypothesis, bindings);
      expect(result.plans[0]!.prerequisites).toContainEqual({ code: codes[index] });
    }
  });

  it('does not assume unknown authentication is anonymous', async () => {
    const { planner, context, hypothesis } = await candidate('CWE-79', model(false, { path: '/search', parameters: [{ name: 'q', location: 'query', required: false }],
      authentication: 'unknown', roles: [] }));
    expect((await planner.plan(context, hypothesis)).plans[0]!.prerequisites).toContainEqual({ code: 'authentication-unknown' });
    expect((await planner.plan(context, hypothesis, { allowAnonymous: true, inputs: [bindings.inputs![1]!] })).plans[0]!.readiness).toBe('READY');
  });

  it.each(['json-body', 'form-body'] as const)('requires explicit %s encoding for body injection', async bodyEncoding => {
    const { planner, context, hypothesis } = await candidate('CWE-89', model(false, { method: 'POST', path: '/search',
      parameters: [{ name: 'q', location: 'body', required: true }] }));
    const input: PlanningBindings = { inputs: [{ name: 'q', location: 'body', valueRef: 'baseline-query' }] };
    expect((await planner.plan(context, hypothesis, input)).plans[0]!.prerequisites).toContainEqual({ code: 'body-encoding-required' });
    const result = await planner.plan(context, hypothesis, { ...input, bodyEncoding });
    expect(result.plans[0]!.readiness).toBe('READY'); expect(result.plans[0]!.request.bodyEncoding).toBe(bodyEncoding);
  });
});

describe('input and provider validation', () => {
  it.each(['project', 'status', 'evidence', 'endpoint', 'empty-evidence'])('rejects invalid hypothesis %s', async field => {
    const { planner, context, hypothesis } = await candidate();
    const changed = { ...hypothesis, ...(field === 'project' ? { projectId: 'other' } : field === 'status' ? { status: 'CONFIRMED' as never }
      : field === 'endpoint' ? { endpointId: 'other' } : { evidenceIds: field === 'empty-evidence' ? [] : ['missing'] }) };
    expect(await planner.plan(context, changed, bindings)).toEqual({ plans: [], diagnostics: [{ code: 'invalid-hypothesis' }] });
  });

  it('rejects evidence belonging to an unrelated endpoint', async () => {
    const { planner, context, hypothesis } = await candidate();
    const changed = { ...context, evidence: [...context.evidence, evidence('unrelated', {}, { endpointId: 'elsewhere' })] };
    expect((await planner.plan(changed, { ...hypothesis, evidenceIds: ['unrelated'] }, bindings)).diagnostics).toEqual([{ code: 'invalid-hypothesis' }]);
  });

  it.each(['/orders/*', '/orders/:id?', '//other.test/path', '/orders/../private', '/orders?q=secret', '/orders/{id}'])('rejects ambiguous target %s', async path => {
    const fixture = await candidate();
    const context = { ...fixture.context, endpoints: fixture.context.endpoints.map(endpoint => ({ ...endpoint, path })) };
    expect((await fixture.planner.plan(context, fixture.hypothesis, bindings)).diagnostics).toEqual([{ code: 'invalid-hypothesis' }]);
  });

  it('rejects exact-origin scope violations', async () => {
    const { planner, context, hypothesis } = await candidate();
    expect((await planner.plan({ ...context, project: { ...context.project, allowedOrigins: ['https://shop.test:444'] } }, hypothesis)).diagnostics)
      .toEqual([{ code: 'invalid-hypothesis' }]);
  });

  it.each(['PUT', 'DELETE', 'PATCH', 'OPTIONS'] as const)('reports unsupported %s without calling a rule planner', async method => {
    const { rule, context, hypothesis } = await candidate('CWE-639', model(false, { method }));
    const generate = vi.spyOn(rule, 'generateTests');
    const result = await new SecurityTestPlanner({ plugins: [rule] }).plan(context, hypothesis, bindings);
    expect(result.diagnostics).toEqual([{ code: 'unsupported-method' }]); expect(generate).not.toHaveBeenCalled();
  });

  it('reports missing or unsupported CWE registration', async () => {
    const { context, hypothesis } = await candidate();
    expect((await new SecurityTestPlanner({ plugins: [] }).plan(context, hypothesis)).diagnostics).toEqual([{ code: 'unsupported-cwe' }]);
    expect((await new SecurityTestPlanner({ plugins: [] }).plan(context, { ...hypothesis, cweId: 'CWE-9999' })).diagnostics)
      .toEqual([{ code: 'unsupported-cwe' }]);
  });

  it.each(['target', 'project', 'probe', 'parameter', 'duplicate', 'identities'] as const)('rejects malformed provider plan %s', async mutation => {
    const { rule, context, hypothesis } = await candidate('CWE-79');
    const original = (await rule.generateTests(context, hypothesis))[0]!;
    const changed = { ...original,
      ...(mutation === 'target' ? { targetUrl: 'https://evil.test/' } : {}),
      ...(mutation === 'project' ? { scope: { ...original.scope, projectId: 'other' } } : {}),
      ...(mutation === 'probe' ? { probeId: 'sql-injection' } : {}),
      ...(mutation === 'parameter' ? { scope: { ...original.scope, parameter: { name: 'unknown', location: 'query' } } } : {}),
      ...(mutation === 'identities' ? { identityIds: ['alice', 'alice'] } : {}),
    } as SecurityTestPlan;
    const planner = new SecurityTestPlanner({ plugins: [{ cweId: rule.cweId, generateTests: async () => mutation === 'duplicate' ? [changed, changed] : [changed] }] });
    expect(await planner.plan(context, hypothesis, bindings)).toEqual({ plans: [], diagnostics: [{ code: 'invalid-plan' }] });
  });

  it.each([
    { inputs: [{ name: 'missing', location: 'query', valueRef: 'input' }] },
    { inputs: [...bindings.inputs!, ...bindings.inputs!] },
    { inputs: [{ name: 'id', location: 'path', valueRef: '' }] },
    { bodyEncoding: 'xml' },
  ])('rejects invalid input binding %j', async input => {
    const { planner, context, hypothesis } = await candidate();
    expect((await planner.plan(context, hypothesis, input as PlanningBindings)).diagnostics).toEqual([{ code: 'invalid-bindings' }]);
  });

  it('sanitizes provider errors and does not invoke candidate detection or evidence evaluation', async () => {
    const { rule, context, hypothesis } = await candidate();
    const detect = vi.spyOn(rule, 'detectCandidates'), evaluate = vi.spyOn(rule, 'evaluateEvidence');
    vi.spyOn(rule, 'generateTests').mockRejectedValue(new Error('PRIVATE_SESSION_SECRET'));
    const result = await new SecurityTestPlanner({ plugins: [rule] }).plan(context, hypothesis, bindings);
    expect(result).toEqual({ plans: [], diagnostics: [{ code: 'plugin-failed' }] });
    expect(detect).not.toHaveBeenCalled(); expect(evaluate).not.toHaveBeenCalled();
  });

  it('reports no plans and bounds returned plan counts', async () => {
    const { rule, context, hypothesis } = await candidate();
    const base = (await rule.generateTests(context, hypothesis))[0]!;
    const none = new SecurityTestPlanner({ plugins: [{ cweId: rule.cweId, generateTests: async () => [] }] });
    expect((await none.plan(context, hypothesis)).diagnostics).toEqual([{ code: 'no-plans' }]);
    const planner = new SecurityTestPlanner({ maxPlans: 1, plugins: [{ cweId: rule.cweId,
      generateTests: async () => [base, { ...base, id: `${base.id}:second` }] }] });
    const result = await planner.plan(context, hypothesis, bindings);
    expect(result.plans).toHaveLength(1); expect(result.diagnostics).toEqual([{ code: 'plan-limit' }]);
  });

  it('rejects duplicate plugins and invalid limits', () => {
    const rule = plugins()[0]!;
    expect(() => new SecurityTestPlanner({ plugins: [rule, rule] })).toThrow('Duplicate');
    for (const maxPlans of [0, -1, 1.5, 1_001, Infinity]) expect(() => new SecurityTestPlanner({ plugins: [rule], maxPlans })).toThrow('limit');
  });
});

import { describe, expect, it } from 'vitest';
import { AgentOOrchestrator, type CoreProviders, type Evidence, type SecurityScanner } from '@agento/core';
import { buildApplicationSecurityModel, fromAnalysisContext } from '@agento/security-model';
import {
  CWE79Plugin, CWE89Plugin, CWE639Plugin, CWE862Plugin, CWE942Plugin, CWE1004Plugin, CWE614Plugin,
  CWEPluginRegistry, EvidenceCWEPlugin, fromCoreEvidence, toCoreEvidence,
} from '../src/index.js';
import type { CWEPlugin, EvaluationScope } from '../src/index.js';
import type { CookieSecurityEvidence } from '@agento/runtime';
import { context, cookies, cors, authorization, xss, sql, endpoint, policy, project, route, scope } from './helpers.js';

const options = { sensitiveCookieNames: ['sid'], untrustedOrigins: ['https://unapproved.invalid'], authorizationPolicies: [policy] };
const plugins = () => [new CWE79Plugin(options), new CWE89Plugin(options), new CWE639Plugin(options), new CWE862Plugin(options),
  new CWE942Plugin(options), new CWE1004Plugin(options), new CWE614Plugin(options)];

describe('application model candidates and declarative probe plans', () => {
  it.each(plugins())('%s generates immutable, evidence-linked hypotheses from a full model', async plugin => {
    const input = context(); const model = buildApplicationSecurityModel({ project, identities: input.identities,
      contributions: [fromAnalysisContext(input)] });
    const candidates = await plugin.detectCandidates(model);
    expect(candidates).toHaveLength(1);
    expect(candidates[0]).toMatchObject({ status: 'HYPOTHESIS', projectId: project.id, cweId: plugin.cweId, evidenceIds: ['route'] });
    expect(Object.isFrozen(candidates[0]!.scope)).toBe(true);
    const plans = await plugin.generateTests(model, candidates[0]!);
    expect(plans[0]).toMatchObject({ hypothesisId: candidates[0]!.id, probeId: plugin.metadata().probeId,
      requiredCapabilities: expect.arrayContaining([`probe:${plugin.metadata().probeId}`]), targetUrl: scope.targetUrl });
    expect(plans[0]!.steps[0]!.action).toBe('probe.collect');
    expect(JSON.stringify(plans)).not.toMatch(/playwright|dalfox|sqlmap|selector|payload/i);
  });
  it('supports the single-hypothesis planning API and the existing core API', async () => {
    const plugin = new CWE1004Plugin(options), input = context(), candidate = (await plugin.detectCandidates(input))[0]!;
    expect(await plugin.generateTests(candidate)).toEqual(await plugin.generateTests(input, candidate));
  });
  it('declares authenticated collection identities and the capabilities required to inspect their cookies', async () => {
    const input = context(), plugin = new CWE1004Plugin(options), candidate = (await plugin.detectCandidates(input))[0]!;
    const plan = (await plugin.generateTests(input, candidate))[0]!;
    expect(plan.identityIds).toEqual(['alice', 'bob']);
    expect(plan.requiredCapabilities).toEqual(expect.arrayContaining(['authentication-manager', 'cookie-inspector']));
  });
  it('binds model endpoint aliases and origins without broadening project scope', async () => {
    const input = context();
    const model = buildApplicationSecurityModel({ project, identities: input.identities,
      contributions: [{ ...fromAnalysisContext(input), endpointOrigins: { order: 'https://api.shop.test' } }] });
    expect((await new CWE942Plugin(options).detectCandidates(model))[0]!.scope.targetUrl).toBe('https://api.shop.test/orders/1');
    const forbidden = context({ endpoints: [endpoint({ path: 'https://forbidden.test/orders/1' })] });
    expect(await new CWE942Plugin().detectCandidates(forbidden)).toEqual([]);
  });
  it('does not invent injection points, cookie sensitivity, or SQL candidates', async () => {
    const empty = context({ endpoints: [endpoint({ parameters: [] })], signals: [] });
    expect(await new CWE79Plugin().detectCandidates(empty)).toEqual([]);
    expect(await new CWE89Plugin().detectCandidates(context({ signals: [] }))).toEqual([]);
    expect((await new CWE1004Plugin().detectCandidates(context()))[0]!.scope.sensitiveCookieNames).toEqual([]);
  });
  it('retains parameterless SQL signals as hypotheses without inventing an executable test', async () => {
    const input = context({ endpoints: [endpoint({ parameters: [] })] }), plugin = new CWE89Plugin();
    const candidate = (await plugin.detectCandidates(input))[0]!;
    expect(candidate.status).toBe('HYPOTHESIS'); expect(await plugin.generateTests(input, candidate)).toEqual([]);
  });
  it('does not generate a probe request for an unsupported destructive method', async () => {
    const input = context({ endpoints: [endpoint({ method: 'DELETE' })] }), plugin = new CWE942Plugin();
    const candidate = (await plugin.detectCandidates(input))[0]!;
    expect(await plugin.generateTests(input, candidate)).toEqual([]);
  });
  it('distinguishes multiple attackers and deduplicates repeated policies', async () => {
    const input = context(), second = { ...policy, attackerIdentityId: 'charlie' };
    const plugin = new CWE639Plugin({ authorizationPolicies: [policy, second, policy] });
    const candidates = await plugin.detectCandidates(input);
    expect(candidates).toHaveLength(2); expect(new Set(candidates.map(candidate => candidate.id)).size).toBe(2);
  });
  it('uses explicit sensitive cookie model facts without treating configuration as runtime proof', async () => {
    const model = buildApplicationSecurityModel({ project, identities: context().identities, contributions: [{ ...fromAnalysisContext(context()),
      facts: [{ kind: 'cookie', endpointIds: ['order'], evidenceIds: ['route'], details: { name: 'sid', sensitive: true, httpOnly: false } }] }] });
    const plugin = new CWE1004Plugin(), candidate = (await plugin.detectCandidates(model))[0]!;
    expect(candidate.scope.sensitiveCookieNames).toEqual(['sid']);
    expect((await plugin.evaluateEvidence(model, candidate, [])).status).toBe('NOT_REPRODUCED');
  });
  it('rejects forged hypotheses and reconstructs scope rather than trusting modified JSON', async () => {
    const input = context(), plugin = new CWE1004Plugin(options), hypothesis = (await plugin.detectCandidates(input))[0]!;
    await expect(plugin.generateTests(input, { ...hypothesis, projectId: 'other' })).rejects.toThrow('Invalid rule hypothesis');
    await expect(plugin.generateTests(input, { ...hypothesis, id: 'other' })).rejects.toThrow('Unknown rule hypothesis');
    const forged = { ...hypothesis, scope: { ...hypothesis.scope, targetUrl: 'https://forbidden.test' } };
    const plans = await plugin.generateTests(input, forged);
    expect(plans[0]!.targetUrl).toBe(scope.targetUrl);
  });
});
describe('core evidence bridge', () => {
  it.each(['scanner-failed', 'scanner-skipped'] as const)('preserves incomplete scanner coverage: %s', diagnostic => {
    const probe = { ...sql(), outcome: 'PARTIAL' as const, diagnostics: [diagnostic] };
    expect(fromCoreEvidence(toCoreEvidence(probe))).toEqual(probe);
  });
  it.each([cookies(), cors(), authorization(), xss(), sql()])('round trips only normalized public observations', probe => {
    expect(fromCoreEvidence(toCoreEvidence(probe, 'order'))).toEqual(probe);
  });
  it('projects private extras at every nested boundary and redacts query values', () => {
    const probe = cookies(); const item = probe.observations[0]!;
    Object.assign(probe, { password: 'private-password' });
    Object.assign(item.response, { headers: { authorization: 'private-token' }, value: 'private-response-value', url: `${scope.targetUrl}?token=private-query` });
    Object.assign(item.response.body, { data: 'private-body' }); Object.assign(item.cookies[0]!, { rawValue: 'private-cookie' });
    const wrapped = toCoreEvidence(probe, 'order');
    expect(JSON.stringify(wrapped)).not.toMatch(/private-/); expect(Object.isFrozen(wrapped.facts.probe)).toBe(true);
    expect(fromCoreEvidence(wrapped)).toBeDefined();
    expect(Object.isFrozen(probe.diagnostics)).toBe(false);
    expect(Object.isFrozen(probe.observations[0]!.cookies)).toBe(false);
  });
  it.each(['id', 'projectId', 'capturedAt', 'producerId'] as const)('rejects inconsistent envelope %s', field => {
    expect(fromCoreEvidence({ ...toCoreEvidence(cookies()), [field]: 'mismatch' })).toBeUndefined();
  });
  it('rejects malformed normalized fields and raw cookie values', () => {
    const probe = cookies(); Object.assign(probe.observations[0]!.cookies[0]!, { value: 'private' });
    expect(() => toCoreEvidence(probe)).toThrow('Invalid normalized probe evidence');
    const wrapped = toCoreEvidence(cookies());
    expect(fromCoreEvidence({ ...wrapped, facts: { ...wrapped.facts, schemaVersion: 2 } })).toBeUndefined();
  });
});
describe('independent registration and unchanged core orchestration', () => {
  it('registers all seven independently and rejects duplicates, missing entries and mismatched metadata', () => {
    const registry = new CWEPluginRegistry();
    for (const plugin of plugins()) { registry.register(plugin); expect(registry.get(plugin.cweId)).toBe(plugin); }
    expect(registry.list()).toHaveLength(7); expect(Object.isFrozen(registry.list()[0]!.requiredCapabilities)).toBe(true);
    expect(() => registry.register(new CWE79Plugin())).toThrow('duplicate');
    expect(() => registry.get('CWE-999999')).toThrow('not registered');
    const mismatch = new CWE1004Plugin(); Object.defineProperty(mismatch, 'cweId', { value: 'CWE-99999' });
    expect(() => new CWEPluginRegistry().register(mismatch)).toThrow('Invalid');
  });
  function providers(rule: CWEPlugin, scanner?: SecurityScanner): CoreProviders {
    const input = context();
    return { plugins: [rule], frameworkAdapter: { id: 'fake-framework', capabilities: ['routes'], supports: async () => true,
      extract: async () => ({ components: input.components, endpoints: input.endpoints, resources: input.resources,
        signals: input.signals, evidence: input.evidence }) }, ...(scanner ? { scanner } : {}) };
  }
  it.each(plugins())('%s runs through the original core lifecycle with an injected probe provider', async rule => {
    const record = { 'cookie-security': cookies(), 'cross-origin': cors(), authorization: authorization(), xss: xss(), 'sql-injection': sql() }[rule.metadata().probeId];
    const scanner: SecurityScanner = { id: 'fake-probe-host', capabilities: [`probe:${rule.metadata().probeId}`, ...rule.metadata().requiredCapabilities, 'authentication-manager', 'cookie-inspector'],
      execute: async (_context, plan) => ({ id: `result:${plan.id}`, planId: plan.id, producerId: 'fake-probe-host', outcome: 'COMPLETED',
        summary: 'Synthetic probe host', evidence: [toCoreEvidence(record, 'order')] }) };
    const report = await new AgentOOrchestrator(providers(rule, scanner)).run({ project, identities: context().identities });
    expect(report.findings[0]).toMatchObject({ cweId: rule.cweId, status: 'CONFIRMED', evidenceIds: [record.id] });
  });
  it('keeps absent execution providers unconfirmed', async () => {
    const report = await new AgentOOrchestrator(providers(new CWE1004Plugin(options))).run({ project, identities: [] });
    expect(report.results[0]!.outcome).toBe('SKIPPED'); expect(report.findings[0]!.status).toBe('NOT_REPRODUCED');
  });
  it.each(['FAILED', 'SKIPPED'] as const)('ignores even apparently positive evidence in %s results', async outcome => {
    const plugin = new CWE1004Plugin(options), input = context(), candidate = (await plugin.detectCandidates(input))[0]!;
    const plan = (await plugin.generateTests(input, candidate))[0]!;
    const finding = await plugin.evaluateEvidence(input, candidate, [{ id: 'failed', planId: plan.id, producerId: 'test', outcome,
      summary: 'Not executed', evidence: [toCoreEvidence(cookies(), 'order')] }]);
    expect(finding.status).toBe('NOT_REPRODUCED'); expect(finding.evidenceIds).toEqual([]);
  });
  it.each(['wrong-plan', 'wrong-endpoint', 'wrong-project', 'source-only'] as const)('ignores %s evidence', async kind => {
    const plugin = new CWE1004Plugin(options), input = context(), candidate = (await plugin.detectCandidates(input))[0]!;
    const plan = (await plugin.generateTests(input, candidate))[0]!;
    const evidence: Evidence = kind === 'source-only' ? route : toCoreEvidence(cookies(kind === 'wrong-project' ? { projectId: 'other' } : {}), kind === 'wrong-endpoint' ? 'other' : 'order');
    const finding = await plugin.evaluateEvidence(input, candidate, [{ id: 'result', planId: kind === 'wrong-plan' ? 'other' : plan.id,
      producerId: 'test', outcome: 'COMPLETED', summary: 'Synthetic result', evidence: [evidence] }]);
    expect(finding.status).toBe('NOT_REPRODUCED');
  });
  it('accepts a new mock CWE with no edits to core or probes', async () => {
    class MockCWEPlugin extends EvidenceCWEPlugin<'cookie-security'> {
      constructor() { super({ cweId: 'CWE-999999', title: 'Synthetic cookie policy', owaspCategory: 'test', severity: 'info',
        probeId: 'cookie-security', requiredCapabilities: [], optionalCapabilities: [] }); }
      protected isCandidate() { return true; }
      protected interpret(_evidence: CookieSecurityEvidence, _scope: EvaluationScope) {
        return { status: 'REJECTED' as const, summary: 'Synthetic negative policy.' };
      }
    }
    const registry = new CWEPluginRegistry().register(new MockCWEPlugin());
    const scanner: SecurityScanner = { id: 'mock-probe-host', capabilities: ['probe:cookie-security', 'authentication-manager', 'cookie-inspector'],
      execute: async (_context, plan) => ({ id: 'mock-result', planId: plan.id, producerId: 'mock-probe-host', outcome: 'COMPLETED',
        summary: 'Synthetic observations', evidence: [toCoreEvidence(cookies(), 'order')] }) };
    const report = await new AgentOOrchestrator(providers(registry.get('CWE-999999'), scanner)).run({ project, identities: context().identities });
    expect(report.hypotheses[0]!.cweId).toBe('CWE-999999'); expect(report.plans[0]!.steps[0]!.parameters.probeId).toBe('cookie-security');
    expect(report.findings[0]!.status).toBe('REJECTED');
  });
});

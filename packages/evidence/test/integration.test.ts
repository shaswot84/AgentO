import { readFile } from 'node:fs/promises';
import { describe, expect, it, vi } from 'vitest';
import { AgentOOrchestrator, type Evidence, type SecurityTestPlan } from '@agento/core';
import { CapabilityRegistry, CookieSecurityProbe, NormalizedCookieAnalyzer, NormalizedResponseCollector } from '@agento/runtime';
import { CWE614Plugin, fromCoreEvidence, toCoreEvidence } from '@agento/cwe';
import { NucleiAdapter } from '@agento/security-scanners';
import { MemoryEvidenceStore, verifyEvidenceBundle } from '../src/index.js';
import { fakeProviders, project, scope } from './helpers.js';

describe('core and adapter evidence boundaries', () => {
  it('retains source, static, browser and execution evidence before consumers see it', async () => {
    const providers = fakeProviders();
    const store = new MemoryEvidenceStore({ secrets: ['PRIVATE_TOKEN'] });
    const capture = vi.spyOn(store, 'capture');
    const execute = providers.scanner!.execute.bind(providers.scanner);
    vi.spyOn(providers.scanner!, 'execute').mockImplementation(async (...args) => {
      const result = await execute(...args);
      return { ...result, evidence: result.evidence.map(item => ({ ...item, facts: { token: 'PRIVATE_TOKEN', status: 200 } })) };
    });
    const evaluate = providers.plugins[0]!.evaluateEvidence.bind(providers.plugins[0]);
    vi.spyOn(providers.plugins[0]!, 'evaluateEvidence').mockImplementation(async (...args) => {
      expect(JSON.stringify(args[0].evidence)).not.toContain('PRIVATE_TOKEN');
      expect(JSON.stringify(args[2])).not.toContain('PRIVATE_TOKEN');
      return evaluate(...args);
    });
    const report = await new AgentOOrchestrator({ ...providers, evidenceStore: store }).run({ project,
      identities: [{ id: 'alice', label: 'Alice', roles: [], authentication: 'session-cookie' }],
      workflows: [{ id: 'browse', identityId: 'alice', goal: 'Inspect orders' }] });
    expect(capture).toHaveBeenCalledTimes(4); expect(store.list()).toHaveLength(4);
    expect(report.findings[0]!.status).toBe('CONFIRMED');
    const bundle = store.exportFinding(report.findings[0]!);
    expect(verifyEvidenceBundle(JSON.parse(JSON.stringify(bundle)))).toEqual(bundle);
    expect(bundle.evidence[0]!.provenance).toMatchObject({ probeId: 'fake-scanner', capabilityIds: ['synthetic-check'] });
    expect(JSON.stringify(report)).not.toContain('PRIVATE_TOKEN');
  });
  it.each([false, true])('preserves real cookie probe and CWE evaluation across retention (Secure: %s)', async secure => {
    const collector = new NormalizedResponseCollector();
    const probe = new CookieSecurityProbe();
    const capabilities = new CapabilityRegistry().register('response-collector', collector)
      .register('cookie-analyzer', new NormalizedCookieAnalyzer())
      .register('request-executor', { execute: vi.fn(async request => collector.collect({ url: request.url, method: 'GET' }, {
        status: 200, headers: { 'set-cookie': [`sid=PRIVATE_SESSION; Path=/; HttpOnly${secure ? '; Secure' : ''}`] },
        body: Buffer.from('PRIVATE_BODY'), truncated: false, firstByteMs: 1,
      }, { startedAt: '2026-10-19T00:00:00Z', firstByteMs: 1, durationMs: 2 })) });
    const rule = new CWE614Plugin({ sensitiveCookieNames: ['sid'] });
    const store = new MemoryEvidenceStore({ secrets: ['PRIVATE_SESSION', 'PRIVATE_BODY'] });
    const source: Evidence = { id: 'source', projectId: project.id, producerId: 'framework', kind: 'source-location',
      capturedAt: '2026-10-19T00:00:00Z', summary: 'Protected route.', facts: { method: 'GET', path: '/account' } };
    const report = await new AgentOOrchestrator({ plugins: [rule], evidenceStore: store,
      frameworkAdapter: { id: 'framework', capabilities: ['route-extraction'], supports: async () => true, extract: async () => ({
        components: [{ id: 'api', projectId: project.id, name: 'API', kind: 'service' }], resources: [], signals: [], evidence: [source],
        endpoints: [{ id: 'account', componentId: 'api', method: 'GET', path: '/account', authentication: 'required',
          roles: [], parameters: [], evidenceIds: ['source'] }],
      }) }, scanner: { id: 'probe-runner', capabilities: ['probe:cookie-security', ...probe.metadata().requiredCapabilities],
        execute: async (_context, plan) => {
          const observation = await probe.execute({ project, capabilities, request: { url: plan.targetUrl } });
          return { id: 'result', planId: plan.id, producerId: 'probe-runner', outcome: 'COMPLETED', summary: 'Cookie observation.',
            evidence: [toCoreEvidence(observation, 'account')] };
        } },
    }).run({ project, identities: [] });
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]!.status).toBe(secure ? 'REJECTED' : 'CONFIRMED');
    const proof = store.forFinding(report.findings[0]!)[0]!;
    expect(fromCoreEvidence(proof)?.probeId).toBe('cookie-security');
    expect(JSON.stringify(proof)).not.toMatch(/PRIVATE_/);
    expect(proof.provenance.probeId).toBe('cookie-security');
    const rehydrated = verifyEvidenceBundle(JSON.parse(JSON.stringify(store.exportFinding(report.findings[0]!))));
    expect(fromCoreEvidence(rehydrated.evidence[0]!)).toEqual(fromCoreEvidence(proof));
  });
  it('retains scanner claims and exchange hashes without turning a claim into proof', async () => {
    const collector = new NormalizedResponseCollector();
    const plan: SecurityTestPlan = { id: 'plan', hypothesisId: 'hypothesis', cweId: 'CWE-89', executor: 'scanner',
      requiredCapabilities: ['security-scanner'], risk: 'active', targetUrl: `${project.baseUrl}/search?q=test`, identityIds: [], steps: [] };
    const scanner = new NucleiAdapter({ runner: async process => {
      const url = (await readFile(process.args[process.args.indexOf('-l') + 1]!, 'utf8')).trim();
      await fetch(url, { signal: process.signal });
      return { stdout: JSON.stringify({ 'template-id': 'PRIVATE_RULE', type: 'http', 'matched-at': url,
        info: { severity: 'high', classification: { 'cwe-id': ['CWE-89'] } }, response: 'PRIVATE_RAW' }), stderr: '', exitCode: 0 };
    } });
    const result = await scanner.run({ project, planId: plan.id, cweId: plan.cweId, request: { url: plan.targetUrl }, maxRequests: 4,
      executor: { execute: async request => collector.collect({ url: request.url, method: 'GET' }, {
        status: 200, headers: {}, body: Buffer.from('PRIVATE_BODY'), truncated: false, firstByteMs: 1,
      }, { startedAt: '2026-10-19T00:00:00Z', firstByteMs: 1, durationMs: 2 }) } });
    expect(result.error).toBeUndefined(); expect(result.outcome).toBe('COMPLETED');
    const store = new MemoryEvidenceStore();
    const records = store.capture(result.evidence, { ...scope, capabilityIds: scanner.capabilities, targetUrl: plan.targetUrl });
    const claims = records.filter(item => item.facts.observation === 'scanner-candidate');
    expect(claims).toHaveLength(1); expect(claims[0]!.facts.verified).toBe(false);
    expect(records.filter(item => item.kind === 'http-response').length).toBeGreaterThan(0);
    for (const id of claims[0]!.facts.responseEvidenceIds as string[]) expect(store.get(id)?.kind).toBe('http-response');
    expect(JSON.stringify(records)).not.toContain('PRIVATE_');
  });
});

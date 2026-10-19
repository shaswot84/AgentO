import { describe, expect, it, vi } from 'vitest';
import { AgentOOrchestrator } from '../src/index.js';
import type { CoreProviders, VerificationEngine } from '../src/index.js';
import { evidence, fakePlugin, fakeProviders, project } from './fakes.js';

const request = { project, identities: [{ id: 'alice', label: 'Alice', roles: ['customer'],
  authentication: 'session-cookie' as const, sessionRef: 'opaque-session' }] };

describe('Phase 2 orchestration with interface-only fakes', () => {
  it('uses all seven interfaces and preserves evidence provenance', async () => {
    const providers = fakeProviders();
    const review = vi.spyOn(providers.reasoning!, 'reviewHypotheses');
    const suggest = vi.spyOn(providers.remediation!, 'suggest');
    const report = await new AgentOOrchestrator(providers).run({ ...request,
      workflows: [{ id: 'browse-order', goal: 'Open Alice’s order', identityId: 'alice' }],
      suggestRemediation: true });
    expect(report.context.endpoints[0]?.path).toBe('/api/orders/:id');
    expect(report.context.resources[0]?.ownerIdentityId).toBe('alice');
    expect(report.context.signals[0]?.evidenceIds).toEqual(['static-evidence']);
    expect(report.hypotheses[0]?.status).toBe('HYPOTHESIS');
    expect(report.results[0]?.outcome).toBe('COMPLETED');
    expect(report.findings[0]?.status).toBe('CONFIRMED');
    expect(report.findings[0]?.evidenceIds).toEqual(['proof:plan:CWE-639']);
    expect(report.context.evidence.map(item => item.producerId)).toEqual([
      'fake-framework', 'fake-static', 'fake-browser', 'fake-scanner',
    ]);
    expect(review).toHaveBeenCalledOnce();
    expect(suggest).toHaveBeenCalledOnce();
    expect(report.remediation[0]?.findingId).toBe(report.findings[0]?.id);
  });

  it('runs browser test plans through the browser interface', async () => {
    const providers = fakeProviders();
    const scanner = vi.spyOn(providers.scanner!, 'execute');
    const report = await new AgentOOrchestrator({ ...providers, plugins: [fakePlugin('CWE-639', 'browser')] }).run(request);
    expect(report.results[0]?.producerId).toBe('fake-browser');
    expect(scanner).not.toHaveBeenCalled();
  });

  it('delegates planning to an optional provider while keeping evaluation with the originating rule', async () => {
    const providers = fakeProviders(), plugin = providers.plugins[0]!;
    const original = plugin.generateTests.bind(plugin);
    const generate = vi.spyOn(plugin, 'generateTests');
    const evaluate = vi.spyOn(plugin, 'evaluateEvidence');
    const plan = vi.fn(original);
    const report = await new AgentOOrchestrator({ ...providers, testPlanner: { generateTests: plan } }).run(request);
    expect(plan).toHaveBeenCalledOnce(); expect(generate).not.toHaveBeenCalled();
    expect(evaluate).toHaveBeenCalledOnce(); expect(report.results[0]?.outcome).toBe('COMPLETED');
  });

  it('allows a scanner replacement without changing the plugin or orchestrator', async () => {
    const providers = fakeProviders();
    const report = await new AgentOOrchestrator({ ...providers, scanner: {
      id: 'replacement', capabilities: ['synthetic-check'],
      async execute(_context, plan) {
        return { id: 'replacement-result', planId: plan.id, producerId: this.id,
          outcome: 'COMPLETED', summary: 'Replacement', evidence: [evidence('replacement-proof', 'http-response', this.id)] };
      },
    } }).run(request);
    expect(report.findings[0]?.evidenceIds).toEqual(['replacement-proof']);
  });

  it('accepts an independently registered fake CWE without core changes', async () => {
    const report = await new AgentOOrchestrator({ ...fakeProviders(), plugins: [fakePlugin('CWE-9999')] }).run(request);
    expect(report.findings[0]?.cweId).toBe('CWE-9999');
  });

  it('isolates a thrown execution failure and continues subsequent plans', async () => {
    const providers = fakeProviders();
    const execute = vi.spyOn(providers.scanner!, 'execute');
    execute.mockRejectedValueOnce(new Error('raw credentials must not escape'));
    const report = await new AgentOOrchestrator({ ...providers,
      plugins: [fakePlugin(), fakePlugin('CWE-862')] }).run({ ...request, suggestRemediation: true });
    expect(report.results.map(result => result.outcome)).toEqual(['FAILED', 'COMPLETED']);
    expect(report.findings.map(finding => finding.status)).toEqual(['HYPOTHESIS', 'CONFIRMED']);
    expect(report.remediation).toHaveLength(1);
    expect(JSON.stringify(report)).not.toContain('raw credentials');
  });

  it.each([false, true])('skips plans with missing provider/capability (provider exists: %s)', async exists => {
    const providers: CoreProviders = { plugins: [fakePlugin()], ...(exists ? {
      scanner: { id: 'incapable', capabilities: [], execute: vi.fn() },
    } : {}) };
    const report = await new AgentOOrchestrator(providers).run(request);
    expect(report.results[0]?.outcome).toBe('SKIPPED');
    expect(report.findings[0]?.status).toBe('HYPOTHESIS');
    if (providers.scanner) expect(providers.scanner.execute).not.toHaveBeenCalled();
  });

  it('supports black-box inputs without calling source providers', async () => {
    const providers = fakeProviders();
    const analyze = vi.spyOn(providers.staticAnalyzer!, 'analyze');
    const supports = vi.spyOn(providers.frameworkAdapter!, 'supports');
    const report = await new AgentOOrchestrator(providers).run({ ...request, project: { ...project, mode: 'black-box' } });
    expect(report.context.signals).toEqual([]);
    expect(analyze).not.toHaveBeenCalled();
    expect(supports).not.toHaveBeenCalled();
  });

  it('does not extract from an unsupported framework', async () => {
    const providers = fakeProviders();
    vi.spyOn(providers.frameworkAdapter!, 'supports').mockResolvedValue(false);
    const extract = vi.spyOn(providers.frameworkAdapter!, 'extract');
    const report = await new AgentOOrchestrator(providers).run(request);
    expect(report.context.endpoints).toEqual([]);
    expect(extract).not.toHaveBeenCalled();
  });

  it('rejects duplicate plugin registrations', () => {
    expect(() => new AgentOOrchestrator({ plugins: [fakePlugin(), fakePlugin()] })).toThrow('Duplicate plugin');
  });

  it('rejects invented evidence references from reasoning', async () => {
    const providers = fakeProviders();
    vi.spyOn(providers.reasoning!, 'reviewHypotheses').mockImplementation(async (_context, hypotheses) =>
      hypotheses.map(hypothesis => ({ ...hypothesis, evidenceIds: ['invented'] })));
    await expect(new AgentOOrchestrator(providers).run(request)).rejects.toThrow('Unknown evidence reference');
  });

  it('rejects results attached to the wrong plan', async () => {
    const providers = fakeProviders();
    vi.spyOn(providers.scanner!, 'execute').mockResolvedValue({ id: 'bad-result', planId: 'other-plan',
      producerId: 'fake-scanner', outcome: 'COMPLETED', summary: '', evidence: [] });
    await expect(new AgentOOrchestrator(providers).run(request)).rejects.toThrow('Result does not match');
  });

  it('rejects a confirmed finding without evidence', async () => {
    const plugin = fakePlugin();
    const original = plugin.evaluateEvidence.bind(plugin);
    vi.spyOn(plugin, 'evaluateEvidence').mockImplementation(async (...args) => ({
      ...await original(...args), status: 'CONFIRMED', evidenceIds: [],
    }));
    await expect(new AgentOOrchestrator({ ...fakeProviders(), plugins: [plugin] }).run(request))
      .rejects.toThrow('Confirmed finding requires evidence');
  });

  it('rejects conflicting evidence IDs instead of losing provenance', async () => {
    const providers = fakeProviders();
    vi.spyOn(providers.staticAnalyzer!, 'analyze').mockResolvedValue({ signals: [],
      evidence: [evidence('framework-evidence', 'static-analysis', 'fake-static')] });
    await expect(new AgentOOrchestrator(providers).run(request)).rejects.toThrow('Duplicate evidence');
  });

  it('keeps remediation opt-in', async () => {
    const providers = fakeProviders();
    const suggest = vi.spyOn(providers.remediation!, 'suggest');
    const report = await new AgentOOrchestrator(providers).run(request);
    expect(report.remediation).toEqual([]);
    expect(suggest).not.toHaveBeenCalled();
  });

  it('freezes provider evidence and finding references without freezing provider-owned inputs', async () => {
    const providers = fakeProviders();
    const input = evidence('static-evidence', 'static-analysis', 'fake-static');
    const nested = { value: [200] };
    vi.spyOn(providers.staticAnalyzer!, 'analyze').mockResolvedValue({ signals: [], evidence: [{ ...input, facts: { nested } }] });
    const detect = providers.plugins[0]!.detectCandidates;
    vi.spyOn(providers.plugins[0]!, 'detectCandidates').mockImplementation(async context => {
      expect(Object.isFrozen(context)).toBe(true); expect(Object.isFrozen(context.evidence)).toBe(true);
      expect(Object.isFrozen(context.evidence[0]!.facts)).toBe(true);
      expect(() => { (context.evidence as unknown as unknown[]).pop(); }).toThrow();
      return detect(context);
    });
    const report = await new AgentOOrchestrator(providers).run(request);
    nested.value[0] = 500;
    expect(report.context.evidence.find(item => item.id === input.id)!.facts.nested).toEqual({ value: [200] });
    expect(Object.isFrozen(report.findings[0]!.evidenceIds)).toBe(true);
    expect(Object.isFrozen(report.results[0]!.evidence)).toBe(true);
  });
});

it('delegates final verification before remediation and passes only the current hypothesis plans', async () => {
  const providers = fakeProviders();
  const plugin = providers.plugins[0]!;
  const evaluate = plugin.evaluateEvidence.bind(plugin);
  const direct = vi.spyOn(plugin, 'evaluateEvidence');
  const suggest = vi.spyOn(providers.remediation!, 'suggest');
  const verify = vi.fn<VerificationEngine['verify']>(async (context, hypothesis, plans, results) => {
    expect(plans.every(plan => plan.hypothesisId === hypothesis.id)).toBe(true);
    expect(results.every(result => plans.some(plan => plan.id === result.planId))).toBe(true);
    expect(Object.isFrozen(context.evidence[0])).toBe(true);
    return { ...await evaluate(context, hypothesis, results), status: 'NOT_REPRODUCED' as const, confidence: 'low' as const };
  });
  const report = await new AgentOOrchestrator({ ...providers, verifier: { verify } }).run({ ...request, suggestRemediation: true });
  expect(verify).toHaveBeenCalledOnce(); expect(direct).not.toHaveBeenCalled();
  expect(report.findings[0]!.status).toBe('NOT_REPRODUCED'); expect(suggest).not.toHaveBeenCalled();
});

it('checks the verifier output against the originating hypothesis', async () => {
  const providers = fakeProviders();
  const verify: VerificationEngine['verify'] = async (context, hypothesis, _plans, results) => ({
    ...await providers.plugins[0]!.evaluateEvidence(context, hypothesis, results), hypothesisId: 'unrelated',
  });
  await expect(new AgentOOrchestrator({ ...providers, verifier: { verify } }).run(request))
    .rejects.toThrow('Finding does not match its hypothesis');
});

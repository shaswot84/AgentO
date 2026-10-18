import { describe, expect, it } from 'vitest';
import type { CWEPlugin, SecurityHypothesis } from '@agento/core';
import { buildApplicationSecurityModel } from '@agento/security-model';
import { SecurityHypothesisEngine, type HypothesisContextRule } from '../src/index.js';
import { endpoint, engine, evidence, model, plugins, project } from './helpers.js';

describe('deterministic hypothesis generation', () => {
  it('covers all seven known cases with concrete reasons and relevant evidence', async () => {
    const input = model(), result = await engine().generate(input);
    expect(new Set(result.hypotheses.map(h => h.cweId))).toEqual(new Set(plugins().map(p => p.cweId)));
    expect(result.review).toBe('disabled'); expect(result.diagnostics).toEqual([]);
    expect(result.usage.modelCalls).toBe(0);
    for (const hypothesis of result.hypotheses) {
      expect(hypothesis.status).toBe('HYPOTHESIS'); expect(hypothesis.reason.trim()).not.toBe('');
      expect(hypothesis.rationale.length).toBeGreaterThan(0);
      expect(hypothesis.evidenceIds.length).toBeGreaterThan(0);
      expect(hypothesis.evidenceIds.every(id => input.evidence.some(e => e.id === id))).toBe(true);
      expect(hypothesis.reason).not.toMatch(/no ownership check|is vulnerable|confirmed vulnerability/i);
      expect(hypothesis.limitations.join(' ')).toContain('runtime evidence');
    }
    expect(result.hypotheses.find(h => h.cweId === 'CWE-89')!.reason).toContain('does not prove runtime data flow');
  });

  it('reduces fixed observations and preserves uncertain ownership as a testable question', async () => {
    const vulnerable = await engine().generate(model()), fixed = await engine().generate(model(true));
    expect(fixed.hypotheses.length).toBeLessThan(vulnerable.hypotheses.length);
    expect(fixed.hypotheses.map(h => h.cweId)).toEqual(['CWE-639']);
    expect(fixed.hypotheses[0]!.reason).toContain('enforcement remains unverified');
  });

  it('produces no hypotheses from an empty application model', async () => {
    const input = buildApplicationSecurityModel({ project });
    expect((await engine().generate(input)).hypotheses).toEqual([]);
  });

  it('is stable, immutable, JSON safe, and independent across concurrent runs', async () => {
    const input = model(), before = JSON.stringify(input), service = engine();
    const [first, second] = await Promise.all([service.generate(input), service.generate(input)]);
    expect(first).toEqual(second); expect(JSON.parse(JSON.stringify(first))).toEqual(first);
    expect(JSON.stringify(input)).toBe(before); expect(Object.isFrozen(first.hypotheses[0]!.rationale)).toBe(true);
    expect(() => { (first.hypotheses[0]!.evidenceIds as string[]).push('bad'); }).toThrow();
  });

  it('retains original plugin IDs and endpoint aliases through the core reasoning port', async () => {
    const input = model(), candidates = (await Promise.all(plugins().map(p => p.detectCandidates(input)))).flat();
    const result = await engine().reviewHypotheses(input, candidates);
    for (const hypothesis of result) {
      expect(candidates.some(candidate => candidate.id === hypothesis.id)).toBe(true);
      const plugin = plugins().find(p => p.cweId === hypothesis.cweId)!;
      await expect(plugin.generateTests(input, hypothesis)).resolves.toBeDefined();
    }
  });

  it.each([
    { projectId: 'other' }, { endpointId: 'missing' }, { evidenceIds: ['missing'] }, { status: 'CONFIRMED' },
  ])('rejects malformed or unrelated supplied candidates: %j', async change => {
    const input = model(), candidate = (await plugins()[0]!.detectCandidates(input))[0]!;
    const result = await engine().reviewHypotheses(input, [{ ...candidate, ...change } as SecurityHypothesis]);
    expect(result).toEqual([]);
  });

  it('rejects duplicate hypothesis IDs instead of collapsing conflicting candidates', async () => {
    const input = model(), candidate = (await plugins()[0]!.detectCandidates(input))[0]!;
    expect(await engine().reviewHypotheses(input, [candidate, candidate])).toEqual([]);
  });

  it('does not accept candidates for origins outside the project scope', async () => {
    const input = { ...model(), project: { ...project, allowedOrigins: [] } };
    expect((await engine().generate(input)).hypotheses).toEqual([]);
  });

  it('does not treat route declarations, cookie names, or generic database operations as proof of suspicion', async () => {
    const input = buildApplicationSecurityModel({ project, contributions: [{ source: 'source',
      components: [{ id: 'service', projectId: project.id, kind: 'service', name: 'Service' }], endpoints: [endpoint],
      evidence: [evidence('route', { observation: 'route' }), evidence('db', { observation: 'database-operation', interpolated: false, placeholders: 1 }),
        evidence('tracking', { observation: 'cookie', name: 'sid', options: { httpOnly: false, secure: false } })] }] });
    expect((await engine().generate(input)).hypotheses).toEqual([]);
    const sensitive = await engine({ sensitiveCookieNames: ['sid'] }).generate(input);
    expect(sensitive.hypotheses.map(h => h.cweId).sort()).toEqual(['CWE-1004', 'CWE-614']);
  });

  it('does not assign unbound runtime cookie observations to every endpoint', async () => {
    const { endpointId: _endpointId, ...unboundCookie } = evidence('cookie', { observation: 'cookie', sensitive: true, httpOnly: false });
    const input = buildApplicationSecurityModel({ project, contributions: [{ source: 'runtime',
      components: [{ id: 'service', projectId: project.id, kind: 'service', name: 'Service' }], endpoints: [endpoint],
      evidence: [evidence('route', { observation: 'route' }), unboundCookie] }] });
    expect((await engine().generate(input)).hypotheses).toEqual([]);
  });

  it('supports custom CWEs without changing orchestration, runtime, or built-in rules', async () => {
    const custom: Pick<CWEPlugin, 'cweId' | 'detectCandidates'> = { cweId: 'CWE-9999', detectCandidates: async context => [{
      id: 'custom', projectId: project.id, cweId: 'CWE-9999', status: 'HYPOTHESIS', reason: 'ignored raw reason',
      endpointId: context.endpoints[0]!.id, evidenceIds: ['route'],
    }] };
    const rule: HypothesisContextRule = { cweId: 'CWE-9999', gather: () => [{ id: 'custom-support', kind: 'custom',
      statement: 'A custom normalized observation requires investigation.', strength: 'candidate', evidenceIds: ['route'] }] };
    const result = await new SecurityHypothesisEngine({ plugins: [custom], rules: [rule] }).generate(model());
    expect(result.hypotheses[0]).toMatchObject({ cweId: 'CWE-9999', reason: 'A custom normalized observation requires investigation.' });
  });

  it('isolates candidate-provider and rule failures with sanitized diagnostics', async () => {
    const badPlugin = { cweId: 'CWE-8888' as const, detectCandidates: async () => { throw new Error('private-failure'); } };
    const result = await engine({ plugins: [badPlugin, ...plugins()] }).generate(model());
    expect(result.hypotheses.length).toBeGreaterThan(0);
    expect(result.diagnostics).toContainEqual({ code: 'candidate-provider-failed' });
    expect(JSON.stringify(result)).not.toContain('private-failure');
    const failed = await engine({ rules: [{ cweId: 'CWE-639', gather: () => { throw new Error('private-rule'); } }] }).generate(model());
    expect(failed.diagnostics).toContainEqual({ code: 'rule-failed' }); expect(failed.hypotheses).toEqual([]);
  });

  it('reports partial candidate and hypothesis coverage under configured limits', async () => {
    const limited = await engine({ limits: { maxCandidates: 2, maxHypotheses: 1 } }).generate(model());
    expect(limited.hypotheses).toHaveLength(1);
    expect(limited.diagnostics.map(d => d.code)).toEqual(expect.arrayContaining(['candidate-limit', 'hypothesis-limit']));
  });

  it('bounds support context and reports the limit', async () => {
    const result = await engine({ limits: { maxSupportsPerCandidate: 1 } }).generate(model());
    expect(result.diagnostics).toContainEqual({ code: 'context-limit' });
    expect(result.hypotheses.every(h => h.rationale.length === 1)).toBe(true);
  });

  it('rejects evidence explicitly bound to another endpoint even when a fact links it to this one', async () => {
    const original = model(), endpointId = original.endpoints[0]!.id;
    const foreign = evidence('foreign', { observation: 'cookie' }, { endpointId: 'other' });
    const input = { ...original, evidence: [...original.evidence, foreign],
      cookies: [{ id: 'misbound', kind: 'cookie' as const, source: 'runtime' as const, endpointIds: [endpointId],
        evidenceIds: [foreign.id], details: { sensitive: true, httpOnly: false } }] };
    const result = await engine().generate(input);
    expect(result.hypotheses.some(h => h.cweId === 'CWE-1004')).toBe(false);
    expect(result.hypotheses.some(h => h.evidenceIds.includes('foreign'))).toBe(false);
  });

  it('rejects supports without evidence or with invented references', async () => {
    const result = await engine({ rules: [{ cweId: 'CWE-639', gather: () => [
      { id: 'empty', kind: 'custom', statement: 'Unsupported claim.', strength: 'candidate', evidenceIds: [] },
      { id: 'unknown', kind: 'custom', statement: 'Unsupported claim.', strength: 'candidate', evidenceIds: ['missing'] },
    ] }] }).generate(model());
    expect(result.hypotheses).toEqual([]);
  });

  it.each([0, -1, NaN, Infinity, 2.5, 100_000])('rejects invalid limits %s', value => {
    expect(() => engine({ limits: { maxCandidates: value } })).toThrow('Invalid hypothesis limit');
  });

  it('rejects duplicate registration', () => {
    expect(() => engine({ plugins: [plugins()[0]!, plugins()[0]!] })).toThrow('duplicate candidate plugin');
  });
});

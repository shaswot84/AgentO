import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { FileEvidenceStore } from '@agento/evidence';
import { VerificationJudge } from '@agento/verifier';
import { CWE79Plugin, CWE89Plugin, fromCoreEvidence } from '@agento/cwe';
import { A05Error, runA05Scan } from '../src/index.js';
import { repository, setup } from './helpers.js';

const paths: string[] = [];
afterEach(() => { for (const path of paths.splice(0)) rmSync(path, { recursive: true, force: true }); });
async function fixture(mode: 'vulnerable' | 'fixed' = 'vulnerable') { const path = repository(); paths.push(path); return setup(path, mode); }

describe('source-grounded injection assessment', () => {
  it.each(['vulnerable', 'fixed'] as const)('binds source, model, plan, proof and verdict in %s mode', async mode => {
    const state = await fixture(mode), report = await runA05Scan(state.options);
    expect(report.hypotheses, JSON.stringify(report.diagnostics)).toHaveLength(2);
    expect(report.executions.every(item => item.outcome === 'COMPLETED'), JSON.stringify(report.executions)).toBe(true);
    expect(report.findings.filter(item => item.status === 'CONFIRMED')).toHaveLength(mode === 'vulnerable' ? 2 : 0);
    expect(state.scans).toHaveLength(2);
    expect(state.calls.every(request => ['/search', '/sql'].includes(new URL(request.url).pathname))).toBe(true);
    expect(state.calls.filter(request => new URL(request.url).pathname === '/search').every(request => new URL(request.url).searchParams.get('keep') === 'constant')).toBe(true);
    for (const decision of report.decisions) {
      expect(decision.diagnostics).toEqual([]); expect(decision.staticEvidenceIds.length).toBeGreaterThan(0); expect(decision.runtimeEvidenceIds).toHaveLength(1);
      expect(decision.finding.evidenceIds.every(id => report.context.evidence.some(item => item.id === id))).toBe(true);
    }
    expect(report.plans.every(plan => plan.scope.parameter?.name === 'q')).toBe(true);
    expect(report.context.evidence.some(item => fromCoreEvidence(item)?.probeId === 'sql-injection')).toBe(true);
    expect(JSON.stringify(report)).not.toMatch(/private-baseline|private-result|window.name/);
    expect(Object.isFrozen(report.plans[0])).toBe(true);
  });
  it('replays both decisions after reopening retained proof without target access', async () => {
    const state = await fixture(), directory = mkdtempSync(join(tmpdir(), 'a05-proof-')); paths.push(directory);
    const store = new FileEvidenceStore(directory), report = await runA05Scan({ ...state.options, evidenceStore: store });
    const head = store.headDigest; store.close();
    const reopened = new FileEvidenceStore(directory, { expectedHeadDigest: head });
    try {
      const judge = new VerificationJudge({ plugins: [new CWE79Plugin(), new CWE89Plugin()], evidenceStore: reopened });
      for (const hypothesis of report.hypotheses) {
        const decision = await judge.judge({ context: report.context, hypothesis, plans: report.plans.filter(item => item.hypothesisId === hypothesis.id),
          results: report.results.filter(result => report.plans.some(plan => plan.hypothesisId === hypothesis.id && plan.id === result.planId)) });
        expect(decision).toEqual(report.decisions.find(item => item.finding.hypothesisId === hypothesis.id));
        expect(reopened.exportFinding(decision.finding).evidence.length).toBeGreaterThan(1);
      }
    } finally { reopened.close(); }
  });
  it('keeps default approval-required plans skipped before traffic', async () => {
    const state = await fixture(), { approval: _, ...policy } = state.options.policy;
    const report = await runA05Scan({ ...state.options, policy });
    expect(state.calls).toHaveLength(0); expect(state.scans).toHaveLength(0);
    expect(report.executions.every(item => item.code === 'approval-required')).toBe(true);
    expect(report.findings.every(item => item.status !== 'CONFIRMED')).toBe(true);
  });
  it('blocks missing private bindings instead of inventing values', async () => {
    const state = await fixture(), report = await runA05Scan({ ...state.options, targets: [{ path: '/search', cweId: 'CWE-79', inputs: {} }] });
    expect(report.plans[0]?.readiness).toBe('BLOCKED'); expect(state.calls).toHaveLength(0);
    expect(report.executions[0]?.code).toBe('input-required');
  });
  it('skips unavailable required scanners without starting probes', async () => {
    const state = await fixture(), report = await runA05Scan({ ...state.options, scanners: [] });
    expect(report.executions.every(item => item.outcome === 'SKIPPED')).toBe(true); expect(state.calls).toHaveLength(0);
  });
  it('does not fan out to inputs or routes without a matching source signal', async () => {
    const state = await fixture(), report = await runA05Scan({ ...state.options, targets: [{ path: '/other', cweId: 'CWE-79', inputs: { other: 'value' } }] });
    expect(report.plans).toEqual([]); expect(report.diagnostics).toContain('no-grounded-input:CWE-79:/other'); expect(state.calls).toHaveLength(0);
  });
  it('reports failed static analysis as incomplete coverage', async () => {
    const state = await fixture(), report = await runA05Scan({ ...state.options, staticAnalyzer: { id: 'missing-static', capabilities: ['static-analysis'], analyze: async () => ({ evidence: [], signals: [] }) } });
    expect(report.diagnostics).toContain('static-analysis-incomplete'); expect(report.findings).toEqual([]); expect(state.calls).toEqual([]);
  });
  it('cannot confirm from scanner claims when browser and controlled SQL proof are absent', async () => {
    const state = await fixture('fixed');
    const report = await runA05Scan({ ...state.options, targets: state.options.targets.map(({ responseJsonPointer: _, ...target }) => target) });
    expect(report.findings.every(item => item.status !== 'CONFIRMED')).toBe(true);
  });
  it.each([{ allowedMethods: ['POST'] }, { allowedOrigins: ['https://outside.invalid'] }])('denies policy mismatch before traffic %j', async extra => {
    const state = await fixture(), report = await runA05Scan({ ...state.options, policy: { ...state.options.policy, ...extra } });
    expect(report.executions.every(item => item.outcome === 'SKIPPED')).toBe(true); expect(state.calls).toHaveLength(0);
  });
  it('handles request exhaustion without confirmation', async () => {
    const state = await fixture(), report = await runA05Scan({ ...state.options, policy: { ...state.options.policy, maxRequestsPerExecution: 1 } });
    expect(state.calls).toHaveLength(2); expect(report.findings.every(item => item.status !== 'CONFIRMED')).toBe(true);
  });
  it('cancels before discovery or target effects', async () => {
    const state = await fixture(); await expect(runA05Scan({ ...state.options, signal: AbortSignal.abort() })).rejects.toThrow('cancelled');
    expect(state.calls).toHaveLength(0);
  });
  it.each(['/missing', '/search/:id'])('refuses unselected or non-literal paths %s', async path => {
    const state = await fixture(); await expect(runA05Scan({ ...state.options, targets: [{ path, cweId: 'CWE-79', inputs: { q: 'value' } }] })).rejects.toBeInstanceOf(A05Error);
    expect(state.calls).toHaveLength(0);
  });
});

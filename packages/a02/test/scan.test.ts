import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FileEvidenceStore } from '@agento/evidence';
import { CWE1004Plugin, CWE614Plugin, CWE942Plugin, fromCoreEvidence } from '@agento/cwe';
import { VerificationJudge } from '@agento/verifier';
import { runA02Scan } from '../src/index.js';
import { repository, setup } from './helpers.js';

describe('A02 assessment host', () => {
  let directory: string;
  beforeAll(() => { directory = repository(); });
  afterAll(() => rmSync(directory, { recursive: true, force: true }));

  it.each(['vulnerable', 'fixed'] as const)('runs the full pipeline with shared cookie collection in %s mode', async mode => {
    const { options, calls } = setup(directory, mode);
    const report = await runA02Scan(options);
    expect(report.findings.map(item => item.cweId).sort()).toEqual(['CWE-1004', 'CWE-614', 'CWE-942']);
    expect(report.findings.every(item => item.status === (mode === 'vulnerable' ? 'CONFIRMED' : 'NOT_REPRODUCED'))).toBe(true);
    expect(report.decisions.every(item => item.diagnostics.length === 0 && item.runtimeEvidenceIds.length === 1)).toBe(true);
    expect(report.executions.every(item => item.outcome === 'COMPLETED')).toBe(true);
    const cookies = report.executions.filter(item => item.probeId === 'cookie-security');
    expect(cookies).toHaveLength(2);
    expect(new Set(cookies.map(item => item.collectionId)).size).toBe(1);
    expect(cookies.filter(item => item.reused)).toHaveLength(1);
    expect(report.context.evidence.filter(item => fromCoreEvidence(item))).toHaveLength(2);
    expect(calls).toHaveLength(6);
    expect(calls.filter(item => new URL(item.url).pathname === '/login')).toHaveLength(2);
    expect(calls.every(item => new URL(item.url).origin === options.project.baseUrl)).toBe(true);
    expect(report.context.endpoints).toHaveLength(1);
    for (const finding of report.findings) {
      expect(finding.evidenceIds.length).toBeGreaterThan(1);
      expect(finding.evidenceIds.every(id => report.context.evidence.some(item => item.id === id))).toBe(true);
    }
    expect(new Set(report.context.evidence.map(item => item.id)).size).toBe(report.context.evidence.length);
    expect(report.audit.filter(item => item.operation === 'request' && item.outcome === 'ALLOW')).toHaveLength(6);
    expect(JSON.stringify(report)).not.toMatch(/private-password|private-session-token|private-response-body|private-login-body/);
    expect(Object.isFrozen(report)).toBe(true);
  });

  it('reopens stored evidence and reproduces every verdict without target access', async () => {
    const { options, calls } = setup(directory), journal = mkdtempSync(join(tmpdir(), 'agento-a02-proof-'));
    const store = new FileEvidenceStore(journal);
    try {
      const report = await runA02Scan({ ...options, evidenceStore: store }), head = store.headDigest, count = calls.length;
      store.close();
      const reopened = new FileEvidenceStore(journal, { expectedHeadDigest: head });
      try {
        const rules = { sensitiveCookieNames: options.sensitiveCookieNames, untrustedOrigins: options.untrustedOrigins };
        const judge = new VerificationJudge({ plugins: [new CWE1004Plugin(rules), new CWE614Plugin(rules), new CWE942Plugin(rules)], evidenceStore: reopened });
        for (const hypothesis of report.hypotheses) {
          const plans = report.plans.filter(item => item.hypothesisId === hypothesis.id);
          const decision = await judge.judge({ context: report.context, hypothesis, plans,
            results: report.results.filter(item => plans.some(plan => plan.id === item.planId)) });
          expect(decision).toEqual(report.decisions.find(item => item.finding.hypothesisId === hypothesis.id));
          expect(reopened.exportFinding(decision.finding).evidence.length).toBeGreaterThan(1);
        }
        expect(calls).toHaveLength(count);
      } finally { reopened.close(); }
    } finally { store.close(); rmSync(journal, { recursive: true, force: true }); }
  });

  it('keeps missing authentication unconfirmed and makes no requests', async () => {
    const { options, calls } = setup(directory);
    const { authentication: _authentication, ...withoutAuthentication } = options;
    const report = await runA02Scan(withoutAuthentication);
    expect(calls).toHaveLength(0);
    expect(report.executions.every(item => item.outcome === 'SKIPPED' && item.code === 'selection-unavailable')).toBe(true);
    expect(report.findings).toHaveLength(3);
    expect(report.findings.every(item => item.status === 'NOT_REPRODUCED' && item.confidence === 'low' && item.evidenceIds.length > 0)).toBe(true);
  });

  it('preserves the policy approval requirement without approving a generated plan', async () => {
    const { options, calls } = setup(directory);
    const { approval: _approval, ...policy } = options.policy;
    const report = await runA02Scan({ ...options, policy });
    expect(calls).toHaveLength(0);
    expect(report.executions.every(item => item.code === 'approval-required')).toBe(true);
    expect(report.findings.every(item => item.status === 'NOT_REPRODUCED')).toBe(true);
  });

  it.each([
    { allowedMethods: ['GET', 'OPTIONS'] }, { maxRequestsPerExecution: 1 },
    { tools: { 'a02-http': {} } }, { allowedOrigins: ['https://other.invalid'] },
  ])('stops denied or exhausted execution and retains only unconfirmed verdicts: %j', async override => {
    const { options, calls } = setup(directory);
    const report = await runA02Scan({ ...options, policy: { ...options.policy, ...override } });
    expect(report.findings.every(item => item.status === 'NOT_REPRODUCED')).toBe(true);
    expect(report.executions.every(item => item.outcome !== 'COMPLETED')).toBe(true);
    if ('maxRequestsPerExecution' in override) expect(calls).toHaveLength(2);
    else expect(calls.every(item => item.method !== 'POST')).toBe(true);
    expect(JSON.stringify(report)).not.toMatch(/private-password|private-session-token/);
  });

  it('shares failed cookie collection without promoting it or retrying it for the second rule', async () => {
    const { options } = setup(directory);
    let sends = 0;
    const transport = { send: async () => { sends++; throw new Error('private-password'); } };
    const report = await runA02Scan({ ...options, transport });
    expect(sends).toBe(2);
    expect(report.executions.filter(item => item.reused)).toHaveLength(1);
    expect(report.decisions.every(item => item.runtimeEvidenceIds.length === 0)).toBe(true);
    expect(report.findings.every(item => item.status === 'NOT_REPRODUCED')).toBe(true);
    expect(JSON.stringify(report)).not.toContain('private-password');
  });

  it('leaves the Secure check blocked on HTTP while the other plans can run', async () => {
    const { options } = setup(directory, 'vulnerable', 'http://target.invalid');
    const report = await runA02Scan(options);
    expect(report.plans.find(item => item.cweId === 'CWE-614')?.prerequisites).toContainEqual({ code: 'https-required' });
    expect(report.findings.find(item => item.cweId === 'CWE-614')?.status).toBe('NOT_REPRODUCED');
    expect(report.findings.filter(item => item.status === 'CONFIRMED')).toHaveLength(2);
  });

  it('does not reuse collection across endpoint targets', async () => {
    const { options } = setup(directory);
    const report = await runA02Scan({ ...options, paths: ['/target', '/other'] });
    expect(report.findings).toHaveLength(6);
    expect(new Set(report.executions.filter(item => item.probeId === 'cookie-security').map(item => item.collectionId)).size).toBe(2);
    expect(report.context.evidence.filter(item => fromCoreEvidence(item))).toHaveLength(4);
  });

  it('reports missing sensitivity and origin declarations without confirmation', async () => {
    const { options, calls } = setup(directory);
    const report = await runA02Scan({ ...options, sensitiveCookieNames: [], untrustedOrigins: [] });
    expect(report.findings.every(item => item.status === 'NOT_REPRODUCED')).toBe(true);
    expect(calls).toHaveLength(0);
    expect(report.diagnostics).toContain('sensitive-cookie-names-required');
    expect(report.diagnostics).toContain('untrusted-origins-required');
  });

  it('honors cancellation before access and rejects unknown or nonliteral paths', async () => {
    const { options, calls } = setup(directory);
    await expect(runA02Scan({ ...options, signal: AbortSignal.abort() })).rejects.toMatchObject({ code: 'cancelled' });
    await expect(runA02Scan({ ...options, paths: ['/missing'] })).rejects.toMatchObject({ code: 'route-unavailable' });
    for (const path of ['//other.invalid/target', '/target?q=secret', '/target/../other', '/:id', '/%74arget']) {
      await expect(runA02Scan({ ...options, paths: [path] })).rejects.toMatchObject({ code: 'invalid-options' });
    }
    expect(calls).toHaveLength(0);
  });
});

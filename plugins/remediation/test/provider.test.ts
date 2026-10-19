import { describe, expect, it } from 'vitest';
import { AgentOOrchestrator, MVP_CWES, type CWEPlugin } from '@agento/core';
import { buildSecurityReport, reportToJSON } from '@agento/reporting';
import { ExpressRemediationProvider, sourceDigest } from '../src/index.js';
import { fixture } from './helpers.js';

describe('source-bound suggestions', () => {
  it.each(MVP_CWES)('generates an immutable %s patch and runnable regression source', async cweId => {
    const state = fixture(cweId), before = JSON.stringify({ context: state.context, finding: state.finding });
    const suggestion = await state.provider.suggest(state.context, state.finding);
    expect(suggestion.findingId).toBe(state.finding.id);
    expect(suggestion.patch).toContain('diff --git a/src/');
    expect(suggestion.regressionTest).toContain('security:');
    expect(suggestion.regressionTest).toContain('normal:');
    expect(suggestion.validation).toBe('NOT_RUN');
    expect(suggestion.files.every(file => file.beforeSha256 !== file.afterSha256)).toBe(true);
    expect(Object.isFrozen(suggestion.files[0])).toBe(true);
    expect(JSON.stringify({ context: state.context, finding: state.finding })).toBe(before);
    expect(await state.provider.suggest(state.context, state.finding)).toEqual(suggestion);
  });
  it.each(['HYPOTHESIS', 'LIKELY', 'NOT_REPRODUCED', 'REJECTED'] as const)('refuses %s findings', async status => {
    const state = fixture();
    await expect(state.provider.suggest(state.context, { ...state.finding, status })).rejects.toMatchObject({ code: 'not-confirmed' });
  });
  it('refuses unsupported revisions, missing files, and stale snapshots', async () => {
    const state = fixture();
    const source = { ...state.sources[0]!, content: state.sources[0]!.content + '// new revision\n' };
    expect(() => new ExpressRemediationProvider({ evidenceStore: state.store, sources: [source] })).toThrow('source-mismatch');
    const changed = new ExpressRemediationProvider({ evidenceStore: state.store, sources: [{ ...source, sha256: sourceDigest(source.content) }] });
    await expect(changed.suggest(state.context, state.finding)).rejects.toMatchObject({ code: 'unsupported-source' });
    const missing = new ExpressRemediationProvider({ evidenceStore: state.store, sources: [] });
    await expect(missing.suggest(state.context, state.finding)).rejects.toMatchObject({ code: 'missing-source' });
  });
  it('rejects project, endpoint, and evidence mismatches', async () => {
    const state = fixture();
    await expect(state.provider.suggest(state.context, { ...state.finding, projectId: 'other' })).rejects.toMatchObject({ code: 'invalid-input' });
    await expect(state.provider.suggest({ ...state.context, endpoints: [{ ...state.context.endpoints[0]!, path: '/other' }] }, state.finding)).rejects.toMatchObject({ code: 'unsupported-source' });
    await expect(state.provider.suggest(state.context, { ...state.finding, evidenceIds: ['invented'] })).rejects.toMatchObject({ code: 'unrelated-evidence' });
    const evidence = state.context.evidence.map(item => item.id === 'runtime' ? { ...item, summary: 'changed' } : item);
    await expect(state.provider.suggest({ ...state.context, evidence }, state.finding)).rejects.toMatchObject({ code: 'unrelated-evidence' });
    await expect(state.provider.suggest(state.context, { ...state.finding, evidenceIds: [state.sources[0]!.evidenceIds[0]!] })).rejects.toMatchObject({ code: 'unrelated-evidence' });
  });
  it('checks stored record hashes and source checksum citations', async () => {
    const state = fixture();
    const source = state.sources[0]!;
    const provider = new ExpressRemediationProvider({ sources: [{ ...source, evidenceIds: ['runtime'] }], evidenceStore: state.store });
    await expect(provider.suggest(state.context, state.finding)).rejects.toMatchObject({ code: 'unrelated-evidence' });
    const tampered = state.context.evidence.map(item => ({ ...item, digest: '0'.repeat(64) }));
    const badStore = { capture: state.store.capture.bind(state.store), get: (id: string) => tampered.find(item => item.id === id) };
    const broken = new ExpressRemediationProvider({ sources: state.sources, evidenceStore: badStore });
    await expect(broken.suggest({ ...state.context, evidence: tampered }, state.finding)).rejects.toMatchObject({ code: 'integrity-failed' });
  });
  it('copies caller snapshots and never freezes caller input', async () => {
    const state = fixture(), first = state.sources[0]!;
    state.sources[0] = { ...first, content: 'changed' };
    expect(Object.isFrozen(first)).toBe(false);
    expect((await state.provider.suggest(state.context, state.finding)).patch).toContain('isOwner');
  });
  it.each(['../escape.ts', '/absolute.ts', 'src/../../escape.ts', '.git/config.ts', 'src/a\n.ts'])('rejects unsafe path %s', path => {
    const state = fixture();
    expect(() => new ExpressRemediationProvider({ evidenceStore: state.store, sources: [{ ...state.sources[0]!, path }] })).toThrow('invalid-input');
  });
  it('rejects accessor input without invoking it', () => {
    const state = fixture(); let accessed = false;
    const source = { ...state.sources[0]!, get content() { accessed = true; return ''; } };
    expect(() => new ExpressRemediationProvider({ evidenceStore: state.store, sources: [source] })).toThrow('invalid-input');
    expect(accessed).toBe(false);
  });
  it('bounds output and refuses private values instead of corrupting patches', async () => {
    const state = fixture();
    const limited = new ExpressRemediationProvider({ evidenceStore: state.store, sources: state.sources, maxPatchBytes: 10 });
    await expect(limited.suggest(state.context, state.finding)).rejects.toMatchObject({ code: 'patch-limit' });
    const secret = new ExpressRemediationProvider({ evidenceStore: state.store, sources: state.sources, secrets: ['currentUserId'] });
    await expect(secret.suggest(state.context, state.finding)).rejects.toMatchObject({ code: 'unsafe-output' });
    const privateReference = new ExpressRemediationProvider({ evidenceStore: state.store, sources: state.sources, secrets: ['runtime'] });
    await expect(privateReference.suggest(state.context, state.finding)).rejects.toMatchObject({ code: 'unsafe-output' });
  });
  it('rejects retained runtime records from another target environment', async () => {
    const state = fixture();
    const project = { ...state.context.project, baseUrl: 'https://other.invalid', allowedOrigins: ['https://other.invalid'] };
    const captured = state.store.capture([{ id: 'other-runtime', projectId: project.id, kind: 'http-response', producerId: 'synthetic-probe',
      capturedAt: '2026-10-19T10:00:00Z', summary: 'Other environment', endpointId: 'endpoint', facts: {} }], { project, capabilityIds: ['synthetic-probe'] });
    await expect(state.provider.suggest({ ...state.context, evidence: [...state.context.evidence, ...captured] }, {
      ...state.finding, evidenceIds: [...state.finding.evidenceIds.filter(id => id !== 'runtime'), 'other-runtime'],
    })).rejects.toMatchObject({ code: 'unrelated-evidence' });
  });
  it('sanitizes store failures and preserves the original finding and evidence', async () => {
    const state = fixture(), before = JSON.stringify({ context: state.context, finding: state.finding });
    const broken = new ExpressRemediationProvider({ sources: state.sources, evidenceStore: {
      capture: state.store.capture.bind(state.store), get() { throw new Error('/private/path secret-value'); },
    } });
    await expect(broken.suggest(state.context, state.finding)).rejects.toThrow('Remediation failed: integrity-failed');
    expect(JSON.stringify({ context: state.context, finding: state.finding })).toBe(before);
    expect((await state.provider.suggest(state.context, state.finding)).validation).toBe('NOT_RUN');
  });
  it('exports suggestions through existing reporting without claiming a verified fix', async () => {
    const state = fixture(); const suggestion = await state.provider.suggest(state.context, state.finding);
    const report = buildSecurityReport({ context: state.context, findings: [state.finding], hypotheses: [state.hypothesis],
      plans: [state.plan], results: [state.result], remediation: [suggestion] }, { evidenceStore: state.store });
    expect(report.findings[0]!.remediation.status).toBe('SUGGESTED');
    expect(reportToJSON(report)).toContain('NOT_RUN');
  });
  it('uses the existing core provider contract without changing verification logic', async () => {
    const state = fixture();
    const plugin: CWEPlugin = { cweId: state.finding.cweId,
      async detectCandidates() { return [state.hypothesis]; }, async generateTests() { return [state.plan]; },
      async evaluateEvidence() { return state.finding; } };
    const orchestrator = new AgentOOrchestrator({ plugins: [plugin], remediation: state.provider,
      frameworkAdapter: { id: 'fixture-framework', capabilities: ['synthetic'], async supports() { return true; },
        async extract() { return { components: [], endpoints: state.context.endpoints, resources: [], signals: [], evidence: state.context.evidence.filter(item => item.id !== 'runtime') }; } },
      scanner: { id: 'fixture-scanner', capabilities: ['synthetic-probe'], async execute() { return state.result; } } });
    const report = await orchestrator.run({ project: state.context.project, identities: [], suggestRemediation: true });
    expect(report.findings[0]!.status).toBe('CONFIRMED');
    expect(report.remediation[0]!.patch).toContain('isOwner');
  });
});

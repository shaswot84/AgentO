import { rmSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';
import { MemoryEvidenceStore } from '@agento/evidence';
import { runA01Scan } from '@agento/a01';
import { runA02Scan } from '@agento/a02';
import { runA05Scan } from '@agento/a05';
import { setup as a01Setup } from '../../a01/test/helpers.js';
import { repository as a02Repository, setup as a02Setup } from '../../a02/test/helpers.js';
import { repository as a05Repository, setup as a05Setup } from '../../a05/test/helpers.js';
import { buildSecurityReport, reportToJSON, reportToMarkdown } from '../src/index.js';
import { generatedAt } from './helpers.js';

const paths: string[] = [];
afterEach(() => { for (const path of paths.splice(0)) rmSync(path, { recursive: true, force: true }); });

describe('existing assessment report compatibility (controlled adapters)', () => {
  it.each(['vulnerable', 'fixed'] as const)('exports A01 proof in %s mode without further target activity', async mode => {
    const state = a01Setup(mode); paths.push(state.repositoryPath);
    const store = new MemoryEvidenceStore();
    const scan = await runA01Scan({ ...state.options, evidenceStore: store });
    const calls = state.calls.length, logins = state.logins.length;
    const report = buildSecurityReport(scan, { evidenceStore: store, generatedAt });
    expect(report.findings.map(item => item.status)).toEqual([mode === 'vulnerable' ? 'CONFIRMED' : 'NOT_REPRODUCED', mode === 'vulnerable' ? 'CONFIRMED' : 'NOT_REPRODUCED']);
    expect(report.findings.every(item => item.source && item.endpoint && item.runtimeEvidenceIds.length > 0), JSON.stringify({
      findings: report.findings.map(item => ({ source: item.source, endpoint: item.endpoint, diagnostics: item.diagnostics })),
      sources: report.evidence.filter(item => item.source).map(item => item.source), originals: scan.findings.map(item => item.source),
    })).toBe(true);
    expect(reportToJSON(report) + reportToMarkdown(report)).not.toMatch(/private-session|owner-only-order-content|admin-only-user-content/);
    expect(state.calls).toHaveLength(calls); expect(state.logins).toHaveLength(logins);
  });
  it.each(['vulnerable', 'fixed'] as const)('exports three A02 CWEs in %s mode', async mode => {
    const path = a02Repository(); paths.push(path);
    const state = a02Setup(path, mode), store = new MemoryEvidenceStore();
    try {
      const scan = await runA02Scan({ ...state.options, evidenceStore: store });
      const calls = state.calls.length, report = buildSecurityReport(scan, { evidenceStore: store, generatedAt });
      expect(report.findings).toHaveLength(3);
      expect(report.findings.every(item => item.status === (mode === 'vulnerable' ? 'CONFIRMED' : 'NOT_REPRODUCED'))).toBe(true);
      expect(new Set(report.findings.map(item => item.cweId))).toEqual(new Set(['CWE-1004', 'CWE-614', 'CWE-942']));
      expect(reportToJSON(report) + reportToMarkdown(report)).not.toMatch(/private-session-token|private-password|private-response-body/);
      expect(state.calls).toHaveLength(calls);
    } finally { await state.authentication.close(); }
  });
  it.each(['vulnerable', 'fixed'] as const)('exports XSS and SQL A05 proof in %s mode', async mode => {
    const path = a05Repository(); paths.push(path);
    const state = await a05Setup(path, mode), store = new MemoryEvidenceStore();
    const scan = await runA05Scan({ ...state.options, evidenceStore: store });
    const calls = state.calls.length, report = buildSecurityReport(scan, { evidenceStore: store, generatedAt });
    expect(report.findings).toHaveLength(2);
    expect(report.findings.every(item => item.status === (mode === 'vulnerable' ? 'CONFIRMED' : 'NOT_REPRODUCED'))).toBe(true);
    expect(new Set(report.findings.map(item => item.cweId))).toEqual(new Set(['CWE-79', 'CWE-89']));
    expect(reportToJSON(report) + reportToMarkdown(report)).not.toMatch(/private-baseline|private-result/);
    expect(state.calls).toHaveLength(calls);
  });
});

import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Evidence, Project, StaticAnalyzer } from '@agento/core';
import { localFile, normalizeMatches, record } from './normalize.js';
import { readSources } from './repository.js';
import { ExecutionError, runSemgrep } from './runner.js';
import type { SemgrepAdapterOptions, SemgrepAnalysis, SemgrepDiagnostic } from './types.js';

const ruleFile = fileURLToPath(new URL('../rules/express-injection.yml', import.meta.url));
const defaults = { timeoutMs: 120_000, maxOutputBytes: 8_388_608 };
const hash = (...parts: string[]) => createHash('sha256').update(JSON.stringify(parts)).digest('hex').slice(0, 24);

export class SemgrepAdapter implements StaticAnalyzer {
  readonly id = 'semgrep-adapter';
  readonly capabilities = ['static-analysis', 'javascript', 'typescript', 'source-sink-evidence'] as const;
  private readonly timeoutMs: number;
  private readonly maxOutputBytes: number;
  constructor(private readonly options: SemgrepAdapterOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? defaults.timeoutMs;
    this.maxOutputBytes = options.maxOutputBytes ?? defaults.maxOutputBytes;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 600_000
      || !Number.isSafeInteger(this.maxOutputBytes) || this.maxOutputBytes < 1 || this.maxOutputBytes > 33_554_432) {
      throw new Error('Semgrep execution limits are invalid.');
    }
  }

  async analyze(project: Project): Promise<SemgrepAnalysis> {
    const capturedAt = (this.options.now ?? (() => new Date().toISOString()))();
    const diagnostics: SemgrepDiagnostic[] = [];
    let signals: SemgrepAnalysis['signals'] = [], evidence: Evidence[] = [];
    let status: SemgrepAnalysis['status'] = 'completed', sourceDigest = 'no-source', toolVersion: string | null = null;
    const finish = (): SemgrepAnalysis => {
      const id = `semgrep:${hash(project.id, 'run', sourceDigest, status, JSON.stringify(diagnostics))}`;
      const runEvidence: Evidence = { id, projectId: project.id, producerId: this.id, capturedAt, kind: 'static-analysis',
        summary: `Static analysis ${status}; signals are candidates requiring runtime verification.`,
        facts: { observation: 'static-analysis-run', status, diagnosticCodes: diagnostics.map(item => item.code),
          signalCount: signals.length, sourceDigest, toolVersion, runtimeVerified: false } };
      return { status, diagnostics, signals, evidence: [runEvidence, ...evidence] };
    };
    if (project.mode !== 'code-aware') {
      status = 'skipped'; diagnostics.push({ code: 'mode-not-code-aware', message: 'Static analysis requires code-aware mode.' }); return finish();
    }
    if (!project.repositoryPath) {
      status = 'failed'; diagnostics.push({ code: 'repository-unavailable', message: 'A repository path is required.' }); return finish();
    }
    if (!project.languages.some(language => ['javascript', 'typescript'].includes(language))) {
      status = 'skipped'; diagnostics.push({ code: 'unsupported-language', message: 'Bundled rules support JavaScript and TypeScript.' }); return finish();
    }
    const inventory = await readSources(project.repositoryPath);
    diagnostics.push(...inventory.diagnostics);
    sourceDigest = hash(...[...inventory.files].flatMap(([name, file]) => [name, file.text]));
    if (diagnostics.some(item => item.code === 'repository-unavailable')) { status = 'failed'; return finish(); }
    if (!inventory.files.size) { status = diagnostics.length ? 'partial' : 'completed'; return finish(); }
    let snapshot: string | undefined;
    try {
      snapshot = await mkdtemp(join(tmpdir(), 'agento-semgrep-'));
      for (const [name, file] of inventory.files) {
        await mkdir(dirname(join(snapshot, name)), { recursive: true });
        await writeFile(join(snapshot, name), file.text);
      }
      const result = await (this.options.runner ?? runSemgrep)({ executable: this.options.executable ?? 'semgrep',
        cwd: snapshot, timeoutMs: this.timeoutMs, maxOutputBytes: this.maxOutputBytes,
        args: ['scan', '--config', ruleFile, '--oss-only', '--json', '--dataflow-traces', '--metrics', 'off',
          '--disable-version-check', '--no-rewrite-rule-ids', '--no-error', '--disable-nosem', '--jobs', '1',
          '--max-target-bytes', '1048576', '--timeout', '5', '--', '.'] });
      if (Buffer.byteLength(result.stdout) > this.maxOutputBytes) throw new ExecutionError('output-limit');
      let parsed: unknown;
      try { parsed = JSON.parse(result.stdout); } catch { throw new ExecutionError('invalid-output'); }
      const raw = record(parsed);
      if (!raw || !Array.isArray(raw.results) || !Array.isArray(raw.errors)) throw new ExecutionError('invalid-output');
      if (typeof raw.version === 'string' && /^\d+\.\d+\.\d+$/.test(raw.version)) toolVersion = raw.version;
      if (raw.errors.length) diagnostics.push({ code: 'scan-error', message: 'Semgrep reported incomplete source analysis.' });
      const paths = record(raw.paths);
      const scanned = Array.isArray(paths?.scanned) ? new Set(paths.scanned.map(file => localFile(file, snapshot!))) : undefined;
      if (!scanned || [...inventory.files.keys()].some(file => !scanned.has(file))) {
        diagnostics.push({ code: 'scan-error', message: 'Semgrep did not report scanning every selected source file.' });
      }
      if (result.exitCode !== 0) diagnostics.push({ code: 'tool-failed', message: 'Semgrep returned a nonzero exit code.' });
      const normalized = normalizeMatches(raw, inventory, snapshot, project, this.options, capturedAt,
        (...parts) => `semgrep:${hash(sourceDigest, ...parts)}`);
      signals = normalized.signals; evidence = normalized.evidence; diagnostics.push(...normalized.diagnostics);
      status = diagnostics.length ? result.exitCode !== 0 && !signals.length ? 'failed' : 'partial' : 'completed';
    } catch (error) {
      status = 'failed';
      diagnostics.push({ code: error instanceof ExecutionError ? error.code : 'tool-failed',
        message: 'Static analysis could not complete; check the tool installation and execution limits.' });
    } finally {
      if (snapshot) await rm(snapshot, { recursive: true, force: true });
    }
    return finish();
  }
}

import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Endpoint, EndpointDiscoveryDiagnostic, EndpointDiscoveryProvider, EndpointDiscoveryReport,
  Evidence, FrameworkAnalysis, Project, SourceLocation } from '@agento/core';
import { readRepository, type Repository } from './repository.js';
import type { NoirOptions } from './types.js';

export const NOIR_VERSION = '1.4.0';
export const DEFAULT_SOURCE_EXCLUSIONS = ['data/static/codefixes'] as const;
const methods = new Set(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']);
const hash = (...parts: unknown[]) => createHash('sha256').update(JSON.stringify(parts)).digest('hex').slice(0, 24);
const record = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
type Code = EndpointDiscoveryDiagnostic['code'];
class ToolFailure extends Error { constructor(readonly code: Code) { super(code); } }
const messages: Record<Code, string> = {
  'tool-unavailable': 'Noir is unavailable. Install the pinned tool or set AGENTO_NOIR_EXECUTABLE.',
  'tool-version': 'Noir must use the supported version 1.4.0.', 'tool-failed': 'Noir did not finish successfully.',
  'tool-timeout': 'Noir exceeded its process time limit.', 'tool-output-limit': 'Noir exceeded its output limit.',
  cancelled: 'Endpoint discovery was cancelled.', 'invalid-output': 'Noir did not return the supported JSON format.',
  'invalid-endpoint': 'An endpoint record was omitted because it was invalid.',
  'invalid-source': 'An endpoint record was omitted because its source could not be checked.',
  'source-selection': 'Source selection is limited or contains unreadable files.',
};

/** Shell-free, fixed arguments, private environment and bounded output. Never forwards tool errors. */
async function run(executable: string, args: readonly string[], cwd: string, timeoutMs: number,
  maxBytes: number, signal?: AbortSignal): Promise<{ output: string; code: number | null }> {
  if (signal?.aborted) throw new ToolFailure('cancelled');
  return new Promise((accept, reject) => {
    const child = spawn(executable, [...args], { cwd, shell: false, detached: process.platform !== 'win32',
      env: { PATH: process.env.PATH ?? '/usr/bin:/bin', LANG: 'C.UTF-8', HOME: cwd, TMPDIR: cwd,
        XDG_CONFIG_HOME: join(cwd, 'config'), XDG_CACHE_HOME: join(cwd, 'cache') }, stdio: ['ignore', 'pipe', 'pipe'] });
    let bytes = 0, failure: Code | undefined;
    const output: Buffer[] = [];
    const kill = () => {
      try { if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, 'SIGKILL'); else child.kill('SIGKILL'); }
      catch { /* Process already stopped. */ }
    };
    const stop = (code: Code) => { failure ??= code; kill(); };
    const abort = () => stop('cancelled');
    const timer = setTimeout(() => stop('tool-timeout'), timeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    child.stdout.on('data', (chunk: Buffer) => { bytes += chunk.length;
      if (bytes > maxBytes) stop('tool-output-limit'); else if (!failure) output.push(chunk); });
    child.stderr.on('data', (chunk: Buffer) => { bytes += chunk.length; if (bytes > maxBytes) stop('tool-output-limit'); });
    child.on('error', () => { failure ??= 'tool-unavailable'; });
    child.on('close', code => {
      clearTimeout(timer); signal?.removeEventListener('abort', abort); kill();
      if (failure) reject(new ToolFailure(failure)); else accept({ output: Buffer.concat(output).toString('utf8'), code });
    });
  });
}

/** Noir is an inventory source only. This class has no probe, target transport, or policy port. */
export class NoirEndpointDiscoveryProvider implements EndpointDiscoveryProvider {
  readonly id = 'noir-endpoint-discovery';
  readonly capabilities = ['static-endpoint-discovery'] as const;
  private readonly executable: string;
  private readonly timeoutMs: number;
  private readonly maxOutputBytes: number;
  readonly excludePaths: readonly string[];
  private readonly now: () => string;
  constructor(options: NoirOptions = {}) {
    const bundled = fileURLToPath(new URL('../node_modules/.bin/noir', import.meta.url));
    const executable = options.executable ?? process.env.AGENTO_NOIR_EXECUTABLE ?? (existsSync(bundled) ? bundled : 'noir');
    this.executable = executable.includes('/') || executable.includes('\\') ? resolve(executable) : executable;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.maxOutputBytes = options.maxOutputBytes ?? 8_388_608;
    this.now = options.now ?? (() => new Date().toISOString());
    this.excludePaths = [...new Set([...DEFAULT_SOURCE_EXCLUSIONS, ...(options.excludePaths ?? [])])];
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 300_000
      || !Number.isSafeInteger(this.maxOutputBytes) || this.maxOutputBytes < 1 || this.maxOutputBytes > 67_108_864
      || this.excludePaths.some(path => !path || isAbsolute(path) || path.includes('\\')
        || path.split('/').some(part => !part || part === '.' || part === '..'))) throw new Error('Invalid endpoint discovery options');
  }

  async discover(project: Project, options: { readonly signal?: AbortSignal } = {}): Promise<FrameworkAnalysis & {
    readonly discovery: EndpointDiscoveryReport;
  }> {
    const diagnostics: EndpointDiscoveryDiagnostic[] = [];
    const report = (code: Code) => { if (!diagnostics.some(item => item.code === code)) diagnostics.push({ code, message: messages[code] }); };
    let status: EndpointDiscoveryReport['status'] = 'failed';
    let components: FrameworkAnalysis['components'] = [], endpoints: Endpoint[] = [], evidence: Evidence[] = [];
    let workspace: string | undefined;
    let selectedFiles = 0;
    const capturedAt = this.now();
    try {
      if (!project.repositoryPath) throw new ToolFailure('source-selection');
      const repository = await readRepository(project.repositoryPath, this.excludePaths);
      selectedFiles = repository.files.size;
      if (repository.diagnostics.length) report('source-selection');
      if (repository.diagnostics.some(item => item.code === 'repository-unavailable') || !selectedFiles) throw new ToolFailure('source-selection');
      if (options.signal?.aborted) throw new ToolFailure('cancelled');
      workspace = await mkdtemp(join(tmpdir(), 'agento-noir-'));
      const snapshot = join(workspace, 'source');
      await mkdir(snapshot);
      // Snapshot only the bounded, selected source. Noir cannot follow repository symlinks or load its configs.
      for (const [file, source] of repository.files) {
        const destination = join(snapshot, relative(repository.root, file));
        await mkdir(dirname(destination), { recursive: true });
        await writeFile(destination, source.text, { mode: 0o600 });
      }
      const config = join(workspace, 'empty.yaml');
      await writeFile(config, '{}\n', { mode: 0o600 });
      const version = await run(this.executable, ['--version'], workspace, this.timeoutMs, 4096, options.signal);
      if (version.code !== 0 || !new RegExp(`^v?${NOIR_VERSION.replaceAll('.', '\\.')}\\s*$`).test(version.output.trim())) {
        throw new ToolFailure('tool-version');
      }
      const result = await run(this.executable, ['scan', snapshot, '-f', 'json', '--no-log', '--no-color', '--no-spinner',
        '--strict', '--concurrency', '1', '--config-file', config, '--only-techs', 'js_express'],
      workspace, this.timeoutMs, this.maxOutputBytes, options.signal);
      if (result.code !== 0 && result.code !== 2) throw new ToolFailure('tool-failed');
      let raw: unknown;
      try { raw = JSON.parse(result.output); } catch { throw new ToolFailure('invalid-output'); }
      if (!record(raw) || !Array.isArray(raw.endpoints) || !Array.isArray(raw.errors)) throw new ToolFailure('invalid-output');
      if (result.code === 2 || raw.errors.length) report('tool-failed');
      if (raw.endpoints.length > 10_000) report('tool-output-limit');
      const componentId = `noir:service:${hash(project.id)}`;
      const normalized = normalize(raw.endpoints.slice(0, 10_000), project, repository, snapshot, componentId, capturedAt, report);
      endpoints = normalized.endpoints; evidence = normalized.evidence;
      if (endpoints.length) components = [{ id: componentId, projectId: project.id, name: project.name, kind: 'service' }];
      status = diagnostics.length ? 'partial' : 'completed';
    } catch (error) {
      const code = error instanceof ToolFailure ? error.code : 'tool-failed'; report(code);
      status = code === 'tool-unavailable' || code === 'tool-version' ? 'unavailable' : 'failed';
    } finally { if (workspace) await rm(workspace, { recursive: true, force: true }); }
    evidence.push({ id: `noir:run:${hash(project.id, status, endpoints.map(item => item.id), diagnostics)}`,
      projectId: project.id, producerId: this.id, capturedAt, kind: 'static-analysis',
      summary: 'Static endpoint discovery run. Inventory is incomplete until independently validated.',
      facts: { observation: 'endpoint-discovery-run', providerId: this.id, version: NOIR_VERSION, status,
        selectedFiles, candidateCount: endpoints.length, completeCoverage: false,
        diagnosticCodes: diagnostics.map(item => item.code), excludedPaths: this.excludePaths, runtimeVerified: false } });
    return { components, endpoints, resources: [], signals: [], evidence, discovery: { providerId: this.id, status, diagnostics } };
  }
}

function normalize(raw: unknown[], project: Project, repository: Repository, snapshot: string, componentId: string,
  capturedAt: string, report: (code: Code) => void): { endpoints: Endpoint[]; evidence: Evidence[] } {
  const endpoints = new Map<string, Endpoint>(), evidence = new Map<string, Evidence>();
  for (const entry of raw) {
    if (!record(entry) || !methods.has(String(entry.method)) || typeof entry.url !== 'string'
      || entry.protocol !== 'http' || entry.internal === true || !entry.url.startsWith('/') || entry.url.startsWith('//')
      || entry.url.length > 2048 || /[\x00-\x20\\?#%]/.test(entry.url) || entry.url.includes('..')
      || entry.url.split('/').some(segment => segment.startsWith('?')) || !Array.isArray(entry.params)) { report('invalid-endpoint'); continue; }
    const locations: SourceLocation[] = [];
    if (record(entry.details) && entry.details.technology === 'js_express' && Array.isArray(entry.details.code_paths)) {
      if (entry.details.code_paths.length > 32) report('tool-output-limit');
      for (const item of entry.details.code_paths.slice(0, 32)) {
        if (!record(item) || typeof item.path !== 'string' || !Number.isSafeInteger(item.line) || Number(item.line) < 1) continue;
        const file = relative(snapshot, resolve(snapshot, item.path));
        if (!file || file.startsWith('../') || isAbsolute(file)) continue;
        const source = repository.files.get(join(repository.root, file));
        if (!source || Number(item.line) > source.getLineStarts().length) continue;
        const location = { file: file.replaceAll('\\', '/'), startLine: Number(item.line) };
        if (!locations.some(value => value.file === location.file && value.startLine === location.startLine)) locations.push(location);
      }
    }
    if (!locations.length) { report('invalid-source'); continue; }
    const id = `noir:endpoint:${hash(project.id, entry.method, entry.url)}`;
    const parameters = new Map((endpoints.get(id)?.parameters ?? []).map(value => [`${value.location}:${value.name}`, value]));
    if (entry.params.length > 256) report('tool-output-limit');
    for (const item of entry.params.slice(0, 256)) {
      if (!record(item) || typeof item.name !== 'string' || item.name.length > 128 || !/^[A-Za-z0-9_$.[\]-]+$/.test(item.name)) continue;
      const type = item.param_type;
      const location = type === 'json' || type === 'form' || type === 'xml' ? 'body' : type;
      if (!['path', 'query', 'body', 'header', 'cookie'].includes(String(location))) continue;
      const key = `${location}:${item.name}`;
      if (parameters.size >= 256 && !parameters.has(key)) { report('tool-output-limit'); continue; }
      parameters.set(key, { name: item.name, location: location as Endpoint['parameters'][number]['location'], required: false });
    }
    const normalizedParameters = [...parameters.values()].sort((a, b) => a.location.localeCompare(b.location) || a.name.localeCompare(b.name));
    const references = new Set(endpoints.get(id)?.evidenceIds ?? []);
    for (const source of locations) {
      const evidenceId = `noir:source:${hash(id, source, normalizedParameters)}`; references.add(evidenceId);
      evidence.set(evidenceId, { id: evidenceId, projectId: project.id, producerId: 'noir-endpoint-discovery',
        capturedAt, kind: 'source-location', endpointId: id, source, summary: 'Unvalidated static endpoint candidate.',
        facts: { observation: 'endpoint-candidate', method: String(entry.method), path: entry.url,
          parameters: normalizedParameters.map(item => ({ ...item })), runtimeVerified: false } });
    }
    endpoints.set(id, { id, componentId, method: entry.method as Endpoint['method'], path: entry.url,
      parameters: normalizedParameters,
      authentication: 'unknown', roles: [], evidenceIds: [...references].sort(),
      discovery: { providerId: 'noir-endpoint-discovery', validation: 'candidate' } });
  }
  return { endpoints: [...endpoints.values()].sort((a, b) => a.method.localeCompare(b.method) || a.path.localeCompare(b.path)), evidence: [...evidence.values()] };
}

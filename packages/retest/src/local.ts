import { execFile } from 'node:child_process';
import { lstat, readdir, readFile, mkdtemp, mkdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import type { NormalizedProbeEvidence, ProbeTestPlan } from '@agento/cwe';
import { RetestError, type RegressionResult, type RetestEnvironment, type RetestInput, type RetestSession } from './contracts.js';
import { loopbackOrigin, safePath, sha256 } from './value.js';

export interface LocalTarget {
  readonly baseUrl: string;
  dispose(): Promise<void>;
}
/** Explicit host ports. Never infer shell commands, credentials or private probe inputs from patch prose. */
export interface LocalPatchOptions {
  readonly sourceDirectory: string;
  /** Only these source trees/files are copied. No symlinks, Git metadata or node_modules. */
  readonly include: readonly string[];
  /** Optional installed development dependencies linked into the temporary copy. */
  readonly dependencyDirectory?: string;
  start(directory: string, signal: AbortSignal): Promise<LocalTarget>;
  regression(directory: string, input: RetestInput, signal: AbortSignal): Promise<RegressionResult>;
  replay(target: LocalTarget, plan: ProbeTestPlan, targetUrl: string, signal: AbortSignal): Promise<NormalizedProbeEvidence>;
}
const exec = promisify(execFile);
const forbidden = (path: string) => path.split('/').some(part => part === 'node_modules' || part.startsWith('.')
  || /\.(?:env|sqlite|sqlite-journal|pem|key)$/.test(part));

/** Copies source, checks every reviewed hash, applies only ordinary unified hunks, then starts the host. */
export class LocalPatchEnvironment implements RetestEnvironment {
  readonly #options: LocalPatchOptions;
  constructor(options: LocalPatchOptions) {
    if (!options || !Array.isArray(options.include) || !options.include.length || options.include.length > 64
      || options.include.some(path => !safePath(path) || forbidden(path))
      || typeof options.sourceDirectory !== 'string' || !options.start || !options.regression || !options.replay) throw new RetestError('invalid-options');
    this.#options = { ...options, include: [...options.include] };
  }
  async create(input: RetestInput, signal: AbortSignal): Promise<RetestSession> {
    const options = this.#options, source = resolve(options.sourceDirectory);
    if (await realpath(source) !== source || !(await lstat(source)).isDirectory()) throw new RetestError('invalid-input');
    const directory = await mkdtemp(join(tmpdir(), 'agento-retest-'));
    let target: LocalTarget | undefined;
    const cleanup = async () => { try { await target?.dispose(); } finally { await rm(directory, { recursive: true, force: true }); } };
    try {
      let bytes = 0, files = 0;
      const copy = async (relative: string): Promise<void> => {
        if (signal.aborted) throw new Error();
        if (forbidden(relative)) throw new RetestError('invalid-input');
        const from = join(source, relative), to = join(directory, relative), stat = await lstat(from);
        if (stat.isSymbolicLink()) throw new RetestError('invalid-input');
        if (stat.isDirectory()) {
          await mkdir(to, { recursive: true });
          for (const child of await readdir(from)) await copy(relative + '/' + child);
        } else if (stat.isFile()) {
          bytes += stat.size;
          if (++files > 10_000 || bytes > 33_554_432) throw new RetestError('invalid-input');
          await mkdir(resolve(to, '..'), { recursive: true });
          await writeFile(to, await readFile(from), { flag: 'wx', mode: 0o600 });
        } else throw new RetestError('invalid-input');
      };
      for (const path of options.include) await copy(path);
      const suggestion = input.remediation;
      if (!Array.isArray(suggestion.files) || !suggestion.files.length || suggestion.files.length > 16
        || new Set(suggestion.files.map(file => file.path)).size !== suggestion.files.length
        || !safePath(suggestion.regressionTestPath) || forbidden(suggestion.regressionTestPath)
        || Buffer.byteLength(suggestion.patch) + Buffer.byteLength(suggestion.regressionTest) > 1_048_576) throw new RetestError('invalid-input');
      // Permit only the source-bound provider's ordinary per-file unified format; no modes, renames or binary content.
      const sections = suggestion.patch.split(/(?=^diff --git )/m).filter(Boolean);
      if (sections.length !== suggestion.files.length) throw new RetestError('invalid-input');
      for (const [index, file] of suggestion.files.entries()) {
        if (!safePath(file.path) || forbidden(file.path) || !/^[a-f0-9]{64}$/.test(file.beforeSha256)
          || !/^[a-f0-9]{64}$/.test(file.afterSha256) || sha256(await readFile(join(directory, file.path), 'utf8')) !== file.beforeSha256) throw new RetestError('invalid-input');
        const header = `diff --git a/${file.path} b/${file.path}\n--- a/${file.path}\n+++ b/${file.path}\n`;
        const body = sections[index]!.slice(header.length).split('\n'), hunk = /^@@ -\d+,(\d+) \+\d+,(\d+) @@$/.exec(body[0]!);
        if (!sections[index]!.startsWith(header) || !hunk || body.at(-1) !== ''
          || body.slice(1, -1).some(line => !/^[ +-]/.test(line))
          || body.slice(1, -1).filter(line => line[0] !== '+').length !== Number(hunk[1])
          || body.slice(1, -1).filter(line => line[0] !== '-').length !== Number(hunk[2])) throw new RetestError('invalid-input');
      }
      await exec('git', ['init', '--quiet', '--initial-branch=agento-retest'], { cwd: directory, signal, timeout: 10_000, maxBuffer: 65_536 });
      const patch = join(directory, '.repair.patch'); await writeFile(patch, suggestion.patch, { mode: 0o600, flag: 'wx' });
      await exec('git', ['apply', '--check', '--', patch], { cwd: directory, signal, timeout: 10_000, maxBuffer: 65_536 });
      await exec('git', ['apply', '--', patch], { cwd: directory, signal, timeout: 10_000, maxBuffer: 65_536 });
      for (const file of suggestion.files) if (sha256(await readFile(join(directory, file.path), 'utf8')) !== file.afterSha256) throw new RetestError('invalid-input');
      const testPath = join(directory, suggestion.regressionTestPath);
      await mkdir(resolve(testPath, '..'), { recursive: true });
      await writeFile(testPath, suggestion.regressionTest, { flag: 'wx', mode: 0o600 });
      if (options.dependencyDirectory) await symlink(await realpath(options.dependencyDirectory), join(directory, 'node_modules'), 'dir');
      target = await options.start(directory, signal);
      loopbackOrigin(target.baseUrl);
      if (signal.aborted) throw new Error();
      const active = target;
      return { id: `isolated:${randomUUID()}`, baseUrl: active.baseUrl,
        runRegression: signal => options.regression(directory, input, signal),
        replay: (plan, targetUrl, signal) => options.replay(active, plan, targetUrl, signal), dispose: cleanup };
    } catch (error) { await cleanup(); throw error; }
  }
}

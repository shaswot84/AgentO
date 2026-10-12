import { spawn } from 'node:child_process';
import { join } from 'node:path';
import type { DiagnosticCode, SemgrepInvocation, SemgrepProcessResult } from './types.js';

export class ExecutionError extends Error {
  constructor(readonly code: DiagnosticCode) { super(code); }
}

/** Fixed argv, no shell, bounded output/time, and no inherited Semgrep credentials/configuration. */
export function runSemgrep(invocation: SemgrepInvocation): Promise<SemgrepProcessResult> {
  return new Promise((resolve, reject) => {
    const environment: NodeJS.ProcessEnv = {};
    for (const key of ['PATH', 'SystemRoot', 'WINDIR', 'TMPDIR', 'TEMP', 'TMP', 'LANG']) {
      if (process.env[key]) environment[key] = process.env[key];
    }
    Object.assign(environment, {
      SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0',
      SEMGREP_SETTINGS_FILE: join(invocation.cwd, '.semgrep-settings.yml'),
      SEMGREP_LOG_FILE: join(invocation.cwd, '.semgrep.log'),
      XDG_CONFIG_HOME: invocation.cwd, XDG_CACHE_HOME: invocation.cwd,
    });
    const child = spawn(invocation.executable, [...invocation.args], {
      cwd: invocation.cwd, env: environment, shell: false,
      stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32',
    });
    const chunks: Buffer[] = [];
    let bytes = 0, failure: DiagnosticCode | undefined;
    function stop(code: DiagnosticCode): void {
      failure ??= code;
      try {
        if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch { child.kill('SIGKILL'); }
    }
    const timer = setTimeout(() => stop('timeout'), invocation.timeoutMs);
    child.stdout.on('data', (data: Buffer) => {
      bytes += data.length;
      if (bytes > invocation.maxOutputBytes) stop('output-limit');
      else chunks.push(data);
    });
    // Stderr is never forwarded or retained; it can contain secrets and raw source.
    child.stderr.on('data', (data: Buffer) => {
      bytes += data.length;
      if (bytes > invocation.maxOutputBytes) stop('output-limit');
    });
    child.on('error', (error: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      reject(new ExecutionError(error.code === 'ENOENT' ? 'tool-not-found' : 'tool-failed'));
    });
    child.on('close', exitCode => {
      clearTimeout(timer);
      if (failure) reject(new ExecutionError(failure));
      else if (exitCode === null) reject(new ExecutionError('tool-failed'));
      else resolve({ exitCode, stdout: Buffer.concat(chunks).toString('utf8') });
    });
  });
}

import { spawn } from 'node:child_process';
import { ScannerError } from './contracts.js';
import type { ProcessRunner } from './contracts.js';

/** No shell, no inherited credentials, and one process group per invocation. */
export const runProcess: ProcessRunner = input => new Promise((resolve, reject) => {
  if (input.signal.aborted) { reject(new ScannerError('cancelled')); return; }
  const child = spawn(input.executable, [...input.args], { cwd: input.cwd, env: { ...input.env },
    shell: false, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] });
  let failure: ScannerError | undefined, size = 0;
  const out: Buffer[] = [], err: Buffer[] = [];
  const kill = () => {
    try {
      if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, 'SIGKILL');
      else child.kill('SIGKILL');
    } catch { /* The process group has already exited. */ }
  };
  const stop = (code: 'timeout' | 'cancelled' | 'output-limit') => { failure ??= new ScannerError(code); kill(); };
  const timer = setTimeout(() => stop('timeout'), input.timeoutMs);
  const abort = () => stop('cancelled');
  input.signal.addEventListener('abort', abort, { once: true });
  if (input.signal.aborted) abort();
  const collect = (chunks: Buffer[]) => (chunk: Buffer) => {
    size += chunk.length;
    if (size > input.maxOutputBytes) stop('output-limit');
    else chunks.push(chunk);
  };
  child.stdout.on('data', collect(out)); child.stderr.on('data', collect(err));
  child.on('error', error => {
    failure ??= new ScannerError((error as NodeJS.ErrnoException).code === 'ENOENT' ? 'not-installed' : 'tool-failed');
  });
  child.on('close', code => {
    clearTimeout(timer); input.signal.removeEventListener('abort', abort); kill();
    if (failure) reject(failure);
    else resolve({ stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8'), exitCode: code ?? -1 });
  });
});

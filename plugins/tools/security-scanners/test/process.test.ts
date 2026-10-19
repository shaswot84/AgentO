import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import { runProcess } from '../src/process.js';
import type { ProcessInput } from '../src/index.js';

function command(code: string, overrides: Partial<ProcessInput> = {}): ProcessInput {
  return { executable: process.execPath, args: ['-e', code], cwd: tmpdir(), env: { PATH: process.env.PATH ?? '' },
    timeoutMs: 2000, maxOutputBytes: 1024, signal: new AbortController().signal, ...overrides };
}
describe('bounded subprocesses', () => {
  it('keeps shell syntax literal and does not inherit parent credentials', async () => {
    const output = await runProcess(command('process.stdout.write(JSON.stringify([process.argv[1], process.env.HOME, process.env.OPENAI_API_KEY]));',
      { args: ['-e', 'process.stdout.write(JSON.stringify([process.argv[1], process.env.HOME, process.env.OPENAI_API_KEY]));', '$(touch /tmp/not-created)'] }));
    expect(JSON.parse(output.stdout)).toEqual(['$(touch /tmp/not-created)', null, null]);
  });
  it('reports missing executables with a stable code', async () => {
    await expect(runProcess(command('', { executable: '/tmp/agento-scanner-file-that-does-not-exist' }))).rejects.toMatchObject({ code: 'not-installed' });
  });
  it('bounds combined stdout and stderr', async () => {
    await expect(runProcess(command('process.stderr.write("x".repeat(1025));'))).rejects.toMatchObject({ code: 'output-limit' });
  });
  it('terminates a stalled process on its deadline', async () => {
    await expect(runProcess(command('setInterval(()=>{},1000)', { timeoutMs: 100 }))).rejects.toMatchObject({ code: 'timeout' });
  });
  it('terminates a running process on cancellation', async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 100);
    try { await expect(runProcess(command('setInterval(()=>{},1000)', { signal: controller.signal }))).rejects.toMatchObject({ code: 'cancelled' }); }
    finally { clearTimeout(timer); }
  });
  it('does not start an already cancelled process', async () => {
    await expect(runProcess(command('', { signal: AbortSignal.abort() }))).rejects.toMatchObject({ code: 'cancelled' });
  });
});

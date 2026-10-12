import { describe, expect, it } from 'vitest';
import { join } from 'node:path';
import { runSemgrep } from '../src/runner.js';
import { repository } from './helpers.js';

const python = process.env.AGENTO_TEST_PYTHON ?? 'python3';

describe('real process boundary', () => {
  it('uses argument arrays and a sanitized environment without a shell', async () => {
    const cwd = await repository({});
    const marker = '$(touch SHOULD_NOT_EXIST); `echo SECRET`';
    const previous = process.env.SEMGREP_APP_TOKEN;
    process.env.SEMGREP_APP_TOKEN = 'CREDENTIAL_SECRET';
    try {
      const result = await runSemgrep({ executable: python, cwd, timeoutMs: 3_000, maxOutputBytes: 16_384,
        args: ['-c', 'import json, os, sys; print(json.dumps({"arg":sys.argv[1], "token":os.environ.get("SEMGREP_APP_TOKEN"), "metrics":os.environ.get("SEMGREP_SEND_METRICS"), "log":os.environ.get("SEMGREP_LOG_FILE")}))', marker] });
      expect(result.exitCode).toBe(0);
      expect(JSON.parse(result.stdout)).toEqual({ arg: marker, token: null, metrics: 'off', log: join(cwd, '.semgrep.log') });
    } finally {
      if (previous === undefined) delete process.env.SEMGREP_APP_TOKEN;
      else process.env.SEMGREP_APP_TOKEN = previous;
    }
  });

  it('returns a typed missing-tool failure without raw process errors', async () => {
    const cwd = await repository({});
    await expect(runSemgrep({ executable: join(cwd, 'missing-semgrep'), cwd, args: [], timeoutMs: 500,
      maxOutputBytes: 1_024 })).rejects.toMatchObject({ code: 'tool-not-found', message: 'tool-not-found' });
  });

  it('terminates long-running processes', async () => {
    const cwd = await repository({});
    await expect(runSemgrep({ executable: python, cwd, args: ['-c', 'import time; time.sleep(60)'],
      timeoutMs: 50, maxOutputBytes: 1_024 })).rejects.toMatchObject({ code: 'timeout' });
  });

  it.each(['stdout', 'stderr'])('bounds %s without leaking its content', async stream => {
    const cwd = await repository({});
    await expect(runSemgrep({ executable: python, cwd,
      args: ['-c', `import sys; sys.${stream}.write('RAW_SECRET' * 1000)`], timeoutMs: 3_000,
      maxOutputBytes: 100 })).rejects.toMatchObject({ code: 'output-limit', message: 'output-limit' });
  });
});

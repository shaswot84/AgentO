import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { MVP_CWES } from '@agento/core';
import { fixture, repository } from './helpers.js';

const sandbox = mkdtempSync(join(tmpdir(), 'agento-remediation-check-'));
afterAll(() => rmSync(sandbox, { recursive: true, force: true }));
const key = join(sandbox, 'key.pem'), cert = join(sandbox, 'cert.pem');
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
  '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'], { stdio: 'ignore' });

type Assertion = { title: string; status: string };
function regressions(path: string, testPath: string) {
  const output = join(path, 'regression-results.json');
  let exitCode = 0;
  try {
    execFileSync(process.execPath, [join(repository, 'node_modules/vitest/vitest.mjs'), 'run', testPath,
      '--reporter=json', '--outputFile=' + output], { cwd: path, timeout: 30_000, stdio: 'pipe',
      env: { ...process.env, AGENTO_TEST_TLS_KEY: key, AGENTO_TEST_TLS_CERT: cert, DB_PATH: ':memory:' } });
  } catch (error) { exitCode = (error as { status: number }).status; }
  const report = JSON.parse(readFileSync(output, 'utf8')) as { testResults: { assertionResults: Assertion[] }[] };
  return { exitCode, assertions: report.testResults.flatMap(item => item.assertionResults) };
}

describe('generated patches against the real Express storefront in isolated temporary branches', () => {
  it.each(MVP_CWES)('%s security tests fail before the patch and pass after; normal behavior remains', async cweId => {
    const state = fixture(cweId), original = JSON.stringify(state.context.evidence);
    const suggestion = await state.provider.suggest(state.context, state.finding);
    const path = join(sandbox, cweId); mkdirSync(path);
    for (const item of ['src', 'public', 'package.json', 'tsconfig.json']) cpSync(join(repository, item), join(path, item), { recursive: true });
    // A separate repository and named fixture branch; the user's Git metadata is never touched.
    execFileSync('git', ['init', '--quiet', '--initial-branch=remediation-fixture'], { cwd: path });
    symlinkSync(join(repository, 'node_modules'), join(path, 'node_modules'), 'dir');
    mkdirSync(join(path, 'test'));
    writeFileSync(join(path, suggestion.regressionTestPath), suggestion.regressionTest, { flag: 'wx' });
    const before = regressions(path, suggestion.regressionTestPath);
    expect(before.exitCode).toBe(1);
    expect(before.assertions.filter(item => item.title.startsWith('security:')).every(item => item.status === 'failed')).toBe(true);
    expect(before.assertions.filter(item => item.title.startsWith('normal:')).every(item => item.status === 'passed')).toBe(true);
    expect(before.assertions).toHaveLength(2);
    const patchPath = join(path, 'repair.patch'); writeFileSync(patchPath, suggestion.patch);
    execFileSync('git', ['apply', '--check', patchPath], { cwd: path });
    execFileSync('git', ['apply', patchPath], { cwd: path });
    execFileSync(process.execPath, [join(repository, 'node_modules/typescript/bin/tsc'), '-p', 'tsconfig.json', '--noEmit'], { cwd: path, stdio: 'pipe' });
    const after = regressions(path, suggestion.regressionTestPath);
    expect(after.exitCode).toBe(0);
    expect(after.assertions.every(item => item.status === 'passed')).toBe(true);
    for (const source of state.sources) expect(readFileSync(join(repository, source.path), 'utf8')).toBe(source.content);
    expect(JSON.stringify(state.context.evidence)).toBe(original);
    expect(suggestion.validation).toBe('NOT_RUN');
  }, 90_000);
});

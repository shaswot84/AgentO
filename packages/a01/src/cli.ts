#!/usr/bin/env node
import { lstat, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Persona } from '@agento/core';
import { FileEvidenceStore } from '@agento/evidence';
import { FormLoginStrategy } from '@agento/tool-e2e-browser';
import { A01Error } from './contracts.js';
import { runA01Scan } from './scan.js';

interface Account {
  id: string; label: string; roles: string[]; usernameEnv: string; passwordEnv: string;
  expectedIdentity: string; expectedRole: string;
}
/** Credentials are read only during a guarded login, never copied into the report. */
export async function scanFile(configPath: string) {
  const path = resolve(configPath), input = JSON.parse(await readFile(path, 'utf8'));
  const { project, targets, policy, accounts, login, evidenceDirectory, output } = input;
  const relative = (value: string) => resolve(path, '..', value);
  if (typeof evidenceDirectory !== 'string' || !evidenceDirectory || typeof output !== 'string' || !output
    || !project || typeof project.repositoryPath !== 'string' || !Array.isArray(accounts) || accounts.length < 2 || accounts.length > 10
    || accounts.some((account: Account) => !account || ![account.usernameEnv, account.passwordEnv].every(value => typeof value === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(value))
      || !account.expectedIdentity || !account.expectedRole)
    || !login || ![login.loginUrl, login.usernameSelector, login.passwordSelector, login.submitSelector, login.verificationUrl].every(value => typeof value === 'string' && value)
    || !login.response || ![login.identityPath, login.rolePath].every(value => Array.isArray(value) && value.length > 0
      && value.length <= 16 && value.every(part => typeof part === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(part)))) throw new A01Error('invalid-options');
  try { await lstat(relative(output)); throw new A01Error('invalid-options'); }
  catch (error) { if (!(error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT')) throw error; }
  const personas: Persona[] = accounts.map((account: Account) => ({ id: account.id, label: account.label, roles: account.roles,
    authentication: 'session-cookie', credentialsRef: `a01:${account.id}`, expectedRole: account.expectedRole }));
  const authentication = new FormLoginStrategy({ loginUrl: login.loginUrl, usernameSelector: login.usernameSelector,
    passwordSelector: login.passwordSelector, submitSelector: login.submitSelector, response: login.response,
    ...(login.successUrl ? { successUrl: login.successUrl } : {}), verification: persona => ({ url: login.verificationUrl,
      identityPath: login.identityPath, expectedIdentity: (accounts as Account[]).find(account => account.id === persona.id)!.expectedIdentity,
      role: { path: login.rolePath, expected: persona.expectedRole! } }) });
  const store = new FileEvidenceStore(relative(evidenceDirectory), { expectedHeadDigest: null });
  try {
    const report = await runA01Scan({ project: { ...project, repositoryPath: relative(project.repositoryPath) }, targets, policy, evidenceStore: store,
      target: { id: 'a01-cli', baseOrigins: project.allowedOrigins, personas, authentication: [authentication], defaultAuthenticationStrategyId: authentication.id },
      credentials: async persona => {
        const account = (accounts as Account[]).find(account => account.id === persona.id)!;
        const username = process.env[account.usernameEnv], password = process.env[account.passwordEnv];
        if (!username || !password) throw new Error('Credentials unavailable');
        return { username, password };
      } });
    await writeFile(relative(output), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    return report;
  } finally { store.close(); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || process.argv[2] === '--help') {
    process.stdout.write('Usage: node packages/a01/dist/cli.js /private/scan.json\n');
    process.exitCode = process.argv[2] === '--help' ? 0 : 1;
  } else scanFile(process.argv[2]!).then(report => {
    process.stdout.write(`${report.findings.length} verdicts; ${report.findings.filter(item => item.status === 'CONFIRMED').length} confirmed.\n`);
    if (report.executions.some(item => item.outcome !== 'COMPLETED') || report.diagnostics.length) process.exitCode = 2;
  }).catch(error => { process.stderr.write(`A01 scan failed: ${error instanceof A01Error ? error.code : 'scan-failed'}.\n`); process.exitCode = 1; });
}

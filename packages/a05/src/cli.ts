#!/usr/bin/env node
import { lstat, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FileEvidenceStore } from '@agento/evidence';
import { DalfoxAdapter, SqlmapAdapter } from '@agento/security-scanners';
import { A05Error } from './contracts.js';
import { runA05Scan } from './scan.js';

export async function scanFile(configPath: string) {
  const path = resolve(configPath), input = JSON.parse(await readFile(path, 'utf8'));
  const { evidenceDirectory, output, semgrepExecutable, dalfoxExecutable, sqlmapExecutable,
    project, targets, policy, allowAnonymous, maxScannerRequests } = input;
  const relative = (value: string) => resolve(path, '..', value);
  if (typeof evidenceDirectory !== 'string' || !evidenceDirectory || typeof output !== 'string' || !output
    || !project || typeof project.repositoryPath !== 'string'
    || [semgrepExecutable, dalfoxExecutable, sqlmapExecutable].some(value => value !== undefined && (typeof value !== 'string' || !value))) throw new A05Error('invalid-options');
  try { await lstat(relative(output)); throw new A05Error('invalid-options'); }
  catch (error) { if (!(error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT')) throw error; }
  const store = new FileEvidenceStore(relative(evidenceDirectory), { expectedHeadDigest: null });
  try {
    const report = await runA05Scan({ project: { ...project, repositoryPath: relative(project.repositoryPath) }, targets, policy,
      ...(allowAnonymous !== undefined ? { allowAnonymous } : {}), ...(maxScannerRequests !== undefined ? { maxScannerRequests } : {}),
      ...(semgrepExecutable ? { semgrepExecutable } : {}), evidenceStore: store,
      scanners: [new DalfoxAdapter(dalfoxExecutable ? { executable: dalfoxExecutable } : {}).registration(),
        new SqlmapAdapter(sqlmapExecutable ? { executable: sqlmapExecutable } : {}).registration()] });
    await writeFile(relative(output), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    return report;
  } finally { store.close(); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || process.argv[2] === '--help') {
    process.stdout.write('Usage: node packages/a05/dist/cli.js /private/scan.json\n');
    process.exitCode = process.argv[2] === '--help' ? 0 : 1;
  } else scanFile(process.argv[2]!).then(report => {
    process.stdout.write(`${report.findings.length} verdicts; ${report.findings.filter(item => item.status === 'CONFIRMED').length} confirmed.\n`);
    if (report.executions.some(item => item.outcome !== 'COMPLETED') || report.diagnostics.length) process.exitCode = 2;
  }).catch(error => { process.stderr.write(`A05 scan failed: ${error instanceof A05Error ? error.code : 'scan-failed'}.\n`); process.exitCode = 1; });
}

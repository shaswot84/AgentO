import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { RuntimeError } from '@agento/runtime';
import type { DatabaseFingerprint, ScannerRequest, SecurityScannerRequest, SQLScanner } from '@agento/runtime';
import { ScannerAdapter } from './adapter.js';
import { ScannerError } from './contracts.js';
import type { ScannerOptions } from './contracts.js';
import { sqlmap } from './normalize.js';

export class SqlmapAdapter extends ScannerAdapter implements SQLScanner {
  readonly id = 'sqlmap-adapter';
  override readonly capabilities = Object.freeze(['security-scanner', 'sql-scanner']);
  constructor(options: ScannerOptions = {}) { super(options, 'sqlmap'); }
  override registration() {
    const registration = super.registration();
    return { ...registration, metadata: { ...registration.metadata, capabilities: ['security-scanner', 'sql-scanner'] as const,
      supportedCwes: ['CWE-89'] as const }, capabilities: { ...registration.capabilities, 'sql-scanner': { scan: this.scan.bind(this) } } };
  }
  protected async prepare(input: SecurityScannerRequest, url: string, directory: string) {
    if (input.cweId !== 'CWE-89' || !input.parameter) throw new ScannerError('invalid-input');
    const target = new URL(url), requestFile = join(directory, 'request.txt');
    const contentType = input.parameter.location === 'json-body' ? 'application/json' : 'application/x-www-form-urlencoded';
    await writeFile(requestFile, `${input.request.method ?? 'GET'} ${target.pathname}${target.search} HTTP/1.1\r\nHost: ${target.host}\r\nContent-Type: ${contentType}\r\nConnection: close\r\n\r\n${input.request.body ?? ''}`, { mode: 0o600 });
    return { args: ['-r', requestFile, '-p', input.parameter.name, '--batch', '--flush-session', '--disable-coloring',
      '--technique=BE', '--risk=1', '--level=1', '--threads=1', '--timeout=5', '--retries=0', '--skip-waf',
      '--ignore-redirects', '--answers=follow=N', '--output-dir', join(directory, 'sqlmap'), '--tmp-dir', directory,
      '--proxy', target.origin] };
  }
  protected normalize(text: string, url: string) { return sqlmap(text, url); }
  async scan(input: ScannerRequest) {
    const result = await this.run({ ...input, cweId: 'CWE-89', planId: 'sql-injection-probe' });
    if (result.error?.code === 'cancelled') throw new RuntimeError('cancelled');
    const candidate = result.evidence.find(item => item.facts.observation === 'scanner-candidate');
    const technique = candidate?.facts.technique;
    return Object.freeze({ technique: technique === 'boolean' || technique === 'time' ? technique : 'error' as const,
      dbmsFingerprint: (candidate?.facts.dbmsFingerprint ?? null) as DatabaseFingerprint | null,
      // Console claims do not prove a paired, controlled response difference.
      observedDifference: null,
      ...(result.outcome === 'COMPLETED' ? {} : { diagnostic: result.outcome === 'SKIPPED' ? 'scanner-skipped' as const : 'scanner-failed' as const }) });
  }
}

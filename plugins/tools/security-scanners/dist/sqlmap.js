import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { RuntimeError } from '@agento/runtime';
import { ScannerAdapter } from './adapter.js';
import { ScannerError } from './contracts.js';
import { sqlmap } from './normalize.js';
export class SqlmapAdapter extends ScannerAdapter {
    id = 'sqlmap-adapter';
    capabilities = Object.freeze(['security-scanner', 'sql-scanner']);
    constructor(options = {}) { super(options, 'sqlmap'); }
    registration() {
        const registration = super.registration();
        return { ...registration, metadata: { ...registration.metadata, capabilities: ['security-scanner', 'sql-scanner'],
                supportedCwes: ['CWE-89'] }, capabilities: { ...registration.capabilities, 'sql-scanner': { scan: this.scan.bind(this) } } };
    }
    async prepare(input, url, directory) {
        if (input.cweId !== 'CWE-89' || !input.parameter)
            throw new ScannerError('invalid-input');
        const target = new URL(url), requestFile = join(directory, 'request.txt');
        const contentType = input.parameter.location === 'json-body' ? 'application/json' : 'application/x-www-form-urlencoded';
        await writeFile(requestFile, `${input.request.method ?? 'GET'} ${target.pathname}${target.search} HTTP/1.1\r\nHost: ${target.host}\r\nContent-Type: ${contentType}\r\nConnection: close\r\n\r\n${input.request.body ?? ''}`, { mode: 0o600 });
        return { args: ['-r', requestFile, '-p', input.parameter.name, '--batch', '--flush-session', '--disable-coloring',
                '--technique=BE', '--risk=1', '--level=1', '--threads=1', '--timeout=5', '--retries=0', '--skip-waf',
                '--ignore-redirects', '--answers=follow=N', '--output-dir', join(directory, 'sqlmap'), '--tmp-dir', directory,
                '--proxy', target.origin] };
    }
    normalize(text, url) { return sqlmap(text, url); }
    async scan(input) {
        const result = await this.run({ ...input, cweId: 'CWE-89', planId: 'sql-injection-probe' });
        if (result.error?.code === 'cancelled')
            throw new RuntimeError('cancelled');
        const candidate = result.evidence.find(item => item.facts.observation === 'scanner-candidate');
        const technique = candidate?.facts.technique;
        return Object.freeze({ technique: technique === 'boolean' || technique === 'time' ? technique : 'error',
            dbmsFingerprint: (candidate?.facts.dbmsFingerprint ?? null),
            // Console claims do not prove a paired, controlled response difference.
            observedDifference: null,
            ...(result.outcome === 'COMPLETED' ? {} : { diagnostic: result.outcome === 'SKIPPED' ? 'scanner-skipped' : 'scanner-failed' }) });
    }
}

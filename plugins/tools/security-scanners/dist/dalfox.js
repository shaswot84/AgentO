import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { RuntimeError } from '@agento/runtime';
import { ScannerAdapter } from './adapter.js';
import { ScannerError } from './contracts.js';
import { dalfox } from './normalize.js';
export class DalfoxAdapter extends ScannerAdapter {
    id = 'dalfox-adapter';
    capabilities = Object.freeze(['security-scanner', 'xss-scanner']);
    headPreflight = true;
    constructor(options = {}) { super(options, 'dalfox'); }
    registration() {
        const registration = super.registration();
        return { ...registration, metadata: { ...registration.metadata, capabilities: ['security-scanner', 'xss-scanner'],
                supportedCwes: ['CWE-79'] }, capabilities: { ...registration.capabilities, 'xss-scanner': { scan: this.scan.bind(this) } } };
    }
    async prepare(input, url, directory) {
        if (input.cweId !== 'CWE-79' || !input.parameter || input.parameter.location !== 'query'
            || (input.request.method ?? 'GET') !== 'GET' || input.request.body !== undefined)
            throw new ScannerError('invalid-input');
        const targets = join(directory, 'targets.txt');
        await writeFile(targets, `${url}\n`, { mode: 0o600 });
        return { args: ['scan', '--input-type', 'file', targets, '--format', 'json', '--silence', '--no-color', '--skip-discovery', '--skip-mining',
                '--skip-ast-analysis', '--skip-waf-probe', '--workers', '1', '--timeout', '5', '--max-payloads-per-param', '2',
                '--max-concurrent-targets', '1', '--param', input.parameter.name, '--proxy', new URL(url).origin], acceptedExits: [0, 1] };
    }
    normalize(text, url) { return dalfox(text, url); }
    async scan(input) {
        const result = await this.run({ ...input, cweId: 'CWE-79', planId: 'xss-probe' });
        if (result.error?.code === 'cancelled')
            throw new RuntimeError('cancelled');
        // A scanner's V/R/A label alone cannot attest browser execution or a reached DOM sink.
        return Object.freeze({ executionConfirmed: null, domSinkReached: null,
            ...(result.outcome === 'COMPLETED' ? {} : { diagnostic: result.outcome === 'SKIPPED' ? 'scanner-skipped' : 'scanner-failed' }) });
    }
}

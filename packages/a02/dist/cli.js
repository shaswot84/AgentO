#!/usr/bin/env node
import { lstat, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DeterministicRequestExecutor } from '@agento/runtime';
import { FileEvidenceStore } from '@agento/evidence';
import { A02Error } from './contracts.js';
import { HttpCookieAuthenticationManager } from './authentication.js';
import { runA02Scan } from './scan.js';
/** JSON contains environment variable names, never passwords. Config paths resolve beside the config file. */
export async function scanFile(configPath) {
    const path = resolve(configPath), input = JSON.parse(await readFile(path, 'utf8'));
    const { login, evidenceDirectory, output, ...options } = input;
    if (typeof evidenceDirectory !== 'string' || !evidenceDirectory || typeof output !== 'string' || !output)
        throw new A02Error('invalid-options');
    const relative = (value) => resolve(path, '..', value);
    try {
        await lstat(relative(output));
        throw new A02Error('invalid-options');
    }
    catch (error) {
        if (!(error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT'))
            throw error;
    }
    options.project.repositoryPath = relative(options.project.repositoryPath);
    const secrets = [];
    const authentication = login ? new HttpCookieAuthenticationManager({
        executor: new DeterministicRequestExecutor({ baseUrl: options.project.baseUrl, allowedOrigins: options.project.allowedOrigins }),
        login: async (identity) => {
            const fields = login.identities?.[identity.id];
            if (!fields || typeof login.path !== 'string')
                throw new A02Error('invalid-options');
            const body = {};
            for (const [field, variable] of Object.entries(fields)) {
                if (typeof variable !== 'string' || !process.env[variable])
                    throw new A02Error('invalid-options');
                body[field] = process.env[variable];
            }
            return { url: login.path, method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) };
        },
    }) : undefined;
    if (login)
        for (const fields of Object.values(login.identities ?? {}))
            for (const [field, variable] of Object.entries(fields)) {
                if (typeof variable !== 'string' || !process.env[variable])
                    throw new A02Error('invalid-options');
                // Public identity names can equal the username. Preserve those references.
                if (!/^(?:user(?:name)?|email)$/i.test(field))
                    secrets.push(process.env[variable]);
            }
    const store = new FileEvidenceStore(relative(evidenceDirectory), { secrets, expectedHeadDigest: null });
    try {
        const report = await runA02Scan({ ...options, evidenceStore: store, ...(authentication ? { authentication } : {}) });
        await writeFile(relative(output), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
        return report;
    }
    finally {
        store.close();
        await authentication?.close();
    }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    if (process.argv.length !== 3 || process.argv[2] === '--help') {
        process.stdout.write('Usage: node packages/a02/dist/cli.js /private/scan.json\n');
        process.exitCode = process.argv[2] === '--help' ? 0 : 1;
    }
    else {
        scanFile(process.argv[2]).then(report => {
            process.stdout.write(`${report.findings.length} verdicts; ${report.findings.filter(item => item.status === 'CONFIRMED').length} confirmed.\n`);
            if (report.executions.some(item => item.outcome !== 'COMPLETED') || report.diagnostics.length)
                process.exitCode = 2;
        }).catch(error => { process.stderr.write(`A02 scan failed: ${error instanceof A02Error ? error.code : 'scan-failed'}.\n`); process.exitCode = 1; });
    }
}

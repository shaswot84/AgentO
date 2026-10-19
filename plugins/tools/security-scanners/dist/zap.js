import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { ScannerAdapter } from './adapter.js';
import { zap } from './normalize.js';
/** Dedicated command-mode instance; passive scanning of the explicitly requested exchange. */
export class ZapAdapter extends ScannerAdapter {
    id = 'zap-adapter';
    constructor(options = {}) { super(options, 'zap.sh'); }
    async prepare(input, url, directory) {
        const plan = join(directory, 'zap-plan.yaml');
        // JSON is a YAML subset. No planner text is interpolated into YAML or command arguments.
        await writeFile(plan, JSON.stringify({ env: {
                contexts: [{ name: 'agento', urls: [new URL(url).origin], includePaths: [escapeRegex(url)] }],
                parameters: { failOnError: true, failOnWarning: true, progressToStdout: false },
            }, jobs: [
                { type: 'passiveScan-config', parameters: { scanOnlyInScope: true } },
                { type: 'requestor', requests: [{ url, method: input.request.method ?? 'GET',
                            ...(input.request.body !== undefined ? { data: input.request.body } : {}),
                            headers: Object.entries(input.request.headers ?? {}).filter(([name]) => name.toLowerCase() === 'content-type')
                                .map(([name, value]) => `${name}: ${value}`) }] },
                { type: 'passiveScan-wait', parameters: { maxDuration: 1 } },
                { type: 'report', parameters: { template: 'traditional-json', reportDir: directory,
                        reportFile: 'zap-report.json', displayReport: false } },
            ] }), { mode: 0o600 });
        return { args: ['-cmd', '-silent', '-dir', join(directory, 'home'), '-config', 'autoupdate.checkOnStart=false',
                '-config', 'autoupdate.downloadNewRelease=false', '-config', 'oast.callback.localaddr=127.0.0.1',
                '-config', 'oast.callback.remoteaddr=127.0.0.1', '-autorun', plan], reportFile: join(directory, 'zap-report.json') };
    }
    normalize(text, url) { return zap(text, url); }
}
function escapeRegex(value) { return `^${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`; }

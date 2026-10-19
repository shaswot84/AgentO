import { access, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ScannerAdapter } from './adapter.js';
import { ScannerError } from './contracts.js';
import { nuclei } from './normalize.js';
const bundled = fileURLToPath(new URL('../templates/response-observation.yaml', import.meta.url));
export class NucleiAdapter extends ScannerAdapter {
    id = 'nuclei-adapter';
    templates;
    constructor(options = {}) {
        super(options, 'nuclei');
        this.templates = [...(options.templates ?? [bundled])];
        if (!this.templates.length || this.templates.length > 32 || this.templates.some(path => !isAbsolute(path) || /[\r\n,]/.test(path)))
            throw new ScannerError('invalid-input');
    }
    async prepare(input, url, directory) {
        if ((input.request.method ?? 'GET') !== 'GET' || input.request.body !== undefined)
            throw new ScannerError('invalid-input');
        for (const template of this.templates)
            await access(template);
        const targets = join(directory, 'targets.txt');
        await writeFile(targets, `${url}\n`, { mode: 0o600 });
        const config = join(directory, 'nuclei.yaml');
        await writeFile(config, '{}', { mode: 0o600 });
        return { args: ['-config', config, '-l', targets, ...this.templates.flatMap(path => ['-t', path]),
                '-pt', 'http', '-dr', '-ni', '-duc', '-nh', '-no-stdin', '-jsonl', '-silent', '-nc', '-omit-raw', '-omit-template',
                '-c', '1', '-bs', '1', '-rl', '1', '-retries', '0', '-timeout', '5', '-p', new URL(url).origin, '-pi'] };
    }
    normalize(text, url) { return nuclei(text, url); }
}

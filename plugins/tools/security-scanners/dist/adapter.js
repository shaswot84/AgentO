import { randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, open, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RuntimeScope } from '@agento/runtime';
import { ScannerError } from './contracts.js';
import { bounded, openGateway } from './gateway.js';
import { freeze } from './normalize.js';
import { runProcess } from './process.js';
export class ScannerAdapter {
    options;
    command;
    capabilities = Object.freeze(['security-scanner']);
    timeoutMs;
    maxOutputBytes;
    headPreflight = false;
    constructor(options, command) {
        this.options = options;
        this.command = command;
        this.timeoutMs = options.timeoutMs ?? 60_000;
        this.maxOutputBytes = options.maxOutputBytes ?? 2_097_152;
        if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 600_000
            || !Number.isSafeInteger(this.maxOutputBytes) || this.maxOutputBytes < 1 || this.maxOutputBytes > 16_777_216)
            throw new ScannerError('invalid-input');
    }
    registration() {
        return { metadata: { id: this.id, capabilities: ['security-scanner'], supportedCwes: 'all',
                protocols: ['http', 'https'], risk: 'active' },
            capabilities: { 'security-scanner': { run: this.run.bind(this) } }, executable: this.options.executable ?? this.command,
            checkAvailability: async (_signal) => this.options.enabled !== false };
    }
    async execute(context, plan) {
        try {
            if (this.options.enabled === false)
                return this.result(plan.id, [], 'disabled');
            if (!this.options.resolveInput)
                return this.result(plan.id, [], 'not-configured');
            if (plan.executor !== 'scanner' || plan.identityIds.some(id => !context.identities.some(identity => identity.id === id)))
                throw new ScannerError('invalid-input');
            const target = new RuntimeScope(context.project.baseUrl, context.project.allowedOrigins).assert(plan.targetUrl);
            const input = await this.options.resolveInput(context, plan);
            if (input.project.id !== context.project.id || input.planId !== plan.id || input.cweId !== plan.cweId
                || new URL(input.request.url, context.project.baseUrl).href !== target)
                throw new ScannerError('invalid-input');
            return await this.run({ ...input, project: context.project });
        }
        catch (error) {
            return this.result(plan.id, [], error instanceof ScannerError ? error.code : 'invalid-input');
        }
    }
    async run(input) {
        const evidence = [];
        let directory, gateway;
        let timedOut = false;
        const controller = new AbortController();
        const signal = AbortSignal.any([controller.signal, ...[input.signal, input.request.signal].filter((value) => !!value)]);
        const timer = setTimeout(() => { timedOut = true; controller.abort(); }, this.timeoutMs);
        try {
            if (this.options.enabled === false)
                throw new ScannerError('disabled');
            if (signal.aborted)
                throw new ScannerError('cancelled');
            if (typeof input.planId !== 'string' || !input.planId || !input.project.id || !input.executor?.execute)
                throw new ScannerError('invalid-input');
            // Snapshot all private values except live capabilities and cancellation.
            input = { ...input, project: structuredClone(input.project), request: { ...input.request, headers: { ...input.request.headers } },
                ...(input.parameter ? { parameter: { ...input.parameter } } : {}) };
            gateway = await openGateway(input, signal, this.headPreflight);
            directory = await mkdtemp(join(tmpdir(), 'agento-scanner-'));
            await mkdir(join(directory, 'home'), { mode: 0o700 });
            const invocation = await this.prepare(input, gateway.url, directory);
            const processInput = { executable: this.options.executable ?? this.command, args: invocation.args,
                cwd: directory, env: this.environment(directory, gateway.origin), timeoutMs: this.timeoutMs,
                maxOutputBytes: this.maxOutputBytes, signal: gateway.signal };
            let output;
            try {
                const pending = (this.options.runner ?? runProcess)(processInput);
                output = this.options.runner ? await bounded(pending, gateway.signal) : await pending;
            }
            catch (error) {
                gateway.assertHealthy();
                throw error;
            }
            gateway.assertComplete();
            if (signal.aborted)
                throw new ScannerError('cancelled');
            if (Buffer.byteLength(output.stdout) + Buffer.byteLength(output.stderr) > this.maxOutputBytes)
                throw new ScannerError('output-limit');
            if (!(invocation.acceptedExits ?? [0]).includes(output.exitCode))
                throw new ScannerError('tool-failed');
            let text = output.stdout;
            if (invocation.reportFile) {
                const file = await open(invocation.reportFile, 'r');
                try {
                    const stat = await file.stat();
                    if (!stat.isFile() || stat.size > this.maxOutputBytes)
                        throw new ScannerError('output-limit');
                    // Bounded read even if a custom runner leaves a growing report behind.
                    const buffer = Buffer.alloc(this.maxOutputBytes + 1);
                    const { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
                    if (bytesRead > this.maxOutputBytes)
                        throw new ScannerError('output-limit');
                    text = buffer.subarray(0, bytesRead).toString('utf8');
                }
                finally {
                    await file.close();
                }
            }
            const claims = this.normalize(text, gateway.url);
            const capturedAt = new Date().toISOString();
            for (const exchange of gateway.exchanges)
                evidence.push({ id: `scanner-http:${randomUUID()}`, projectId: input.project.id,
                    kind: 'http-response', producerId: this.id, capturedAt, summary: 'Scoped scanner HTTP exchange.',
                    facts: { observation: 'scanner-http-exchange', ...exchange } });
            for (const claim of claims)
                evidence.push({ id: `scanner-claim:${randomUUID()}`, projectId: input.project.id,
                    kind: 'scanner-output', producerId: this.id, capturedAt, summary: 'Scanner claim requires independent verification.',
                    facts: { observation: 'scanner-candidate', ruleDigest: claim.ruleDigest, cweIds: [...claim.cweIds],
                        reportedSeverity: claim.reportedSeverity, reportedConfidence: claim.reportedConfidence,
                        technique: claim.technique, dbmsFingerprint: claim.dbmsFingerprint, verified: false,
                        responseEvidenceIds: evidence.filter(item => item.kind === 'http-response').map(item => item.id) } });
            evidence.push({ id: `scanner-run:${randomUUID()}`, projectId: input.project.id, kind: 'scanner-output', producerId: this.id,
                capturedAt, summary: 'Scanner completed within the configured limits.', facts: { observation: 'scanner-run',
                    requestCount: gateway.exchanges.length, candidateCount: claims.length, verified: false } });
            return this.result(input.planId, evidence);
        }
        catch (error) {
            const code = input.signal?.aborted || input.request.signal?.aborted ? 'cancelled' : timedOut ? 'timeout'
                : error instanceof ScannerError ? error.code : 'tool-failed';
            return this.result(input.planId, [], code);
        }
        finally {
            clearTimeout(timer);
            controller.abort();
            if (gateway)
                await gateway.close();
            if (directory)
                await rm(directory, { recursive: true, force: true }).catch(() => undefined);
        }
    }
    environment(directory, proxy) {
        return { PATH: process.env.PATH ?? '', HOME: join(directory, 'home'), TMPDIR: directory,
            XDG_CONFIG_HOME: join(directory, 'home'), XDG_CACHE_HOME: join(directory, 'home'), XDG_DATA_HOME: join(directory, 'home'),
            LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', NO_COLOR: '1', HTTP_PROXY: proxy, HTTPS_PROXY: proxy,
            http_proxy: proxy, https_proxy: proxy, NO_PROXY: '', no_proxy: '',
            DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD: 'true', DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD: 'true',
            DISABLE_NUCLEI_TEMPLATES_GITLAB_DOWNLOAD: 'true', DISABLE_NUCLEI_TEMPLATES_AWS_DOWNLOAD: 'true',
            DISABLE_NUCLEI_TEMPLATES_AZURE_DOWNLOAD: 'true' };
    }
    result(planId, evidence, code) {
        const skipped = code === 'disabled' || code === 'not-configured' || code === 'not-installed';
        return freeze({ id: `scanner-result:${randomUUID()}`, planId, producerId: this.id,
            outcome: code ? skipped ? 'SKIPPED' : 'FAILED' : 'COMPLETED',
            summary: code ? 'Scanner execution did not complete.' : 'Scanner observations require independent verification.', evidence: [...evidence],
            ...(code ? { error: { code, message: 'Check scanner configuration and execution limits.' } } : {}) });
    }
}

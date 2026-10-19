import { isAbsolute, relative } from 'node:path';
import { EvidenceRedactor, verifyEvidenceBundle } from '@agento/evidence';
import { recipes } from './catalog.js';
import { RemediationError } from './contracts.js';
import { unifiedDiff } from './diff.js';
import { regressionTest } from './regression.js';
import { canonical, copy, freeze, safePath, sha256, strings } from './value.js';
/** Pure suggestion provider. Reviewed recipes are deliberately narrower than arbitrary Express code. */
export class ExpressRemediationProvider {
    id = 'express-remediation';
    capabilities = Object.freeze(['remediation:express-storefront']);
    #store;
    #sources;
    #redactor;
    #privateValues;
    #maxBytes;
    constructor(options) {
        if (!options || typeof options.evidenceStore?.get !== 'function')
            throw new RemediationError('invalid-input');
        this.#store = options.evidenceStore;
        const sources = copy(options.sources), secrets = copy(options.secrets ?? []);
        if (!Array.isArray(sources) || sources.length > 16)
            throw new RemediationError('invalid-input');
        try {
            this.#redactor = new EvidenceRedactor(secrets);
        }
        catch {
            throw new RemediationError('invalid-input');
        }
        this.#privateValues = secrets.flatMap(value => [value, encodeURIComponent(value), Buffer.from(value).toString('base64'), Buffer.from(value).toString('base64url')]);
        this.#maxBytes = options.maxPatchBytes ?? 262_144;
        if (!Number.isSafeInteger(this.#maxBytes) || this.#maxBytes < 1 || this.#maxBytes > 1_048_576)
            throw new RemediationError('invalid-input');
        const indexed = new Map();
        let bytes = 0;
        for (const source of sources) {
            if (!source || !safePath(source.path) || typeof source.content !== 'string'
                || !/^[a-f0-9]{64}$/.test(source.sha256) || indexed.has(source.path))
                throw new RemediationError('invalid-input');
            strings(source.evidenceIds);
            bytes += Buffer.byteLength(source.content);
            if (bytes > 1_048_576)
                throw new RemediationError('patch-limit');
            if (sha256(source.content) !== source.sha256)
                throw new RemediationError('source-mismatch');
            indexed.set(source.path, freeze(source));
        }
        this.#sources = indexed;
    }
    async suggest(context, finding) {
        try {
            return this.#suggest(context, finding);
        }
        catch (error) {
            if (error instanceof RemediationError)
                throw error;
            // Never include source content, private paths, or store diagnostics in errors.
            throw new RemediationError('invalid-input');
        }
    }
    #suggest(input, original) {
        const context = copy({ project: input.project, endpoints: input.endpoints, evidence: input.evidence }), finding = copy(original);
        if (!finding || finding.status !== 'CONFIRMED')
            throw new RemediationError('not-confirmed');
        if (!context.project || context.project.id !== finding.projectId || context.project.mode !== 'code-aware'
            || !Array.isArray(context.evidence) || !Array.isArray(context.endpoints))
            throw new RemediationError('invalid-input');
        strings(finding.evidenceIds);
        strings(finding.testPlanIds);
        const recipe = recipes.find(item => item.cweId === finding.cweId);
        if (!recipe)
            throw new RemediationError('unsupported-source');
        const endpoints = context.endpoints.filter(item => item.id === finding.endpointId);
        const endpoint = endpoints[0];
        const method = ['CWE-1004', 'CWE-614'].includes(finding.cweId) ? 'POST' : 'GET';
        if (endpoints.length !== 1 || !endpoint || endpoint.path !== recipe.endpoint || endpoint.method !== method)
            throw new RemediationError('unsupported-source');
        const evidence = new Map();
        for (const record of context.evidence) {
            if (!record || evidence.has(record.id))
                throw new RemediationError('unrelated-evidence');
            evidence.set(record.id, record);
        }
        const retain = (id) => {
            const observed = evidence.get(id);
            let stored;
            try {
                stored = this.#store.get(id);
            }
            catch {
                throw new RemediationError('integrity-failed');
            }
            if (!observed || !stored || stored.projectId !== finding.projectId || canonical(observed) !== canonical(stored))
                throw new RemediationError('unrelated-evidence');
            const content = { schemaVersion: 1, finding: { id: 'remediation-proof', projectId: finding.projectId,
                    cweId: finding.cweId, status: finding.status, evidenceIds: [id] }, evidence: [stored] };
            let verified;
            try {
                verified = verifyEvidenceBundle({ ...content, digest: sha256(canonical(content)) }).evidence[0];
            }
            catch {
                throw new RemediationError('integrity-failed');
            }
            if (new URL(verified.provenance.environment.baseUrl).origin !== new URL(context.project.baseUrl).origin
                || new URL(verified.provenance.environment.targetUrl).origin !== new URL(context.project.baseUrl).origin)
                throw new RemediationError('unrelated-evidence');
            return stored;
        };
        let runtime = false;
        for (const id of finding.evidenceIds) {
            const record = retain(id);
            if (record.endpointId && record.endpointId !== finding.endpointId)
                throw new RemediationError('unrelated-evidence');
            runtime ||= ['cookie-security', 'cross-origin', 'authorization', 'browser-observation', 'http-response', 'scanner-output'].includes(record.kind);
        }
        if (!runtime)
            throw new RemediationError('unrelated-evidence');
        const sourcePath = (file) => {
            if (!isAbsolute(file))
                return file;
            if (!context.project.repositoryPath)
                throw new RemediationError('unrelated-evidence');
            return relative(context.project.repositoryPath, file);
        };
        const files = [], patches = [], sourceEvidenceIds = new Set();
        for (const file of recipe.files) {
            const snapshot = this.#sources.get(file.path);
            if (!snapshot)
                throw new RemediationError('missing-source');
            if (snapshot.sha256 !== file.sha256)
                throw new RemediationError('unsupported-source');
            for (const id of snapshot.evidenceIds) {
                const record = retain(id);
                if (record.kind !== 'source-location' || !record.source || sourcePath(record.source.file) !== file.path
                    || record.facts.sourceSha256 !== snapshot.sha256)
                    throw new RemediationError('unrelated-evidence');
                sourceEvidenceIds.add(id);
            }
            let after = snapshot.content;
            for (const edit of file.edits) {
                if (!after.includes(edit.before) || after.indexOf(edit.before) !== after.lastIndexOf(edit.before))
                    throw new RemediationError('source-mismatch');
                after = after.replace(edit.before, () => edit.after);
            }
            patches.push(unifiedDiff(file.path, snapshot.content, after));
            files.push({ path: file.path, beforeSha256: snapshot.sha256, afterSha256: sha256(after) });
        }
        const patch = patches.join(''), test = regressionTest(finding.cweId);
        // Never redact patch bytes: that would silently invalidate a fix. Refuse unsafe output.
        const references = JSON.stringify({ findingId: finding.id, evidenceIds: finding.evidenceIds, sourceEvidenceIds: [...sourceEvidenceIds] });
        if (this.#redactor.text(patch) !== patch || this.#redactor.text(references) !== references
            || this.#privateValues.some(value => (patch + test + references).includes(value)))
            throw new RemediationError('unsafe-output');
        if (Buffer.byteLength(patch) + Buffer.byteLength(test) > this.#maxBytes)
            throw new RemediationError('patch-limit');
        return freeze({ findingId: finding.id, explanation: recipe.explanation, patch, regressionTest: test,
            evidenceIds: [...finding.evidenceIds].sort(), status: 'SUGGESTED', recipeId: recipe.id,
            sourceEvidenceIds: [...sourceEvidenceIds].sort(), files,
            regressionTestPath: `test/remediation-${finding.cweId.toLowerCase()}.test.ts`, validation: 'NOT_RUN' });
    }
}

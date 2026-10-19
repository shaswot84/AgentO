import { createHash, randomUUID } from 'node:crypto';
import { freeze, RuntimeError } from '../safety.js';
import { available, base, check, metadata, mutate, publicComparison, publicResponse, sanitized, snapshot, text, validateInjection } from './shared.js';
import { scan, withInjectionExecutor } from './injection.js';
export class SQLInjectionProbe {
    metadata() {
        return metadata('sql-injection', ['request-executor', 'response-collector', 'response-comparator'], ['authentication-manager', 'sql-scanner']);
    }
    supports(context) {
        return available(context, this.metadata().requiredCapabilities)
            && (!context.identity || context.capabilities.has('authentication-manager'));
    }
    execute(input) {
        return sanitized(async () => {
            const context = { ...snapshot(input), parameter: { ...input.parameter },
                ...(input.identity ? { identity: structuredClone(input.identity) } : {}) };
            check(context, this.supports(context));
            if (context.sqlBooleanContext !== undefined && !['quoted-string', 'like-pattern'].includes(context.sqlBooleanContext))
                throw new RuntimeError('invalid-request');
            if (context.responseJsonPointer !== undefined && !/^\/(?:[A-Za-z0-9_-]+)(?:\/[A-Za-z0-9_-]+)*$/.test(context.responseJsonPointer))
                throw new RuntimeError('invalid-request');
            const prepared = validateInjection(context), comparator = context.capabilities.get('response-comparator');
            return withInjectionExecutor(context, async (executor) => {
                const baseline = await executor.execute(prepared), observations = [];
                const like = context.sqlBooleanContext === 'like-pattern';
                const variants = [
                    { variant: 'syntax', technique: 'error', suffix: "'" },
                    { variant: 'boolean-true', technique: 'boolean', suffix: like ? "%' AND '1'='1' -- " : "' AND '1'='1" },
                    { variant: 'boolean-false', technique: 'boolean', suffix: like ? "%' AND '1'='2' -- " : "' AND '1'='2" },
                ];
                const responses = [];
                for (const variant of variants) {
                    const response = await executor.execute(mutate(context, prepared, original => original + variant.suffix));
                    responses.push(response);
                    const errors = indicators(text(response));
                    observations.push({ variant: variant.variant, technique: variant.technique, response: publicResponse(context, response),
                        comparison: publicComparison(comparator.compare(baseline, response)),
                        errorIndicators: errors.map(error => error.label), dbmsFingerprint: errors.find(error => error.dbms)?.dbms ?? null });
                }
                const diagnostics = [];
                if ([baseline, ...responses].some(response => response.body.truncated))
                    diagnostics.push('response-truncated');
                let scanner = null;
                if (context.capabilities.has('sql-scanner')) {
                    const result = await scan({ ...context, request: prepared }, executor, `agento-${randomUUID()}`, value => context.capabilities.get('sql-scanner').scan(value));
                    if (result.diagnostic === 'scanner-failed' || result.diagnostic === 'scanner-skipped')
                        diagnostics.push(result.diagnostic);
                    if (!['error', 'boolean', 'time'].includes(result.technique)
                        || ![null, 'SQLite', 'PostgreSQL', 'MySQL', 'SQLServer', 'Oracle'].includes(result.dbmsFingerprint)
                        || ![true, false, null].includes(result.observedDifference))
                        throw new RuntimeError('invalid-request');
                    scanner = { technique: result.technique, dbmsFingerprint: result.dbmsFingerprint, observedDifference: result.observedDifference };
                }
                else
                    diagnostics.push('scanner-unavailable');
                const projectedControls = context.responseJsonPointer ? projection(context.responseJsonPointer, baseline, responses[1], responses[2]) : undefined;
                return freeze({ ...base(context, this.metadata().id, diagnostics),
                    ...(projectedControls ? { projectedControls } : {}), parameter: { ...context.parameter },
                    baseline: publicResponse(context, baseline), observations,
                    booleanComparison: publicComparison(comparator.compare(responses[1], responses[2])), scanner });
            });
        });
    }
}
function indicators(body) {
    const patterns = [
        ['sqlite-error', /SQLITE_ERROR|SqliteError|SQLite.*(?:error|exception)/i, 'SQLite'],
        ['postgres-error', /PostgreSQL.*ERROR|unterminated quoted string at or near/i, 'PostgreSQL'],
        ['mysql-error', /You have an error in your SQL syntax|mysql_fetch|mysqli_sql_exception/i, 'MySQL'],
        ['sqlserver-error', /Microsoft.*(?:SQL Server|ODBC SQL)|Unclosed quotation mark after the character string/i, 'SQLServer'],
        ['oracle-error', /ORA-\d{5}/, 'Oracle'],
        ['sql-syntax-error', /syntax error|unrecognized token|unterminated.*(?:quote|string)/i, null],
    ];
    return patterns.filter(([, pattern]) => pattern.test(body)).map(([label, , dbms]) => ({ label, dbms }));
}
function projection(pointer, ...responses) {
    const hashes = responses.map(response => {
        if (response.body.truncated || response.status < 200 || response.status >= 300
            || !(response.headers['content-type'] ?? []).some(type => /application\/(?:[a-z.+-]*\+)?json\b/i.test(type)))
            return null;
        try {
            let value = JSON.parse(text(response));
            for (const segment of pointer.slice(1).split('/')) {
                if (!value || typeof value !== 'object' || !Object.hasOwn(value, segment))
                    return null;
                value = value[segment];
            }
            // Require structured result data; scalar reflections are not a database result set.
            if (!value || typeof value !== 'object')
                return null;
            return createHash('sha256').update(JSON.stringify(value)).digest('hex');
        }
        catch {
            return null;
        }
    });
    return hashes.every(hash => hash !== null) ? { pointer, baseline: hashes[0], trueControl: hashes[1], falseControl: hashes[2] } : undefined;
}

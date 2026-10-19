import { randomUUID } from 'node:crypto';
import { freeze, RuntimeError } from '../safety.js';
import type { DatabaseFingerprint, InjectionContext, SecurityProbe, SQLInjectionEvidence } from './contracts.js';
import { available, base, check, metadata, mutate, publicComparison, publicResponse, sanitized, snapshot, text, validateInjection } from './shared.js';
import { scan, withInjectionExecutor } from './injection.js';

export class SQLInjectionProbe implements SecurityProbe<InjectionContext, SQLInjectionEvidence> {
  metadata() { return metadata('sql-injection', ['request-executor', 'response-collector', 'response-comparator'],
    ['authentication-manager', 'sql-scanner']); }
  supports(context: InjectionContext): boolean {
    return available(context, this.metadata().requiredCapabilities)
      && (!context.identity || context.capabilities.has('authentication-manager'));
  }
  execute(input: InjectionContext): Promise<SQLInjectionEvidence> {
    return sanitized(async () => {
      const context = { ...snapshot(input), parameter: { ...input.parameter },
        ...(input.identity ? { identity: structuredClone(input.identity) } : {}) };
      check(context, this.supports(context));
      const prepared = validateInjection(context), comparator = context.capabilities.get('response-comparator');
      return withInjectionExecutor(context, async executor => {
        const baseline = await executor.execute(prepared), observations: SQLInjectionEvidence['observations'][number][] = [];
        const variants = [
          { variant: 'syntax', technique: 'error', suffix: "'" },
          { variant: 'boolean-true', technique: 'boolean', suffix: "' AND '1'='1" },
          { variant: 'boolean-false', technique: 'boolean', suffix: "' AND '1'='2" },
        ] as const;
        const responses = [];
        for (const variant of variants) {
          const response = await executor.execute(mutate(context, prepared, original => original + variant.suffix));
          responses.push(response);
          const errors = indicators(text(response));
          observations.push({ variant: variant.variant, technique: variant.technique, response: publicResponse(context, response),
            comparison: publicComparison(comparator.compare(baseline, response)),
            errorIndicators: errors.map(error => error.label), dbmsFingerprint: errors.find(error => error.dbms)?.dbms ?? null });
        }
        const diagnostics: SQLInjectionEvidence['diagnostics'][number][] = [];
        if ([baseline, ...responses].some(response => response.body.truncated)) diagnostics.push('response-truncated');
        let scanner: SQLInjectionEvidence['scanner'] = null;
        if (context.capabilities.has('sql-scanner')) {
          const result = await scan({ ...context, request: prepared }, executor, `agento-${randomUUID()}`,
            value => context.capabilities.get('sql-scanner').scan(value));
          if (result.diagnostic === 'scanner-failed' || result.diagnostic === 'scanner-skipped') diagnostics.push(result.diagnostic);
          if (!['error', 'boolean', 'time'].includes(result.technique)
            || ![null, 'SQLite', 'PostgreSQL', 'MySQL', 'SQLServer', 'Oracle'].includes(result.dbmsFingerprint)
            || ![true, false, null].includes(result.observedDifference)) throw new RuntimeError('invalid-request');
          scanner = { technique: result.technique, dbmsFingerprint: result.dbmsFingerprint, observedDifference: result.observedDifference };
        } else diagnostics.push('scanner-unavailable');
        return freeze({ ...base(context, this.metadata().id, diagnostics), parameter: { ...context.parameter },
          baseline: publicResponse(context, baseline), observations,
          booleanComparison: publicComparison(comparator.compare(responses[1]!, responses[2]!)), scanner });
      });
    });
  }
}
function indicators(body: string): { label: string; dbms: DatabaseFingerprint | null }[] {
  const patterns: readonly [string, RegExp, DatabaseFingerprint | null][] = [
    ['sqlite-error', /SQLITE_ERROR|SqliteError|SQLite.*(?:error|exception)/i, 'SQLite'],
    ['postgres-error', /PostgreSQL.*ERROR|unterminated quoted string at or near/i, 'PostgreSQL'],
    ['mysql-error', /You have an error in your SQL syntax|mysql_fetch|mysqli_sql_exception/i, 'MySQL'],
    ['sqlserver-error', /Microsoft.*(?:SQL Server|ODBC SQL)|Unclosed quotation mark after the character string/i, 'SQLServer'],
    ['oracle-error', /ORA-\d{5}/, 'Oracle'],
    ['sql-syntax-error', /syntax error|unrecognized token|unterminated.*(?:quote|string)/i, null],
  ];
  return patterns.filter(([, pattern]) => pattern.test(body)).map(([label, , dbms]) => ({ label, dbms }));
}

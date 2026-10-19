import { EvidenceCWEPlugin } from './base.js';
import { complete, confirmed, rejected, sameExchangeTarget, sameTarget, successful, unknown } from './shared.js';
export class CWE89Plugin extends EvidenceCWEPlugin {
    constructor(options = {}) {
        super({ cweId: 'CWE-89', title: 'SQL injection',
            owaspCategory: 'A05:2025', severity: 'high', probeId: 'sql-injection',
            requiredCapabilities: ['request-executor', 'response-collector', 'response-comparator'],
            optionalCapabilities: ['authentication-manager', 'sql-scanner'] }, options);
    }
    isCandidate(candidate) {
        return candidate.hasSignal || candidate.facts.some(fact => fact.kind === 'database-operation'
            || fact.kind === 'data-flow' && (fact.details.cweId === this.cweId
                || Array.isArray(fact.details.cweIds) && fact.details.cweIds.includes(this.cweId)));
    }
    interpret(evidence, scope) {
        const location = evidence.parameter.location === 'query' ? 'query' : 'body';
        if (!scope.parameter || evidence.parameter.name !== scope.parameter.name || location !== scope.parameter.location
            || !sameTarget(evidence.baseline, scope) || !successful(evidence.baseline) || !complete(evidence.baseline)
            || evidence.observations.some(item => !sameTarget(item.response, scope) || !sameExchangeTarget(evidence.baseline, item.response))) {
            return unknown('A successful SQL baseline and parameter-bound observations are required.');
        }
        const variants = new Map(evidence.observations.map(item => [item.variant, item]));
        if (variants.size !== evidence.observations.length)
            return unknown('Duplicate SQL variants make the evidence ambiguous.');
        const syntax = variants.get('syntax'), yes = variants.get('boolean-true'), no = variants.get('boolean-false');
        const labels = { SQLite: 'sqlite-error', PostgreSQL: 'postgres-error', MySQL: 'mysql-error', SQLServer: 'sqlserver-error', Oracle: 'oracle-error' };
        if (syntax && syntax.technique === 'error' && syntax.response.status >= 500 && complete(syntax.response)
            && syntax.dbmsFingerprint && syntax.errorIndicators.includes(labels[syntax.dbmsFingerprint])) {
            return confirmed('A syntax mutation produced a database-specific error after a successful baseline.');
        }
        if (yes && no && [yes, no].every(item => item.technique === 'boolean' && successful(item.response) && complete(item.response))
            && yes.comparison.bodyEqual === true && no.comparison.bodyEqual === false && evidence.booleanComparison.bodyEqual === false
            && yes.response.body.sha256 === evidence.baseline.body.sha256 && no.response.body.sha256 !== yes.response.body.sha256) {
            return confirmed('The true control preserves the baseline while the false control changes the response.');
        }
        const projected = evidence.projectedControls;
        if (projected && yes && no && [yes, no].every(item => item.technique === 'boolean' && successful(item.response) && complete(item.response))
            && projected.baseline === projected.trueControl && projected.falseControl !== projected.trueControl) {
            return confirmed('The declared JSON result field matches the baseline for the true control and differs for the false control.');
        }
        if (projected && evidence.outcome === 'COMPLETED' && syntax && yes && no
            && evidence.observations.every(item => successful(item.response) && complete(item.response) && item.errorIndicators.length === 0)
            && projected.baseline === projected.trueControl && projected.baseline === projected.falseControl) {
            return rejected('Completed checks did not change the declared JSON result field or produce database errors.');
        }
        if (evidence.outcome === 'COMPLETED' && syntax && yes && no && evidence.observations.every(item => successful(item.response) && complete(item.response) && item.errorIndicators.length === 0
            && item.comparison.bodyEqual === true && item.response.body.sha256 === evidence.baseline.body.sha256)
            && evidence.scanner?.observedDifference === false)
            return rejected('Completed SQL checks reproduced the baseline without database error or differential behavior.');
        return unknown('Database-specific error or controlled boolean proof was not established.', 'Generic errors, timing differences and scanner difference flags alone are insufficient.');
    }
}

import { ReportingError } from './contracts.js';
import { checkedRecord, copy, digest } from './value.js';
/** Only renders reports produced by buildSecurityReport (or their unchanged JSON copies). */
function snapshot(report) {
    const value = copy(report);
    const { digest: supplied, ...content } = value;
    if (value.schemaVersion !== 1 || !/^[a-f0-9]{64}$/.test(supplied) || digest(content) !== supplied
        || !Array.isArray(value.findings) || !Array.isArray(value.evidence))
        throw new ReportingError('integrity-failed');
    for (const record of value.evidence)
        checkedRecord(record);
    return value;
}
/** Escape all input text; links and anchors are generated only from evidence IDs. */
function md(value) {
    return value.replace(/[\r\n\u2028\u2029]+/g, ' ').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/([\\`*{}_\[\]()#!|~])/g, '\\$1');
}
const anchor = (id) => `evidence-${digest(id)}`;
const refs = (ids) => ids.length ? ids.map(id => `[${md(id)}](#${anchor(id)})`).join(', ') : 'No retained evidence.';
function claim(value) {
    return value ? `${md(value.text)} Evidence: ${refs(value.evidenceIds)}` : 'Not established by cited evidence.';
}
function block(value, language = '') {
    let width = 3;
    for (const match of value.matchAll(/`+/g))
        width = Math.max(width, match[0].length + 1);
    const fence = '`'.repeat(width);
    return `${fence}${language}\n${value}\n${fence}`;
}
export function reportToJSON(report) {
    return `${JSON.stringify(snapshot(report), null, 2)}\n`;
}
export function reportToMarkdown(report) {
    const value = snapshot(report);
    const lines = [
        `# Security report: ${md(value.project.name)}`, '',
        `Project: ${md(value.project.id)} · Target: ${md(value.project.baseUrl)}`, '',
        `Generated: ${md(value.generatedAt)} · Report SHA-256: ${value.digest}`, '',
        '## Assessment summary', '',
        '| State | Count |', '| --- | ---: |',
        ...Object.entries(value.summary.byStatus).map(([state, count]) => `| ${md(state)} | ${count} |`), '',
        'Severity counts include confirmed findings only.', '',
        '| Severity | Confirmed |', '| --- | ---: |',
        ...Object.entries(value.summary.confirmedBySeverity).map(([severity, count]) => `| ${md(severity)} | ${count} |`), '',
    ];
    if (!value.findings.length)
        lines.push('No findings were supplied. This report makes no claim that the application is secure.', '');
    for (const finding of value.findings) {
        lines.push(`## ${md(finding.title)}`, '', `ID: ${md(finding.id)} · Hypothesis: ${md(finding.hypothesisId)}`, '', `**${md(finding.status)}** · ${md(finding.owaspCategory)} · ${md(finding.cweId)} · Severity: ${md(finding.severity ?? 'not assessed')} · Confidence: ${md(finding.confidence ?? 'not assessed')}`, '', `Assessment: ${claim(finding.assessment)}`, '', finding.endpoint ? `Endpoint: ${md(finding.endpoint.method)} ${md(finding.endpoint.path)}. Evidence: ${refs(finding.endpoint.evidenceIds)}` : 'Endpoint: no cited location.', '', finding.source ? `Source: ${md(finding.source.location.file)}:${finding.source.location.startLine}${finding.source.location.endLine === undefined ? '' : `–${finding.source.location.endLine}`}. Evidence: ${refs(finding.source.evidenceIds)}` : 'Source: no cited location.', '', '### Root cause', '', claim(finding.rootCause), '', '### Proof', '', `Static evidence: ${refs(finding.staticEvidenceIds)}`, '', `Runtime evidence: ${refs(finding.runtimeEvidenceIds)}`, '', ...(finding.otherEvidenceIds.length ? [`Other evidence: ${refs(finding.otherEvidenceIds)}`, ''] : []), ...(finding.contextEvidenceIds.length ? [`Source context: ${refs(finding.contextEvidenceIds)}`, ''] : []), `Assessment source: ${md(finding.verification.source)}.`, '');
        if (finding.verification.diagnostics.length)
            lines.push(`Verification diagnostics: ${finding.verification.diagnostics.map(md).join(', ')}.`, '');
        if (finding.diagnostics.length)
            lines.push(`Report diagnostics: ${finding.diagnostics.map(md).join(', ')}.`, '');
        lines.push('### Reproduction and test plans', '');
        if (!finding.testPlans.length)
            lines.push('No generated test plan was supplied.', '');
        for (const plan of finding.testPlans) {
            lines.push(`Plan: ${md(plan.id)} · ${md(plan.executor)} · ${md(plan.risk)}`, '', `Target: ${md(plan.targetUrl)}`, '', `Identities: ${plan.identityIds.map(md).join(', ') || 'anonymous'}`, '', `Required capabilities: ${plan.requiredCapabilities.map(md).join(', ') || 'none'}`, '', `Basis: ${refs(plan.evidenceIds)}`, '', ...plan.steps.map((step, position) => `${position + 1}. ${md(step.action)} — ${md(step.expectedObservation)}`), '');
        }
        if (finding.executions.length)
            lines.push('| Test result | Plan | Outcome | Evidence |', '| --- | --- | --- | --- |', ...finding.executions.map(result => `| ${md(result.id)} | ${md(result.planId)} | ${md(result.outcome)} | ${refs(result.evidenceIds)} |`), '');
        lines.push('Private request values must be supplied by the authorized host. Retained proof below contains redacted requests, response metadata, and normalized observations where available.', '', '### Suggested remediation', '');
        if (finding.remediation.status === 'NOT_PROVIDED')
            lines.push('No remediation was supplied.', '');
        else {
            lines.push(claim(finding.remediation.explanation), '');
            for (const [label, item] of [['Suggested patch', finding.remediation.patch], ['Regression test specification', finding.remediation.regressionTest]]) {
                if (item)
                    lines.push(`${label}. Evidence: ${refs(item.evidenceIds)}`, '', block(item.text), '');
            }
        }
        lines.push(`Retest status: ${md(finding.retest.status)}.`, '');
    }
    lines.push('## Immutable evidence', '', 'Each record retains its original digest and provenance. Evidence IDs in the report link to these records.', '');
    for (const record of value.evidence) {
        lines.push(`<a id="${anchor(record.id)}"></a>`, '', `### ${md(record.id)}`, '', `${md(record.kind)} · ${md(record.capturedAt)} · Producer: ${md(record.producerId)}`, '', `${md(record.summary)}`, '', `Record SHA-256: ${record.digest}`, '', block(JSON.stringify(record, null, 2), 'json'), '');
    }
    lines.push('## Limits', '', ...value.limitations.map(item => `- ${md(item)}`), '');
    return lines.join('\n');
}

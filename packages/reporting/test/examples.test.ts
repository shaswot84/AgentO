import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { reportToJSON, reportToMarkdown } from '../src/index.js';

it('ships matching portable JSON and Markdown examples labelled as synthetic hypotheses', () => {
  const json = readFileSync(new URL('../examples/report.json', import.meta.url), 'utf8');
  const markdown = readFileSync(new URL('../examples/report.md', import.meta.url), 'utf8');
  const report = JSON.parse(json);
  expect(report.project.name).toContain('not a live scan');
  expect(report.findings.every((item: { status: string }) => item.status === 'HYPOTHESIS')).toBe(true);
  expect(report.evidence.every((item: { provenance: { environment: { id: string } } }) => item.provenance.environment.id === 'synthetic')).toBe(true);
  expect(reportToJSON(report)).toBe(json);
  expect(reportToMarkdown(report)).toBe(markdown);
});

import { isAbsolute, relative, resolve, sep } from 'node:path';
import type { CWEId, Evidence, JsonValue, Project, SecuritySignal, SourceLocation } from '@agento/core';
import type ts from 'typescript-parser';
import { SourceContext } from './context.js';
import type { Inventory } from './repository.js';
import type { SemgrepAdapterOptions, SemgrepDiagnostic } from './types.js';

const rules: Readonly<Record<string, { cweId: CWEId; summary: string }>> = {
  'agento.express.request-to-html': { cweId: 'CWE-79', summary: 'Static candidate: request input may reach an HTML response.' },
  'agento.express.request-to-sql': { cweId: 'CWE-89', summary: 'Static candidate: request input may reach SQL statement text.' },
};
export const record = (value: unknown): Record<string, unknown> | undefined =>
  value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
const integer = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) > 0;

export function localFile(value: unknown, snapshot: string): string | undefined {
  if (typeof value !== 'string' || /[\x00-\x1f]/.test(value)) return;
  const file = (isAbsolute(value) ? relative(snapshot, value) : value).replaceAll(sep, '/').replace(/^\.\//, '');
  if (!file || file.startsWith('/') || file.split('/').some(part => part === '..' || part === '.' || !part)) return;
  if (!resolve(snapshot, file).startsWith(`${snapshot}${sep}`)) return;
  return file;
}

/** Semgrep columns count UTF-8 bytes; the TypeScript parser counts UTF-16 code units. */
function position(value: unknown, file: ts.SourceFile): { line: number; offset: number } | undefined {
  const point = record(value);
  if (!point || !integer(point.line) || !integer(point.col)) return;
  const starts = file.getLineStarts();
  const begin = starts[point.line - 1];
  if (begin === undefined) return;
  const line = Buffer.from(file.text.slice(begin, starts[point.line] ?? file.text.length));
  if (point.col - 1 > line.length) return;
  const prefix = line.subarray(0, point.col - 1);
  const text = prefix.toString('utf8');
  if (Buffer.byteLength(text) !== prefix.length) return;
  return { line: point.line, offset: begin + text.length };
}

export function normalizeMatches(raw: Record<string, unknown>, inventory: Inventory, snapshot: string, project: Project,
  options: SemgrepAdapterOptions, capturedAt: string, identifier: (...parts: string[]) => string): {
    signals: SecuritySignal[]; evidence: Evidence[]; diagnostics: SemgrepDiagnostic[];
  } {
  const signals: SecuritySignal[] = [], evidence: Evidence[] = [], diagnostics: SemgrepDiagnostic[] = [];
  const seen = new Set<string>();
  const context = new SourceContext(inventory);
  const matches = raw.results as unknown[];
  for (const value of matches.slice(0, 10_000)) {
    const match = record(value);
    const ruleId = match?.check_id;
    if (!match || typeof ruleId !== 'string' || !Object.hasOwn(rules, ruleId)) {
      diagnostics.push({ code: 'unknown-rule', message: 'A match did not belong to a bundled candidate rule.' }); continue;
    }
    const name = localFile(match.path, snapshot);
    const file = name && inventory.files.get(name);
    const start = file && position(match.start, file), end = file && position(match.end, file);
    if (!file || !start || !end || end.offset <= start.offset) {
      diagnostics.push({ code: 'invalid-match', message: 'A match had an invalid source location or referenced unscanned source.' }); continue;
    }
    const source: SourceLocation = { file: file.fileName, startLine: start.line, endLine: end.line };
    const id = identifier(project.id, ruleId, file.fileName, String(start.offset), String(end.offset));
    if (seen.has(id)) continue;
    seen.add(id);
    const descriptor = rules[ruleId]!;
    // Framework context is already normalized. Associate only same-project handler ranges.
    const endpoints = (options.frameworkAnalysis?.endpoints ?? []).filter(endpoint =>
      options.frameworkAnalysis?.components.some(component => component.id === endpoint.componentId && component.projectId === project.id)
      && endpoint.handler?.file === source.file && endpoint.handler.startLine <= source.startLine
      && (endpoint.handler.endLine ?? endpoint.handler.startLine) >= (source.endLine ?? source.startLine));
    const endpointId = endpoints.length === 1 ? endpoints[0]!.id : undefined;
    const evidenceId = identifier(id, 'evidence');
    const facts: Record<string, JsonValue> = {
      observation: 'static-candidate', ruleId, cweIds: [descriptor.cweId], runtimeVerified: false,
      requiresRuntimeVerification: true, ...context.describe(file, start.offset, end.offset),
      endpointIds: endpoints.map(endpoint => endpoint.id),
    };
    evidence.push({ id: evidenceId, projectId: project.id, producerId: 'semgrep-adapter', capturedAt,
      kind: 'static-analysis', source, summary: descriptor.summary, facts, ...(endpointId ? { endpointId } : {}) });
    signals.push({ id, projectId: project.id, producerId: 'semgrep-adapter', cweIds: [descriptor.cweId],
      summary: descriptor.summary, source, evidenceIds: [evidenceId], ...(endpointId ? { endpointId } : {}) });
  }
  if (matches.length > 10_000) diagnostics.push({ code: 'limit-reached', message: 'Static match limit reached.' });
  return { signals, evidence, diagnostics };
}

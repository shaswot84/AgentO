import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { vi } from 'vitest';
import type { AnalysisContext, SecurityTestPlan } from '@agento/core';
import { NormalizedResponseCollector } from '@agento/runtime';
import type { HttpRequest, SecurityScannerRequest } from '@agento/runtime';
import type { ProcessInput, ProcessOutput, ProcessRunner } from '../src/index.js';

export const origin = 'https://target.test';
export const collector = new NormalizedResponseCollector();
export const project: AnalysisContext['project'] = { id: 'project', name: 'Target', mode: 'black-box', baseUrl: origin,
  allowedOrigins: [origin], languages: [] };
export const context: AnalysisContext = { project, endpoints: [], components: [], identities: [], resources: [], signals: [], evidence: [] };
export const plan: SecurityTestPlan = { id: 'plan', hypothesisId: 'hypothesis', cweId: 'CWE-89', executor: 'scanner',
  requiredCapabilities: ['security-scanner'], risk: 'active', targetUrl: `${origin}/search?q=PRIVATE_QUERY&keep=1`, identityIds: [], steps: [] };
export function response(request: HttpRequest) {
  return collector.collect({ url: request.url, method: request.method ?? 'GET' }, {
    status: 200, headers: { 'content-type': ['text/html'], 'set-cookie': ['sid=PRIVATE_SESSION; HttpOnly'] },
    body: Buffer.from('PRIVATE_BODY'), truncated: false, firstByteMs: 1,
  }, { startedAt: '2026-10-19T00:00:00Z', firstByteMs: 1, durationMs: 2 });
}
export function input(overrides: Partial<SecurityScannerRequest> = {}): SecurityScannerRequest {
  return { project, planId: plan.id, cweId: 'CWE-89', request: { url: plan.targetUrl,
    headers: { authorization: 'Bearer PRIVATE_TOKEN' } }, maxRequests: 16,
    executor: { execute: vi.fn(async request => response(request)) }, ...overrides };
}
export async function invocation(process: ProcessInput) {
  let url: string, method = 'GET', body: string | undefined;
  if (process.args.includes('-autorun')) {
    const file = process.args[process.args.indexOf('-autorun') + 1]!;
    const automation = JSON.parse(await readFile(file, 'utf8'));
    const request = automation.jobs.find((item: { type: string }) => item.type === 'requestor').requests[0];
    url = request.url; method = request.method; body = request.data;
  } else if (process.args.includes('-r')) {
    const text = await readFile(process.args[process.args.indexOf('-r') + 1]!, 'utf8');
    const host = text.match(/Host: ([^\r\n]+)/)![1];
    const first = text.split('\r\n')[0]!.split(' ');
    method = first[0]!; url = `http://${host}${first[1]}`;
    const data = text.split('\r\n\r\n')[1]; if (data) body = data;
  } else {
    const file = process.args.includes('-l') ? process.args[process.args.indexOf('-l') + 1]! : process.args[3]!;
    url = (await readFile(file, 'utf8')).trim();
  }
  return { url, method, ...(body !== undefined ? { body } : {}) };
}
export function raw(process: ProcessInput, url: string): ProcessOutput {
  if (process.args.includes('-autorun')) return { stdout: '', stderr: '', exitCode: 0 };
  if (process.args.includes('-r')) return { stdout: `[INFO] testing connection to the target URL\nsqlmap identified the following injection point(s) with a total of 4 HTTP(s) requests:\n---\nParameter: q (GET)\n    Type: boolean-based blind\n    Title: PRIVATE_PAYLOAD\n    Payload: q=PRIVATE_PAYLOAD\n---\nback-end DBMS: SQLite\n`, stderr: 'PRIVATE_STDERR', exitCode: 0 };
  if (process.args[0] === 'scan') return { stdout: JSON.stringify({ meta: { incomplete: false },
    findings: [{ type: 'V', data: url, poc: 'PRIVATE_PAYLOAD', evidence: 'PRIVATE_BODY' }] }), stderr: '', exitCode: 1 };
  return { stdout: JSON.stringify({ 'template-id': 'PRIVATE_RULE', type: 'http', 'matched-at': url,
    info: { severity: 'high', classification: { 'cwe-id': ['CWE-89'] }, description: 'PRIVATE_DESCRIPTION' },
    request: 'PRIVATE_REQUEST', response: 'PRIVATE_BODY', 'extracted-results': ['PRIVATE_SESSION'] }), stderr: '', exitCode: 0 };
}
export function runner(transform?: (process: ProcessInput, url: string) => Promise<ProcessOutput>): ProcessRunner {
  return async process => {
    const request = await invocation(process);
    await fetch(request.url, { method: request.method, ...(request.body !== undefined ? { body: request.body } : {}), signal: process.signal });
    if (transform) return transform(process, request.url);
    if (process.args.includes('-autorun')) await writeFile(join(process.cwd, 'zap-report.json'), JSON.stringify({ site: [{ alerts: [{
      pluginid: '10011', cweid: '1004', riskcode: '1', confidence: '2', desc: 'PRIVATE_DESCRIPTION',
      instances: [{ uri: request.url, evidence: 'PRIVATE_SESSION' }],
    }] }] }));
    return raw(process, request.url);
  };
}

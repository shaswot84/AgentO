import { access, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { DalfoxAdapter, NucleiAdapter, ScannerError, SqlmapAdapter, ZapAdapter } from '../src/index.js';
import { context, input, invocation, plan, raw, runner } from './helpers.js';

const engines = [NucleiAdapter, ZapAdapter, DalfoxAdapter, SqlmapAdapter] as const;
const requestFor = (engine: typeof engines[number]) => input(engine === DalfoxAdapter
  ? { cweId: 'CWE-79', parameter: { name: 'q', location: 'query' } }
  : engine === SqlmapAdapter ? { parameter: { name: 'q', location: 'query' } } : {});

describe('canonical scanner results', () => {
  it.each(engines.map(Engine => ({ name: Engine.name, Engine })))('$name normalizes native output, binds proof and removes private data', async ({ Engine }) => {
    const result = await new Engine({ runner: runner() }).run(requestFor(Engine));
    expect(result.outcome).toBe('COMPLETED'); expect(result.planId).toBe('plan');
    expect(result.evidence.filter(item => item.facts.observation === 'scanner-candidate')).toHaveLength(1);
    expect(result.evidence.find(item => item.kind === 'http-response')?.facts).toMatchObject({ status: 200, method: 'GET' });
    const claim = result.evidence.find(item => item.facts.observation === 'scanner-candidate')!;
    expect(claim.facts).toMatchObject({ verified: false, ruleDigest: expect.stringMatching(/^[a-f0-9]{64}$/) });
    expect(claim.facts.responseEvidenceIds).toEqual(result.evidence.filter(item => item.kind === 'http-response').map(item => item.id));
    expect(JSON.stringify(result)).not.toMatch(/PRIVATE_|127\.0\.0\.1|target\.test|Payload|password/);
    expect(Object.isFrozen(result.evidence)).toBe(true); expect(Object.isFrozen(claim.facts)).toBe(true);
  });
  it.each(engines.map(Engine => ({ name: Engine.name, Engine })))('$name isolates a nonzero exit and a later call can succeed', async ({ Engine }) => {
    let fail = true;
    const adapter = new Engine({ runner: runner(async (process, url) => fail ? { stdout: 'PRIVATE', stderr: 'PRIVATE', exitCode: 3 } : raw(process, url)) });
    expect((await adapter.run(requestFor(Engine))).error?.code).toBe('tool-failed');
    fail = false;
    // ZAP requires its private report; use a fresh normally configured adapter for recovery.
    expect((await new Engine({ runner: runner() }).run(requestFor(Engine))).outcome).toBe('COMPLETED');
  });
  it.each(engines.map(Engine => ({ name: Engine.name, Engine })))('$name reports disabled tools without starting a process', async ({ Engine }) => {
    const execute = vi.fn(runner());
    expect(await new Engine({ enabled: false, runner: execute }).run(requestFor(Engine))).toMatchObject({ outcome: 'SKIPPED', error: { code: 'disabled' } });
    expect(execute).not.toHaveBeenCalled();
  });
  it('contains malformed, oversized and unmatched output', async () => {
    for (const [stdout, code] of [['not json PRIVATE', 'invalid-output'], ['x'.repeat(513), 'output-limit'],
      [JSON.stringify({ 'template-id': 'foreign', info: {}, type: 'http', 'matched-at': 'https://other.test/' }), 'invalid-output']] as const) {
      const result = await new NucleiAdapter({ maxOutputBytes: 512, runner: runner(async () => ({ stdout, stderr: '', exitCode: 0 })) }).run(input());
      expect(result).toMatchObject({ outcome: 'FAILED', evidence: [], error: { code } });
    }
  });
  it('distinguishes an empty successful scan from a process that never inspected the target', async () => {
    const result = await new NucleiAdapter({ runner: runner(async () => ({ stdout: '', stderr: '', exitCode: 0 })) }).run(input());
    expect(result.outcome).toBe('COMPLETED'); expect(result.evidence.at(-1)?.facts.candidateCount).toBe(0);
    expect(await new NucleiAdapter({ runner: async () => ({ stdout: '', stderr: '', exitCode: 0 }) }).run(input()))
      .toMatchObject({ outcome: 'FAILED', error: { code: 'incomplete-output' } });
  });
  it('requires private core bindings and preserves the target and plan identity', async () => {
    expect(await new NucleiAdapter().execute(context, plan)).toMatchObject({ outcome: 'SKIPPED', error: { code: 'not-configured' } });
    const adapter = new NucleiAdapter({ runner: runner(), resolveInput: async () => input() });
    expect((await adapter.execute(context, plan)).outcome).toBe('COMPLETED');
    expect((await adapter.execute(context, { ...plan, targetUrl: 'https://other.test' })).outcome).toBe('FAILED');
    expect((await adapter.execute(context, { ...plan, id: 'other-plan' })).outcome).toBe('FAILED');
  });
  it('does not give native tools ambient secrets or private headers on the command line', async () => {
    let directory = '';
    const adapter = new NucleiAdapter({ runner: runner(async (process, url) => {
      directory = process.cwd;
      expect(Object.keys(process.env)).not.toContain('OPENAI_API_KEY');
      expect(Object.keys(process.env)).not.toContain('AWS_SECRET_ACCESS_KEY');
      expect(JSON.stringify(process.args)).not.toMatch(/PRIVATE_|target.test/);
      expect((await stat(process.cwd)).mode & 0o777).toBe(0o700);
      const targets = process.args[process.args.indexOf('-l') + 1]!;
      expect((await stat(targets)).mode & 0o777).toBe(0o600);
      expect(await readFile(targets, 'utf8')).toContain('PRIVATE_QUERY');
      return raw(process, url);
    }) });
    expect((await adapter.run(input())).outcome).toBe('COMPLETED');
    await expect(access(directory)).rejects.toThrow();
  });
  it('keeps temp files and evidence separate for concurrent runs', async () => {
    const directories = new Set<string>();
    const adapter = new NucleiAdapter({ runner: runner(async (process, url) => { directories.add(process.cwd); return raw(process, url); }) });
    const results = await Promise.all([adapter.run(input()), adapter.run(input())]);
    expect(results.every(result => result.outcome === 'COMPLETED')).toBe(true);
    expect(directories.size).toBe(2); expect(results[0]!.id).not.toBe(results[1]!.id);
    for (const directory of directories) await expect(access(directory)).rejects.toThrow();
  });
  it('limits input and tool configuration before effects', async () => {
    expect(() => new NucleiAdapter({ templates: ['https://remote.test/template'] })).toThrow('invalid-input');
    expect(() => new NucleiAdapter({ timeoutMs: 0 })).toThrow('invalid-input');
    expect((await new NucleiAdapter({ runner: runner() }).run(input({ request: { url: plan.targetUrl, method: 'POST' } }))).outcome).toBe('FAILED');
    expect((await new DalfoxAdapter({ runner: runner() }).run(input({ parameter: { name: 'q', location: 'form-body' } }))).outcome).toBe('FAILED');
  });
  it('replaces raw process errors with a fixed code', async () => {
    const result = await new NucleiAdapter({ runner: async () => { throw new Error('PRIVATE_PATH PRIVATE_TOKEN'); } }).run(input());
    expect(result.error?.code).toBe('tool-failed'); expect(JSON.stringify(result)).not.toContain('PRIVATE');
    expect((await new NucleiAdapter({ runner: async () => { throw new ScannerError('not-installed'); } }).run(input())).outcome).toBe('SKIPPED');
  });
});

describe('existing injection ports', () => {
  it('does not promote a Dalfox verification label to browser proof', async () => {
    const adapter = new DalfoxAdapter({ runner: runner() });
    expect(await adapter.scan({ ...input(), parameter: { name: 'q', location: 'query' }, canary: 'canary' }))
      .toEqual({ executionConfirmed: null, domSinkReached: null });
  });
  it('retains sqlmap technique claims without asserting a controlled response difference', async () => {
    const adapter = new SqlmapAdapter({ runner: runner() });
    expect(await adapter.scan({ ...input(), parameter: { name: 'q', location: 'query' }, canary: 'canary' }))
      .toEqual({ technique: 'boolean', dbmsFingerprint: 'SQLite', observedDifference: null });
  });
  it('reports scanner failure and skip states as incomplete probe coverage', async () => {
    const request = { ...input(), parameter: { name: 'q', location: 'query' } as const, canary: 'canary' };
    expect((await new DalfoxAdapter({ enabled: false }).scan(request)).diagnostic).toBe('scanner-skipped');
    expect((await new SqlmapAdapter({ runner: async () => { throw new Error('PRIVATE'); } }).scan(request)).diagnostic).toBe('scanner-failed');
  });
  it('preserves cancellation for unchanged probe logic', async () => {
    const request = { ...input(), parameter: { name: 'q', location: 'query' } as const, canary: 'canary', signal: AbortSignal.abort() };
    await expect(new DalfoxAdapter().scan(request)).rejects.toThrow('cancelled');
    await expect(new SqlmapAdapter().scan(request)).rejects.toThrow('cancelled');
  });
});

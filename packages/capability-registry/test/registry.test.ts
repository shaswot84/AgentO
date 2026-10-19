import { describe, expect, it, vi } from 'vitest';
import { CapabilityRegistry } from '../src/index.js';
import type { SelectionRequest, ToolMetadata } from '../src/index.js';
import { probes, request, runtime, scanner, targetUrl, tool } from './helpers.js';

declare module '@agento/runtime' {
  interface CapabilityCatalog { 'custom-observer': { observe(): Promise<number> } }
}

describe('adapter registration and matching', () => {
  it('retains multiple providers and uses risk, priority and stable IDs for selection', async () => {
    const registry = new CapabilityRegistry().register(tool('z', { priority: 2 })).register(tool('a', { priority: 2 }))
      .register(tool('first', { priority: 3 })).register(tool('passive', { risk: 'passive', priority: -100 }));
    expect(registry.lookup({ capability: 'sql-scanner', cweId: 'CWE-89', protocol: 'https' }).map(item => item.id))
      .toEqual(['passive', 'first', 'a', 'z']);
    const resolved = await registry.resolve(request);
    expect(resolved.report.selections[0]!.selectedToolId).toBe('passive');
    expect(resolved.capabilities!.get('sql-scanner')).toBeDefined();
    expect(resolved.report.risk).toBe('active'); // The plan risk is never downgraded.
  });

  it('filters each candidate by protocol and CWE before checking it', async () => {
    const check = vi.fn(async () => true);
    const registry = new CapabilityRegistry().register(tool('http-only', { protocols: ['http'] }, { checkAvailability: check }))
      .register(tool('other-cwe', { supportedCwes: ['CWE-79'] }, { checkAvailability: check }))
      .register(tool('matching', { supportedCwes: 'all' }));
    const report = (await registry.resolve(request)).report;
    expect(check).not.toHaveBeenCalled();
    expect(report.availability.map(item => item.toolId)).toEqual(['matching']);
    expect(report.selections[0]).toMatchObject({ selectedToolId: 'matching', candidates: [
      { toolId: 'http-only', code: 'protocol-unsupported' }, { toolId: 'matching', code: 'available' },
      { toolId: 'other-cwe', code: 'cwe-unsupported' },
    ] });
  });

  it('reports unknown capabilities without accepting a partial required binding', async () => {
    const registry = new CapabilityRegistry().register(tool('present'));
    const result = await registry.resolve({ ...request, requiredCapabilities: ['sql-scanner', 'request-executor'] });
    expect(result.report.status).toBe('UNAVAILABLE'); expect(result.capabilities).toBeNull();
    expect(result.report.diagnostics).toContainEqual({ code: 'capability-unavailable', capability: 'request-executor' });
  });

  it('keeps missing optional ports visible without withholding required bindings', async () => {
    const result = await new CapabilityRegistry().register(tool('present')).resolve({ ...request, optionalCapabilities: ['xss-scanner'] });
    expect(result.report.status).toBe('READY'); expect(result.capabilities!.has('sql-scanner')).toBe(true);
    expect(result.capabilities!.has('xss-scanner')).toBe(false);
    expect(result.report.diagnostics).toEqual([{ code: 'optional-unavailable', capability: 'xss-scanner' }]);
  });

  it('raises reported risk when an active adapter satisfies a passive request', async () => {
    const result = await new CapabilityRegistry().register(tool('active')).resolve({ ...request, risk: 'passive' });
    expect(result.report.risk).toBe('active');
  });

  it('snapshots registration metadata and port mappings without freezing adapter instances', async () => {
    const adapter = tool('stable'), original = adapter.capabilities['sql-scanner'];
    const registry = new CapabilityRegistry().register(adapter);
    (adapter.metadata.capabilities as string[]).push('xss-scanner');
    (adapter.metadata as { risk: string }).risk = 'passive';
    (adapter.capabilities as { 'sql-scanner': unknown })['sql-scanner'] = scanner();
    const result = await registry.resolve(request);
    expect(result.capabilities!.get('sql-scanner')).toBe(original);
    expect(registry.list()[0]).toMatchObject({ risk: 'active', capabilities: ['sql-scanner'] });
    expect(Object.isFrozen(original)).toBe(false);
    expect(Object.isFrozen(result.report.selections[0]!.candidates)).toBe(true);
    expect(Object.isFrozen(registry.list()[0]!.supportedCwes)).toBe(true);
  });

  it.each([
    { id: 'unsafe id' }, { capabilities: [] }, { capabilities: ['sql-scanner', 'sql-scanner'] },
    { capabilities: ['xss-scanner'] }, { capabilities: ['probe:xss'] }, { protocols: ['file'] },
    { supportedCwes: [] }, { supportedCwes: ['89'] }, { risk: 'unknown' }, { priority: Infinity },
  ])('rejects invalid registration metadata %j', override => {
    expect(() => new CapabilityRegistry().register(tool('invalid', override as Partial<ToolMetadata>))).toThrow();
  });

  it('rejects duplicate IDs and metadata that does not match its actual ports', () => {
    const registry = new CapabilityRegistry().register(tool('duplicate'));
    expect(() => registry.register(tool('duplicate'))).toThrow();
    expect(() => registry.register(tool('empty', {}, { capabilities: {} }))).toThrow();
    expect(() => registry.register(tool('extra', {}, { capabilities: { 'sql-scanner': scanner(), 'xss-scanner': { scan: async () => ({
      executionConfirmed: false, domSinkReached: false,
    }) } } }))).toThrow();
  });

  it('binds probe requirements even if the incoming plan omits primitive capabilities', async () => {
    const { registry, execute, ports } = runtime();
    const result = await registry.resolve({ ...request, requiredCapabilities: ['probe:sql-injection'] });
    expect(result.report.status).toBe('READY'); expect(result.report.probeId).toBe('sql-injection');
    expect(result.capabilities!.has('response-comparator')).toBe(true);
    expect(result.report.diagnostics).toContainEqual({ code: 'optional-unavailable', capability: 'sql-scanner' });
    expect(execute).not.toHaveBeenCalled(); expect(ports['authentication-manager']!.establishSession).not.toHaveBeenCalled();
    expect(ports['browser-controller']!.withSession).not.toHaveBeenCalled();
  });

  it('withholds bindings when the probe implementation is missing', async () => {
    const registry = new CapabilityRegistry().register(tool('scanner'));
    const result = await registry.resolvePlan({ ...request, probeId: 'sql-injection' });
    expect(result.capabilities).toBeNull();
    expect(result.report.diagnostics).toContainEqual({ code: 'probe-unavailable', capability: 'probe:sql-injection' });
  });

  it('resolves direct probe requests without executing a probe', async () => {
    const { registry } = runtime(new CapabilityRegistry({ probes: probes() }));
    const result = await registry.resolveProbe('cookie-security', { cweId: 'CWE-1004', targetUrl, risk: 'passive' });
    expect(result.report.status).toBe('READY'); expect(result.report.probeId).toBe('cookie-security');
    expect(result.capabilities!.has('cookie-analyzer')).toBe(true);
    expect(result.report.risk).toBe('active');
  });

  it('supports independently declared typed capability ports', async () => {
    const observe = vi.fn(async () => 7);
    const registry = new CapabilityRegistry().register({ metadata: { id: 'extension', capabilities: ['custom-observer'],
      supportedCwes: 'all', protocols: ['https'], risk: 'passive' }, capabilities: { 'custom-observer': { observe } } });
    const result = await registry.resolve({ ...request, requiredCapabilities: ['custom-observer'], risk: 'passive' });
    expect(result.report.status).toBe('READY'); expect(observe).not.toHaveBeenCalled();
    expect(await result.capabilities!.get('custom-observer').observe()).toBe(7);
  });

  it('rejects invalid external probe metadata without exporting its contents', async () => {
    const supplied = probes();
    vi.spyOn(supplied, 'list').mockReturnValue([{ id: 'sql-injection', requiredCapabilities: ['PRIVATE probe configuration'], optionalCapabilities: [] }]);
    const { registry } = runtime(new CapabilityRegistry({ probes: supplied }));
    const result = await registry.resolveProbe('sql-injection', { cweId: 'CWE-89', targetUrl, risk: 'active' });
    expect(result.report.status).toBe('UNAVAILABLE'); expect(result.capabilities).toBeNull();
    expect(JSON.stringify(result.report)).not.toContain('PRIVATE');
  });

  it.each([
    { targetUrl: 'file:///tmp/private' }, { targetUrl: 'https://user:password@shop.test/' }, { targetUrl: 'invalid' },
    { cweId: '89' }, { risk: 'unknown' }, { requiredCapabilities: ['raw private value'] },
    { requiredCapabilities: ['probe:xss', 'probe:sql-injection'] }, { probeId: 'xss', requiredCapabilities: ['probe:sql-injection'] },
    { optionalCapabilities: ['probe:xss'] }, { readiness: 'unknown' },
  ])('rejects malformed selection input %j before availability checks', async override => {
    const check = vi.fn(async () => true);
    const registry = new CapabilityRegistry().register(tool('scanner', {}, { checkAvailability: check }));
    const result = await registry.resolve({ ...request, ...override } as SelectionRequest);
    expect(result.report.status).toBe('BLOCKED'); expect(result.capabilities).toBeNull();
    expect(result.report.diagnostics).toEqual([{ code: 'invalid-request' }]); expect(check).not.toHaveBeenCalled();
  });

  it('does not check tools for a plan whose planning prerequisites are blocked', async () => {
    const check = vi.fn(async () => true);
    const result = await new CapabilityRegistry().register(tool('scanner', {}, { checkAvailability: check }))
      .resolvePlan({ ...request, readiness: 'BLOCKED' });
    expect(result.report).toMatchObject({ status: 'BLOCKED', diagnostics: [{ code: 'plan-blocked' }] });
    expect(result.capabilities).toBeNull(); expect(check).not.toHaveBeenCalled();
  });
});

describe('availability, fallback and isolation', () => {
  it('checks each multi-capability adapter once and refreshes availability on every resolution', async () => {
    let available = true;
    const check = vi.fn(async () => available);
    const registry = new CapabilityRegistry().register(tool('primary', { priority: 1 }, { checkAvailability: check }))
      .register(tool('fallback'));
    expect((await registry.resolve(request)).report.selections[0]!.selectedToolId).toBe('primary');
    available = false;
    expect((await registry.resolve(request)).report.selections[0]!.selectedToolId).toBe('fallback');
    expect(check).toHaveBeenCalledTimes(2);
    const { registry: many } = runtime();
    expect((await many.resolve({ ...request, requiredCapabilities: ['request-executor', 'response-collector'] })).report.availability).toHaveLength(1);
  });

  it('sanitizes failed checks and chooses a healthy fallback', async () => {
    const registry = new CapabilityRegistry().register(tool('broken', { priority: 1 }, { checkAvailability: async () => {
      throw new Error('PRIVATE_PATH PRIVATE_TOKEN');
    } })).register(tool('fallback'));
    const result = await registry.resolve(request);
    expect(result.report.selections[0]!.selectedToolId).toBe('fallback');
    expect(result.report.availability).toContainEqual({ toolId: 'broken', available: false, code: 'check-failed' });
    expect(JSON.stringify(result.report)).not.toMatch(/PRIVATE|private-input/);
  });

  it('bounds a stalled check and aborts its local signal', async () => {
    let local: AbortSignal | undefined;
    const registry = new CapabilityRegistry({ availabilityTimeoutMs: 15 }).register(tool('stalled', {}, {
      checkAvailability: async signal => { local = signal; return new Promise(() => {}); },
    })).register(tool('fallback'));
    const result = await registry.resolve(request);
    expect(result.report.status).toBe('READY'); expect(local!.aborted).toBe(true);
    expect(result.report.availability).toContainEqual({ toolId: 'stalled', available: false, code: 'timeout' });
  });

  it('cancels pending checks and never returns a partially usable binding', async () => {
    const controller = new AbortController();
    let started!: () => void;
    const checking = new Promise<void>(resolve => { started = resolve; });
    const registry = new CapabilityRegistry().register(tool('slow', {}, { checkAvailability: async () => {
      started(); return new Promise(() => {});
    } })).register(tool('fast'));
    const resolving = registry.resolve(request, { signal: controller.signal });
    await checking; controller.abort();
    const result = await resolving;
    expect(result.report.status).toBe('CANCELLED'); expect(result.capabilities).toBeNull();
    expect(result.report.diagnostics).toContainEqual({ code: 'cancelled' });
  });

  it('handles pre-cancelled requests and preflight without starting callbacks', async () => {
    const check = vi.fn(async () => true), signal = AbortSignal.abort();
    const registry = new CapabilityRegistry().register(tool('idle', {}, { checkAvailability: check }));
    expect((await registry.resolve(request, { signal })).report.status).toBe('CANCELLED');
    expect(await registry.preflight({ signal })).toEqual([{ toolId: 'idle', available: false, code: 'cancelled' }]);
    expect(check).not.toHaveBeenCalled();
  });

  it('takes a stable snapshot during asynchronous checks', async () => {
    let finish!: (value: boolean) => void;
    let started!: () => void;
    const checking = new Promise<void>(resolve => { started = resolve; });
    const registry = new CapabilityRegistry().register(tool('original', {}, { checkAvailability: async () => {
      started(); return new Promise(resolve => { finish = resolve; });
    } }));
    const plan = { ...request, requiredCapabilities: ['sql-scanner'] };
    const resolving = registry.resolve(plan);
    await checking;
    plan.requiredCapabilities.push('request-executor');
    registry.register(tool('late', { priority: 100 })); finish(true);
    const result = await resolving;
    expect(result.report.status).toBe('READY'); expect(result.report.selections).toHaveLength(1);
    expect(result.report.selections[0]!.selectedToolId).toBe('original');
    expect(result.report.availability).toHaveLength(1);
  });

  it('projects JSON-safe public metadata and report fields', async () => {
    const adapter = tool('private-config', {}, { executable: '/tmp/PRIVATE_EXECUTABLE_PATH' });
    Object.assign(adapter.metadata, { password: 'PRIVATE_METADATA', config: { secret: 'PRIVATE_CONFIG' } });
    const registry = new CapabilityRegistry().register(adapter);
    const json = JSON.stringify({ metadata: registry.list(), result: (await registry.resolve(request)).report });
    expect(json).not.toMatch(/PRIVATE|private-input|executable|password/);
    expect(JSON.parse(json).result.status).toBe('UNAVAILABLE');
  });

  it.each([0, -1, 30_001, NaN, 2.5])('rejects invalid timeout %s', availabilityTimeoutMs => {
    expect(() => new CapabilityRegistry({ availabilityTimeoutMs })).toThrow();
  });
});

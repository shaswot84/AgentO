import { describe, expect, it, vi } from 'vitest';
import { PolicyEngine } from '../src/index.js';
import { config, origin, request, response, setup } from './helpers.js';

describe('policy configuration and plan validation', () => {
  it.each(['*', 'https://*.test', 'https://shop.test/path', 'https://u:p@shop.test', 'ftp://shop.test', 'https://shop.test?x=1', 'https://shop.test.', ' https://shop.test'])('rejects invalid allowlist %s', value => {
    expect(() => new PolicyEngine(config({ allowedOrigins: [value] }))).toThrow();
  });
  it.each([0, -1, NaN, 1.5, Infinity, 100_001])('rejects invalid request limit %s', value => {
    expect(() => new PolicyEngine(config({ maxRequestsPerExecution: value }))).toThrow();
  });
  it.each(['TRACE', 'CONNECT', 'get', '*'])('rejects unsafe configured method %s', value => {
    expect(() => new PolicyEngine(config({ allowedMethods: [value] }))).toThrow();
  });
  it.each(['https://other.test', 'http://shop.test', 'https://shop.test:444', 'https://shop.test.evil', 'https://u:p@shop.test', '//other.test', 'javascript:alert(1)'])('denies target %s before dispatch', async targetUrl => {
    const { resolution, send } = await setup();
    const engine = new PolicyEngine(config()), execute = vi.fn();
    await expect(engine.run(request({ targetUrl }), resolution, execute)).rejects.toThrow();
    expect(send).not.toHaveBeenCalled(); expect(execute).not.toHaveBeenCalled();
    expect(engine.audit().at(-1)?.outcome).toBe('DENY');
  });
  it('intersects project and host scope and checks project IDs', async () => {
    const { resolution } = await setup();
    const engine = new PolicyEngine(config()), input = request();
    expect(engine.review({ ...input, project: { ...input.project, allowedOrigins: ['https://other.test'] } }, resolution.report).code).toBe('target-denied');
    expect(engine.review({ ...input, plan: { ...input.plan, projectId: 'other' } }, resolution.report).code).toBe('invalid-request');
  });
  it('blocks unready plans and unavailable selections', async () => {
    const { resolution } = await setup();
    const engine = new PolicyEngine(config());
    expect(engine.review(request({ readiness: 'BLOCKED' }), resolution.report).code).toBe('plan-blocked');
    expect(engine.review(request(), { ...resolution.report, status: 'UNAVAILABLE' }).code).toBe('selection-unavailable');
    expect(engine.review(request({ requiredCapabilities: ['sql-scanner'] }), resolution.report).code).toBe('selection-unavailable');
  });
  it('uses explicit tool and capability allowlists', async () => {
    const { resolution } = await setup();
    expect(new PolicyEngine(config({ tools: {} })).review(request(), resolution.report).code).toBe('tool-denied');
    expect(new PolicyEngine(config({ tools: { runtime: { capabilities: ['sql-scanner'] } } })).review(request(), resolution.report).code).toBe('tool-denied');
    expect(new PolicyEngine(config({ tools: { runtime: { allowedOrigins: ['https://other.test'] } } })).review(request(), resolution.report).code).toBe('tool-denied');
  });
  it('raises understated risk for target-facing capabilities', async () => {
    const { resolution } = await setup();
    const decision = new PolicyEngine(config({ maxRisk: 'passive' })).review(request(), resolution.report);
    expect(decision).toMatchObject({ code: 'risk-denied', risk: 'active', severity: 'medium' });
    expect(new PolicyEngine(config({ tools: { runtime: { maxRisk: 'passive' } } })).review(request(), resolution.report).code).toBe('risk-denied');
  });
  it('validates structured request methods at review time', async () => {
    const { resolution } = await setup();
    expect(new PolicyEngine(config()).review(request({ request: { method: 'POST' } }), resolution.report).code).toBe('method-denied');
  });
});

describe('scoped approvals', () => {
  it('requires approval by default, then permits one exact execution', async () => {
    const { resolution, send } = await setup();
    const engine = new PolicyEngine({ allowedOrigins: [origin], tools: { runtime: {} } });
    const decision = engine.review(request(), resolution.report);
    expect(decision.outcome).toBe('APPROVAL_REQUIRED');
    await expect(engine.run(request(), resolution, async () => undefined)).rejects.toThrow('approval-required');
    const approvalId = engine.approve(decision.id, 'local-user');
    await engine.run(request(), resolution, async execution => { await execution.capabilities.get('request-executor').execute({ url: origin }); }, { approvalId });
    expect(send).toHaveBeenCalledOnce();
    await expect(engine.run(request(), resolution, async () => undefined, { approvalId })).rejects.toThrow('approval-invalid');
    const audit = engine.audit();
    expect(audit.find(record => record.operation === 'approval')).toMatchObject({ reviewId: decision.id, planFingerprint: audit[0]!.planFingerprint });
  });
  it('invalidates approval when a plan changes, expires or is revoked', async () => {
    let now = 1000;
    const { resolution } = await setup();
    const engine = new PolicyEngine(config({ approval: { risks: ['active'], ttlMs: 20 } }), { now: () => now });
    const token = () => engine.approve(engine.review(request(), resolution.report).id, 'user');
    const changed = token();
    await expect(engine.run(request({ targetUrl: `${origin}/other` }), resolution, async () => undefined, { approvalId: changed })).rejects.toThrow('approval-invalid');
    const revoked = token(); engine.revokeApproval(revoked);
    await expect(engine.run(request(), resolution, async () => undefined, { approvalId: revoked })).rejects.toThrow('approval-invalid');
    const expired = token(); now += 21;
    await expect(engine.run(request(), resolution, async () => undefined, { approvalId: expired })).rejects.toThrow('approval-invalid');
  });
  it('binds approvals to selected tool data and severity', async () => {
    const { resolution } = await setup();
    const engine = new PolicyEngine(config({ approval: { risks: ['active'] } }));
    const approvalId = engine.approve(engine.review(request(), resolution.report).id, 'user');
    await expect(engine.run({ ...request(), severity: 'critical' }, resolution, async () => undefined, { approvalId })).rejects.toThrow('approval-invalid');
    const changed = structuredClone(resolution.report);
    (changed.selections[0]!.candidates[0] as { risk: string }).risk = 'active';
    await expect(engine.run(request(), { ...resolution, report: changed }, async () => undefined, { approvalId })).rejects.toThrow('approval-invalid');
  });
  it('does not allow approval to override a denied plan', async () => {
    const { resolution } = await setup();
    const engine = new PolicyEngine(config());
    const denied = engine.review(request({ targetUrl: 'https://other.test' }), resolution.report);
    expect(() => engine.approve(denied.id, 'user')).toThrow('approval-invalid');
  });
  it('links denied target reviews to a private-safe request fingerprint', async () => {
    const { resolution } = await setup();
    const engine = new PolicyEngine(config());
    engine.review(request({ targetUrl: 'https://evil.test/PRIVATE_PATH?token=PRIVATE_TOKEN' }), resolution.report);
    expect(engine.audit()[0]).toMatchObject({ origin: 'https://evil.test', code: 'target-denied', planFingerprint: expect.stringMatching(/^[0-9a-f]{64}$/) });
    expect(JSON.stringify(engine.audit())).not.toMatch(/PRIVATE/);
  });
});

describe('runtime enforcement and audit', () => {
  it.each(['POST', 'PUT', 'PATCH', 'DELETE', 'TRACE', 'CONNECT', 'get', ''])('blocks method %s before transport', async method => {
    const { resolution, send } = await setup();
    const engine = new PolicyEngine(config());
    await expect(engine.run(request(), resolution, async execution => {
      await execution.capabilities.get('request-executor').execute({ url: origin, method });
    })).rejects.toThrow('method-denied');
    expect(send).not.toHaveBeenCalled();
  });
  it('allows an explicit unsafe method and narrows tool methods', async () => {
    const { resolution, send } = await setup();
    const engine = new PolicyEngine(config({ allowedMethods: ['GET', 'POST'], tools: { runtime: { allowedMethods: ['POST'] } } }));
    await engine.run(request(), resolution, async execution => {
      await execution.capabilities.get('request-executor').execute({ url: origin, method: 'POST', body: 'PRIVATE_BODY' });
      await expect(execution.capabilities.get('request-executor').execute({ url: origin })).rejects.toThrow('method-denied');
    });
    expect(send).toHaveBeenCalledOnce();
  });
  it('checks each action, including redirects and scanner attempts to change host', async () => {
    const send = vi.fn(async input => response(input, 302, { location: ['https://evil.test/private?token=PRIVATE'] }));
    const { resolution } = await setup({ 'request-executor': { execute: send } });
    const engine = new PolicyEngine(config());
    await expect(engine.run(request(), resolution, async execution => {
      await execution.capabilities.get('request-executor').execute({ url: origin });
    })).rejects.toThrow('redirect-denied');
    expect(send).toHaveBeenCalledOnce();
    expect(engine.audit().at(-1)?.code).toBe('redirect-denied');
  });
  it('accepts relative redirects and rejects cross-origin follow-up attempts', async () => {
    const { resolution, send } = await setup();
    const engine = new PolicyEngine(config());
    await engine.run(request(), resolution, async execution => {
      const guard = execution.guardFor('runtime');
      guard.assertRedirect(origin, '/next?private=value');
      await expect(execution.capabilities.get('request-executor').execute({ url: 'https://evil.test' })).rejects.toThrow('target-denied');
    });
    expect(send).not.toHaveBeenCalled();
  });
  it('shares rate limits across concurrent executions and renews the window', async () => {
    let now = 1000;
    const { resolution, send } = await setup();
    const engine = new PolicyEngine(config({ rateLimit: { maxRequests: 2, windowMs: 100 } }), { now: () => now });
    const run = () => engine.run(request(), resolution, async e => e.capabilities.get('request-executor').execute({ url: origin }));
    const results = await Promise.allSettled([run(), run(), run()]);
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(2);
    expect(send).toHaveBeenCalledTimes(2); now += 100;
    await run(); expect(send).toHaveBeenCalledTimes(3);
  });
  it('enforces per-execution and per-tool request limits', async () => {
    const { resolution, send } = await setup();
    for (const options of [{ maxRequestsPerExecution: 1 }, { tools: { runtime: { maxRequests: 1 } } }]) {
      const engine = new PolicyEngine(config(options));
      await expect(engine.run(request(), resolution, async e => {
        await e.capabilities.get('request-executor').execute({ url: origin });
        await e.capabilities.get('request-executor').execute({ url: origin });
      })).rejects.toThrow('request-limit');
    }
    expect(send).toHaveBeenCalledTimes(2);
  });
  it('revokes escaped capabilities on success and error', async () => {
    const { resolution } = await setup();
    const engine = new PolicyEngine(config());
    let saved: Parameters<Parameters<PolicyEngine['run']>[2]>[0];
    await engine.run(request(), resolution, async e => { saved = e; });
    await expect(saved!.capabilities.get('request-executor').execute({ url: origin })).rejects.toThrow('execution-closed');
    await expect(engine.run(request(), resolution, async e => { saved = e; throw new Error('callback'); })).rejects.toThrow('callback');
    expect(saved!.signal.aborted).toBe(true);
    expect(() => saved!.guardFor('runtime').assertActive()).toThrow('execution-closed');
  });
  it('cancels before transport and aborts in-flight signals on closure', async () => {
    const { resolution, send } = await setup();
    const engine = new PolicyEngine(config()), controller = new AbortController();
    await expect(engine.run(request(), resolution, async () => undefined, { signal: AbortSignal.abort() })).rejects.toThrow('cancelled');
    await engine.run(request(), resolution, async e => {
      await e.capabilities.get('request-executor').execute({ url: origin });
    });
    expect(send.mock.calls[0]![0].signal!.aborted).toBe(true);
    await expect(engine.run(request(), resolution, async e => {
      controller.abort(); await e.capabilities.get('request-executor').execute({ url: origin });
    }, { signal: controller.signal })).rejects.toThrow('cancelled');
  });
  it('records immutable private-safe decisions and fails closed when logging fails', async () => {
    const { resolution, send } = await setup();
    const engine = new PolicyEngine(config());
    await engine.run(request(), resolution, async e => { await e.capabilities.get('request-executor').execute({ url: `${origin}/PRIVATE_PATH?secret=PRIVATE_QUERY`, headers: { authorization: 'PRIVATE_TOKEN' }, body: 'PRIVATE_BODY' }); });
    const audit = engine.audit();
    expect(JSON.stringify(audit)).not.toMatch(/PRIVATE|secret|authorization|targetUrl/);
    expect(Object.isFrozen(audit)).toBe(true); expect(Object.isFrozen(audit[0])).toBe(true);
    expect(audit.map(record => record.sequence)).toEqual(audit.map((_, i) => i + 1));
    const broken = new PolicyEngine(config(), { auditSink: () => { throw new Error('PRIVATE_ERROR'); } });
    await expect(broken.run(request(), resolution, async () => { throw new Error('must not run'); })).rejects.toThrow('audit-unavailable');
    expect(send).toHaveBeenCalledOnce();
  });
  it('refuses requests after audit capacity or the execution deadline is reached', async () => {
    const { resolution, send } = await setup();
    let now = 1000;
    const engine = new PolicyEngine(config({ executionTtlMs: 10 }), { now: () => now });
    await expect(engine.run(request(), resolution, async e => {
      now += 11; await e.capabilities.get('request-executor').execute({ url: origin });
    })).rejects.toThrow('execution-closed');
    const full = new PolicyEngine(config({ maxAuditRecords: 1 }));
    await expect(full.run(request(), resolution, async e => e.capabilities.get('request-executor').execute({ url: origin }))).rejects.toThrow('audit-unavailable');
    expect(send).not.toHaveBeenCalled();
  });
  it('ends an unresponsive callback when the execution is cancelled', async () => {
    const { resolution } = await setup();
    const engine = new PolicyEngine(config()), controller = new AbortController();
    const pending = engine.run(request(), resolution, async () => { controller.abort(); return new Promise<never>(() => undefined); }, { signal: controller.signal });
    await expect(pending).rejects.toThrow('cancelled');
  });
  it('refuses an asynchronous audit sink and sanitizes clock errors', async () => {
    const { resolution, send } = await setup();
    const engine = new PolicyEngine(config(), { auditSink: async () => { throw new Error('PRIVATE_SINK'); } });
    await expect(engine.run(request(), resolution, async e => e.capabilities.get('request-executor').execute({ url: origin }))).rejects.toThrow('audit-unavailable');
    expect(send).not.toHaveBeenCalled();
    expect(() => new PolicyEngine(config(), { now: () => { throw new Error('PRIVATE_CLOCK'); } }).review(request(), resolution.report)).toThrow('audit-unavailable');
  });
  it('freezes caller configuration and snapshots mutable input before execution', async () => {
    const { resolution, send } = await setup();
    const settings = config(), input = request(), engine = new PolicyEngine(settings);
    (settings.allowedOrigins as string[]).push('https://evil.test');
    await engine.run(input, resolution, async e => {
      (input.plan as { targetUrl: string }).targetUrl = 'https://evil.test';
      await expect(e.capabilities.get('request-executor').execute({ url: 'https://evil.test' })).rejects.toThrow('target-denied');
    });
    expect(send).not.toHaveBeenCalled();
  });
});

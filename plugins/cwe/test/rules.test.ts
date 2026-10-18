import { describe, expect, it } from 'vitest';
import type { NormalizedProbeEvidence } from '../src/index.js';
import { CWE79Plugin, CWE89Plugin, CWE639Plugin, CWE862Plugin, CWE942Plugin, CWE1004Plugin, CWE614Plugin } from '../src/index.js';
import { authorization, cookies, cors, response, scope, sql, xss } from './helpers.js';

describe('independent evidence verdicts', () => {
  it.each([
    [new CWE79Plugin(), xss()], [new CWE89Plugin(), sql()], [new CWE639Plugin(), authorization()],
    [new CWE862Plugin(), authorization()], [new CWE942Plugin(), cors()],
    [new CWE1004Plugin(), cookies()], [new CWE614Plugin(), cookies()],
  ] as const)('confirms %s from normalized proof and preserves immutable provenance', async (plugin, evidence) => {
    const before = JSON.stringify(evidence), verdict = await plugin.evaluate([evidence], scope);
    expect(verdict).toMatchObject({ cweId: plugin.cweId, status: 'CONFIRMED', confidence: 'high', evidenceIds: [evidence.id] });
    expect(Object.isFrozen(verdict.evidenceIds)).toBe(true); expect(JSON.stringify(evidence)).toBe(before);
  });
  const plugins = [new CWE79Plugin(), new CWE89Plugin(), new CWE639Plugin(), new CWE862Plugin(), new CWE942Plugin(), new CWE1004Plugin(), new CWE614Plugin()];
  it.each(plugins)('%s keeps empty, malformed and foreign evidence inconclusive', async plugin => {
    for (const records of [[], [{} as NormalizedProbeEvidence], [cookies({ projectId: 'other' })]]) {
      expect((await plugin.evaluate(records, scope)).status).toBe('NOT_REPRODUCED');
    }
  });
  it('excludes conflicting duplicate evidence IDs', async () => {
    const safe = cookies(); (safe.observations[0]!.cookies[0] as { httpOnly: boolean }).httpOnly = true;
    const verdict = await new CWE1004Plugin().evaluate([cookies(), safe], scope);
    expect(verdict.status).toBe('NOT_REPRODUCED'); expect(verdict.evidenceIds).toEqual([]);
  });
});
describe('sensitive cookie rules share one observation', () => {
  it.each(['httpOnly', 'secure'] as const)('rejects a completed protected %s cookie', async attribute => {
    const item = cookies(); (item.observations[0]!.cookies[0] as unknown as Record<string, unknown>)[attribute] = true;
    const rule = attribute === 'httpOnly' ? new CWE1004Plugin() : new CWE614Plugin();
    expect((await rule.evaluate([item], scope)).status).toBe('REJECTED');
    expect((await rule.evaluate([{ ...item, outcome: 'PARTIAL' }], scope)).status).toBe('NOT_REPRODUCED');
  });
  it('does not guess sensitivity or apply Secure to an HTTP-only observation', async () => {
    expect((await new CWE1004Plugin().evaluate([cookies()], { ...scope, sensitiveCookieNames: [] })).status).toBe('NOT_REPRODUCED');
    expect((await new CWE614Plugin().evaluate([cookies()], { ...scope, targetUrl: 'http://shop.test/orders/1' })).status).toBe('NOT_REPRODUCED');
  });
  it.each(['domain', 'path', 'maxAge', 'expiresAt'] as const)('ignores inapplicable or deleted cookies via %s', async field => {
    const item = cookies(), values = { domain: 'elsewhere.test', path: '/other', maxAge: 0, expiresAt: '2020-01-01T00:00:00Z' };
    (item.observations[0]!.cookies[0] as unknown as Record<string, unknown>)[field] = values[field];
    expect((await new CWE1004Plugin().evaluate([item], scope)).status).toBe('NOT_REPRODUCED');
  });
  it('can confirm a directly observed missing flag despite unrelated partial collection', async () => {
    expect((await new CWE1004Plugin().evaluate([cookies({ outcome: 'PARTIAL', diagnostics: ['browser-unavailable'] })], scope)).status).toBe('CONFIRMED');
  });
});
describe('authorization proof requirements', () => {
  it.each([new CWE639Plugin(), new CWE862Plugin()])('%s rejects denied access with an owner baseline', async rule => {
    const item = authorization({ attacker: response({ status: 403 }) });
    expect((await rule.evaluate([item], scope)).status).toBe('REJECTED');
  });
  it.each([new CWE639Plugin(), new CWE862Plugin()])('%s does not infer leakage from status or equal bodies', async rule => {
    const item = authorization(); (item.attackerComparison as { ownerMarkersMatch: boolean | null }).ownerMarkersMatch = null;
    expect((await rule.evaluate([item], scope)).status).toBe('NOT_REPRODUCED');
  });
  it('distinguishes anonymous missing authorization from authenticated key bypass', async () => {
    const item = authorization({ attacker: response({ status: 403 }), anonymous: response(), anonymousComparison: authorization().attackerComparison });
    expect((await new CWE862Plugin().evaluate([item], scope)).status).toBe('CONFIRMED');
    expect((await new CWE639Plugin().evaluate([item], scope)).status).toBe('REJECTED');
  });
  it.each([
    authorization({ owner: response({ status: 401 }) }),
    authorization({ attacker: response({ url: 'https://shop.test/login' }) }),
    authorization({ resourceId: 'other' }), authorization({ attackerIdentityId: 'alice' }),
    authorization({ attacker: response({ body: { ...response().body, truncated: true } }) }),
  ])('does not confirm mismatched, truncated or failed baselines', async item => {
    expect((await new CWE639Plugin().evaluate([item], scope)).status).toBe('NOT_REPRODUCED');
  });
  it('requires explicit forbidden-access policy', async () => {
    const publicScope = { ...scope, authorization: { ...scope.authorization!, attackerIsUnauthorized: false, anonymousIsUnauthorized: false } };
    expect((await new CWE639Plugin().evaluate([authorization()], publicScope)).status).toBe('NOT_REPRODUCED');
    expect((await new CWE862Plugin().evaluate([authorization()], publicScope)).status).toBe('NOT_REPRODUCED');
  });
});
describe('XSS interpretation', () => {
  it.each([
    xss({ executionConfirmed: null, domSinkReached: null }), xss({ executionConfirmed: false, domSinkReached: true }),
    xss({ parameter: { name: 'other', location: 'query' } }), xss({ injected: response({ url: 'https://other.test/orders/1' }) }),
  ])('does not mistake reflection, a sink or unrelated evidence for execution', async item => {
    expect((await new CWE79Plugin().evaluate([item], scope)).status).toBe('NOT_REPRODUCED');
  });
  it('rejects a completed check with explicit negative execution and sink observations', async () => {
    expect((await new CWE79Plugin().evaluate([xss({ executionConfirmed: false, domSinkReached: false })], scope)).status).toBe('REJECTED');
  });
});
describe('SQL interpretation', () => {
  it('accepts controlled boolean proof without a database error or optional scanner', async () => {
    const item = sql(); const observations = item.observations.filter(value => value.variant !== 'syntax');
    expect((await new CWE89Plugin().evaluate([{ ...item, observations, outcome: 'PARTIAL', diagnostics: ['scanner-unavailable'] }], scope)).status).toBe('CONFIRMED');
  });
  it.each(['generic-error', 'failed-baseline', 'truncated', 'both-controls-change', 'timing-only', 'duplicate-variants'] as const)(
    'does not confirm %s', async kind => {
      const item = sql(); let candidate = { ...item, observations: item.observations.filter(value => value.variant === 'syntax') };
      if (kind === 'generic-error') candidate = { ...candidate, observations: candidate.observations.map(value => ({ ...value, dbmsFingerprint: null, errorIndicators: ['sql-syntax-error'] })) };
      if (kind === 'failed-baseline') candidate.baseline = response({ status: 500 });
      if (kind === 'truncated') candidate.observations = candidate.observations.map(value => ({ ...value, response: response({ status: 500, body: { ...response().body, truncated: true } }) }));
      if (kind === 'both-controls-change') candidate = { ...item, observations: item.observations.filter(value => value.variant !== 'syntax').map(value => ({ ...value, comparison: { ...value.comparison, bodyEqual: false } })) };
      if (kind === 'timing-only') candidate = { ...item, observations: [], scanner: { technique: 'time', dbmsFingerprint: 'SQLite', observedDifference: true } };
      if (kind === 'duplicate-variants') candidate.observations = [...candidate.observations, ...candidate.observations];
      expect((await new CWE89Plugin().evaluate([candidate], scope)).status).toBe('NOT_REPRODUCED');
    });
  it('rejects fully negative checks and leaves absent scanners partial', async () => {
    const item = sql({ scanner: { technique: 'boolean', dbmsFingerprint: null, observedDifference: false } });
    const observations = item.observations.map(value => ({ ...value, response: response(), comparison: authorization().attackerComparison, errorIndicators: [] }));
    expect((await new CWE89Plugin().evaluate([{ ...item, observations }], scope)).status).toBe('REJECTED');
    expect((await new CWE89Plugin().evaluate([{ ...item, observations, scanner: null, outcome: 'PARTIAL', diagnostics: ['scanner-unavailable'] }], scope)).status).toBe('NOT_REPRODUCED');
  });
});
describe('cross-origin policy interpretation', () => {
  it('does not classify a same-origin or invalid Origin value as cross-origin access', async () => {
    for (const origin of ['https://shop.test', 'https://unapproved.invalid/']) {
      const item = cors(); Object.assign(item.observations[0]!, { requestedOrigin: origin });
      Object.assign(item.observations[0]!.actual.cors, { allowOrigin: [origin] });
      expect((await new CWE942Plugin().evaluate([item], { ...scope, untrustedOrigins: [origin] })).status).toBe('NOT_REPRODUCED');
    }
  });
  it('reports wildcard plus credentials as configuration proof with the browser limitation', async () => {
    const item = cors(); (item.observations[0]!.actual.cors as unknown as { allowOrigin: string[] }).allowOrigin = ['*'];
    const verdict = await new CWE942Plugin().evaluate([item], scope);
    expect(verdict.status).toBe('CONFIRMED'); expect(verdict.limitations.join(' ')).toContain('browsers reject');
  });
  it.each(['preflight-only', 'duplicate-origin', 'no-credentials', 'anonymous', 'untrusted-unknown'] as const)('does not confirm %s', async kind => {
    const item = cors(); const observation = item.observations[0]!;
    if (kind === 'preflight-only') (observation.actual.cors as unknown as { allowOrigin: string[] }).allowOrigin = [];
    if (kind === 'duplicate-origin') (observation.actual.cors as unknown as { allowOrigin: string[] }).allowOrigin = ['https://unapproved.invalid', '*'];
    if (kind === 'no-credentials') (observation.actual.cors as unknown as { allowCredentials: boolean[] }).allowCredentials = [false];
    if (kind === 'anonymous') { (observation as { credentialMode: string }).credentialMode = 'omit'; (observation as { identityId: null }).identityId = null; }
    const verdict = await new CWE942Plugin().evaluate([item], kind === 'untrusted-unknown' ? { ...scope, untrustedOrigins: [] } : scope);
    expect(verdict.status).not.toBe('CONFIRMED');
  });
  it('rejects a restricted actual policy and supports explicit untrusted null origins', async () => {
    const item = cors(); (item.observations[0]!.actual.cors as unknown as { allowOrigin: string[] }).allowOrigin = ['https://trusted.test'];
    expect((await new CWE942Plugin().evaluate([item], scope)).status).toBe('REJECTED');
    const nullItem = cors(); (nullItem.observations[0] as { requestedOrigin: string }).requestedOrigin = 'null';
    (nullItem.observations[0]!.actual.cors as unknown as { allowOrigin: string[] }).allowOrigin = ['null'];
    expect((await new CWE942Plugin().evaluate([nullItem], scope)).status).toBe('CONFIRMED');
  });
});

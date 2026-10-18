import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { BrowserObservation, Project } from '@agento/core';
import { ExpressFrameworkAdapter } from '@agento/framework-express';
import { NormalizedCookieAnalyzer, NormalizedHeaderAnalyzer, NormalizedResponseCollector } from '@agento/runtime';
import type { CookieEvidence, NetworkEvidence } from '@agento/runtime';
import {
  buildApplicationSecurityModel, fromBrowserObservation, fromFrameworkAnalysis,
  fromRuntimeSnapshot, resolveEndpoint,
} from '../src/index.js';

const capturedAt = '2026-10-18T00:00:00.000Z';
const project: Project = { id: 'integrated-shop', name: 'Demo shop', mode: 'code-aware',
  repositoryPath: fileURLToPath(new URL('../../../demo-apps/demo-app-01/', import.meta.url)),
  baseUrl: 'http://localhost:3000', allowedOrigins: ['http://localhost:3000'], languages: ['javascript'] };

describe('existing adapter and runtime integration', () => {
  it('merges real source extraction with normalized runtime and browser ownership observations', async () => {
    const source = await new ExpressFrameworkAdapter({ now: () => capturedAt }).extract(project);
    const sourceOrder = source.endpoints.find(item => item.method === 'GET' && item.path === '/api/orders/:id')!;
    expect(sourceOrder).toBeDefined();
    const collector = new NormalizedResponseCollector();
    const response = collector.collect({ url: 'http://localhost:3000/api/orders/102?token=private-access-token#private-fragment', method: 'GET' }, {
      status: 200,
      headers: { 'content-type': ['application/json'], 'set-cookie': ['sid=private-cookie-value; HttpOnly; SameSite=Lax; Path=/'],
        'access-control-allow-origin': ['http://localhost:3000'], 'access-control-allow-credentials': ['true'],
        authorization: ['Bearer private-auth-token'] },
      body: Buffer.from('{"id":102,"private":"private-response-data"}'), truncated: false, firstByteMs: 2,
    }, { startedAt: capturedAt, firstByteMs: 2, durationMs: 4 });
    const headers = await new NormalizedHeaderAnalyzer().analyze(response);
    const cookies = await new NormalizedCookieAnalyzer().analyze(response);
    const runtime = fromRuntimeSnapshot(project, { producerId: 'normalized-runtime', capturedAt,
      responses: [collector.evidence(response)], headers: [headers], cookies,
      network: [{ sessionId: 'alice-session', identityId: 'alice', source: 'browser',
        url: 'http://localhost:3000/api/orders/102', method: 'GET', status: 200, blocked: false }] });
    const browser: BrowserObservation = {
      endpoints: [{ ...sourceOrder, id: 'observed-order', path: '/api/orders/102',
        authentication: 'unknown', parameters: [], roles: [], evidenceIds: ['observed-owner'] }],
      resources: [{ id: 'order-102', projectId: project.id, type: 'Order', externalKey: '102', ownerIdentityId: 'alice',
        endpointId: 'observed-order', evidenceIds: ['observed-owner'] }], signals: [],
      evidence: [{ id: 'observed-owner', projectId: project.id, kind: 'resource-ownership', producerId: 'browser-port', capturedAt,
        summary: 'Alice explicitly observed as owner of Order 102', endpointId: 'observed-order', identityId: 'alice',
        facts: { resourceId: 'order-102', ownerIdentityId: 'alice' } }],
    };
    const result = buildApplicationSecurityModel({ project,
      identities: [{ id: 'alice', label: 'Alice', roles: ['customer'], authentication: 'session-cookie' }],
      contributions: [fromFrameworkAnalysis(source), runtime, fromBrowserObservation(browser)] });
    const order = resolveEndpoint(result, sourceOrder.id)!;

    expect(result.endpoints).toHaveLength(source.endpoints.length);
    expect(resolveEndpoint(result, 'observed-order')).toBe(order);
    expect(order).toMatchObject({ path: '/api/orders/:id', authentication: 'required' });
    expect(order.observations.map(item => item.source)).toEqual(expect.arrayContaining(['source', 'runtime', 'browser']));
    expect(result.parameters).toContainEqual(expect.objectContaining({ endpointId: order.id, name: 'id', location: 'path', required: true }));
    expect(result.sourceHandlers).toContainEqual(expect.objectContaining({ endpointId: order.id, source: sourceOrder.handler }));
    expect(result.databaseOperations).toContainEqual(expect.objectContaining({ endpointIds: [order.id],
      details: expect.objectContaining({ operation: 'SELECT', tables: expect.arrayContaining(['orders']) }) }));
    expect(result.resourceTypes).toContainEqual(expect.objectContaining({ details: expect.objectContaining({ type: 'Order' }) }));
    expect(result.observedOwnership).toContainEqual(expect.objectContaining({ endpointIds: [order.id],
      details: expect.objectContaining({ ownerIdentityId: 'alice' }) }));
    expect(result.resources[0]!.endpointId).toBe(order.id);
    expect(result.cookies.some(item => item.source === 'source')).toBe(true);
    expect(result.cookies.some(item => item.source === 'runtime')).toBe(true);
    expect(result.corsConfigurations.some(item => item.source === 'source')).toBe(true);
    expect(result.corsConfigurations.some(item => item.source === 'runtime')).toBe(true);
    expect(result.runtimeObservations.some(item => item.producerId === 'normalized-runtime')).toBe(true);
    for (const original of [...source.evidence, ...browser.evidence]) {
      expect(result.evidence.find(item => item.id === original.id)).toEqual(original);
    }
    const serialized = JSON.stringify(result);
    for (const secret of ['private-access-token', 'private-fragment', 'private-cookie-value', 'private-auth-token',
      'private-response-data', 'agento-super-secret-demo-session-key']) expect(serialized).not.toContain(secret);
    expect(JSON.parse(serialized)).toEqual(result);
  });

  it('keeps blocked network observations without inventing endpoints and sanitizes copied cookie material', () => {
    const network: NetworkEvidence[] = [
      { sessionId: 'session', identityId: 'alice', source: 'http', url: 'http://localhost:3000/unreachable',
        method: 'GET', status: null, blocked: false },
      { sessionId: 'session', identityId: 'alice', source: 'browser', url: 'https://outside.test/private?secret=private-query',
        method: 'GET', status: 200, blocked: true },
    ];
    const cookie = { name: 'sid', value: 'private-cookie', domain: 'localhost', path: '/', hostOnly: true,
      httpOnly: true, secure: false, sameSite: 'Lax', expiresAt: null, maxAge: null, partitioned: false,
      source: 'browser', sessionId: 'session' } as unknown as CookieEvidence;
    const contribution = fromRuntimeSnapshot(project, { producerId: 'runtime', capturedAt, network, cookies: [cookie] });
    const result = buildApplicationSecurityModel({ project,
      identities: [{ id: 'alice', label: 'Alice', roles: [], authentication: 'session-cookie' }], contributions: [contribution] });
    expect(result.endpoints).toEqual([]);
    expect(result.runtimeObservations).toHaveLength(3);
    expect(result.cookies).toHaveLength(1);
    expect(result.cookies[0]!.details.value).toBe('[REDACTED]');
    expect(JSON.stringify(result)).not.toMatch(/private-cookie|private-query/);
    expect(cookie.value).toBe('private-cookie');
  });
});

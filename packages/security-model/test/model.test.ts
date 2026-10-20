import { describe, expect, it } from 'vitest';
import type { AnalysisContext, Component, Endpoint, Evidence, Project, Resource, SecuritySignal } from '@agento/core';
import {
  buildApplicationSecurityModel, fromAnalysisContext, fromBrowserObservation,
  fromFrameworkAnalysis, fromStaticAnalysis, resolveEndpoint,
} from '../src/index.js';
import type { ModelContribution, SecurityModelInput } from '../src/index.js';

const project: Project = { id: 'shop', name: 'Shop', mode: 'black-box', baseUrl: 'https://shop.test',
  allowedOrigins: ['https://shop.test', 'https://api.shop.test'], languages: [] };
const component: Component = { id: 'service', projectId: project.id, name: 'Shop service', kind: 'service' };
const endpoint = (id: string, path = '/orders/:id', extra: Partial<Endpoint> = {}): Endpoint => ({
  id, componentId: component.id, method: 'GET', path, parameters: [], authentication: 'unknown', roles: [], evidenceIds: [], ...extra,
});
const evidence = (id: string, endpointId?: string, extra: Partial<Evidence> = {}): Evidence => ({
  id, projectId: project.id, kind: 'source-location', producerId: 'neutral-adapter',
  capturedAt: '2026-10-18T00:00:00.000Z', summary: 'Observed route', facts: { observation: 'route' },
  ...(endpointId ? { endpointId } : {}), ...extra,
});
const source = (endpoints: readonly Endpoint[], extra: Partial<ModelContribution> = {}): ModelContribution => ({
  source: 'source', components: [component], endpoints, ...extra,
});
const model = (...contributions: ModelContribution[]) => buildApplicationSecurityModel({ project, contributions });

describe('neutral model identity and endpoint reconciliation', () => {
  it('preserves unvalidated inventory after merging, aliases and JSON serialization', () => {
    const result = model(source([endpoint('inventory', '/orders/:id', {
      discovery: { providerId: 'inventory', validation: 'candidate' },
    })]), { source: 'runtime', endpoints: [endpoint('observed', '/orders/102')] });
    const serialized = JSON.parse(JSON.stringify(result));
    expect(serialized.endpoints).toHaveLength(1);
    expect(serialized.endpoints[0].discovery).toEqual({ providerId: 'inventory', validation: 'candidate' });
    expect(serialized.endpointAliases.observed).toBe(serialized.endpoints[0].id);
  });
  it('represents an empty black-box application with every collection available', () => {
    const result = buildApplicationSecurityModel({ project });
    expect(result.schemaVersion).toBe(1);
    for (const key of ['components', 'endpoints', 'identities', 'resources', 'signals', 'evidence', 'parameters',
      'authenticationRequirements', 'userRoles', 'sourceHandlers', 'resourceTypes', 'observedOwnership',
      'dataFlows', 'databaseOperations', 'cookies', 'corsConfigurations', 'runtimeObservations', 'diagnostics'] as const) {
      expect(result[key]).toEqual([]);
    }
    expect(result.endpointAliases).toEqual({});
    expect(result.project).toEqual(project);
  });

  it('deduplicates repeated provider data and retains a resolvable alias', () => {
    const input = source([endpoint('declared', '/orders', { evidenceIds: ['route'] })], { evidence: [evidence('route', 'declared')] });
    const result = model(input, input);
    expect(result.endpoints).toHaveLength(1);
    expect(result.evidence).toHaveLength(1);
    expect(result.components).toHaveLength(1);
    expect(resolveEndpoint(result, 'declared')).toBe(result.endpoints[0]);
    expect(resolveEndpoint(result, result.endpoints[0]!.id)).toBe(result.endpoints[0]);
    expect(resolveEndpoint(result, 'absent')).toBeUndefined();
  });

  it('merges source and concrete runtime routes and retains provenance of both observations', () => {
    const result = model(source([endpoint('source-order', '/orders/:id')]), {
      source: 'runtime', endpoints: [endpoint('runtime-order', 'https://shop.test/orders/102?view=full#detail')],
    });
    expect(result.endpoints).toHaveLength(1);
    expect(result.endpoints[0]).toMatchObject({ path: '/orders/:id', origin: 'https://shop.test' });
    expect(result.endpoints[0]!.aliases).toEqual(expect.arrayContaining(['source-order', 'runtime-order']));
    expect(result.endpoints[0]!.observations.map(item => item.source).sort()).toEqual(['runtime', 'source']);
    expect(resolveEndpoint(result, 'source-order')).toBe(resolveEndpoint(result, 'runtime-order'));
  });

  it('recognizes simple brace parameters without interpreting query values as endpoint identity', () => {
    const result = model(source([endpoint('declared', '/orders/{orderId}')]), {
      source: 'browser', endpoints: [endpoint('first', '/orders/102?format=json'), endpoint('second', '/orders/103?format=html')],
    });
    expect(result.endpoints).toHaveLength(1);
    expect(resolveEndpoint(result, 'first')).toBe(resolveEndpoint(result, 'second'));
    expect(result.endpoints[0]!.path).toBe('/orders/:orderId');
  });

  it('keeps different methods and explicit origins separate', () => {
    const result = model(source([
      endpoint('get', '/orders'), endpoint('post', '/orders', { method: 'POST' }),
      endpoint('api', '/orders'),
    ], { endpointOrigins: { api: 'https://api.shop.test' } }));
    expect(result.endpoints).toHaveLength(3);
    expect(resolveEndpoint(result, 'get')!.id).not.toBe(resolveEndpoint(result, 'post')!.id);
    expect(resolveEndpoint(result, 'get')!.id).not.toBe(resolveEndpoint(result, 'api')!.id);
  });

  it('does not match a concrete route to a template on a different origin or method', () => {
    const result = model(source([endpoint('template')]), { source: 'runtime', endpoints: [
      endpoint('different-origin', 'https://api.shop.test/orders/102'),
      endpoint('different-method', '/orders/102', { method: 'DELETE' }),
    ] });
    expect(result.endpoints).toHaveLength(3);
  });

  it('prefers an exact declared path over a matching parameter template', () => {
    const result = model(source([endpoint('template'), endpoint('special', '/orders/latest')]), {
      source: 'runtime', endpoints: [endpoint('request', '/orders/latest')],
    });
    expect(result.endpoints).toHaveLength(2);
    expect(resolveEndpoint(result, 'request')).toBe(resolveEndpoint(result, 'special'));
    expect(resolveEndpoint(result, 'request')).not.toBe(resolveEndpoint(result, 'template'));
  });

  it('retains ambiguous concrete observations instead of guessing between templates', () => {
    const result = model(source([endpoint('area', '/:area/orders'), endpoint('user', '/users/:id')]), {
      source: 'runtime', endpoints: [endpoint('request', '/users/orders')],
    });
    expect(result.endpoints).toHaveLength(3);
    expect(resolveEndpoint(result, 'request')).not.toBe(resolveEndpoint(result, 'area'));
    expect(resolveEndpoint(result, 'request')).not.toBe(resolveEndpoint(result, 'user'));
    expect(result.diagnostics).toContainEqual(expect.objectContaining({ code: 'ambiguous-endpoint' }));
  });

  it('does not guess semantics for framework regex, optional or wildcard syntax', () => {
    const result = model(source([
      endpoint('regex', '/regex/:id(\\d+)'), endpoint('optional', '/optional/:id?'), endpoint('wildcard', '/wild/*'),
    ]), { source: 'runtime', endpoints: [
      endpoint('regex-request', '/regex/102'), endpoint('optional-request', '/optional/102'), endpoint('wild-request', '/wild/102'),
    ] });
    expect(result.endpoints).toHaveLength(6);
  });

  it('gives endpoints project-specific canonical identities', () => {
    const first = model(source([endpoint('route', '/orders')]));
    const secondProject = { ...project, id: 'other-shop' };
    const second = buildApplicationSecurityModel({ project: secondProject,
      contributions: [source([endpoint('route', '/orders')], { components: [{ ...component, projectId: secondProject.id }] })] });
    expect(first.endpoints[0]!.id).not.toBe(second.endpoints[0]!.id);
  });

  it('rejects provider aliases that collide with another endpoint canonical ID', () => {
    const canonicalId = model(source([endpoint('route', '/orders')])).endpoints[0]!.id;
    expect(() => model(source([endpoint('route', '/orders'), endpoint(canonicalId, '/other-route')]))).toThrow();
  });

  it('treats colon segments observed only at runtime as literal paths', () => {
    const result = model({ source: 'runtime', endpoints: [
      endpoint('literal', '/orders/:id'), endpoint('request', '/orders/102'),
    ] });
    expect(result.endpoints).toHaveLength(2);
    expect(resolveEndpoint(result, 'literal')).not.toBe(resolveEndpoint(result, 'request'));
  });

  it('rejects an HTTP origin fact that conflicts with its own observed URL', () => {
    expect(() => model({ source: 'runtime', endpoints: [endpoint('request', '/orders')], evidence: [
      evidence('response', 'request', { kind: 'http-response',
        facts: { origin: 'https://shop.test', url: 'https://api.shop.test/orders', status: 200 } }),
    ] })).toThrow();
  });
});

describe('knowledge, evidence and safe copies', () => {
  it('leaves unknown authentication unknown when a runtime request succeeds', () => {
    const result = model(source([endpoint('source')]), { source: 'runtime', endpoints: [endpoint('request', '/orders/102')],
      evidence: [evidence('response', 'request', { kind: 'http-response', facts: { status: 200 } })] });
    expect(result.endpoints[0]!.authentication).toBe('unknown');
    expect(result.authenticationRequirements.every(item => item.requirement === 'unknown')).toBe(true);
    expect(result.runtimeObservations.map(item => item.id)).toContain('response');
  });

  it('retains conflicting authentication observations and marks the summary unknown', () => {
    const result = model(source([endpoint('required', '/orders', { authentication: 'required', roles: ['customer'] })]), {
      source: 'declared', endpoints: [endpoint('optional', '/orders', { authentication: 'optional' })],
    });
    expect(result.endpoints[0]!.authentication).toBe('unknown');
    expect(result.authenticationRequirements.map(item => item.requirement).sort()).toEqual(['optional', 'required']);
    expect(result.endpoints[0]!.observations.map(item => item.endpoint.authentication).sort()).toEqual(['optional', 'required']);
    expect(result.diagnostics).toContainEqual(expect.objectContaining({ code: 'conflicting-authentication' }));
    expect(result.userRoles).toContainEqual(expect.objectContaining({ name: 'customer' }));
  });

  it('separates parameter locations and retains conflicting requiredness as unknown', () => {
    const result = model(source([endpoint('first', '/orders', { parameters: [
      { name: 'id', location: 'query', required: true }, { name: 'id', location: 'body', required: false },
    ] })]), { source: 'declared', endpoints: [endpoint('second', '/orders', { parameters: [
      { name: 'id', location: 'query', required: false },
    ] })] });
    expect(result.parameters).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: 'id', location: 'query', required: null }),
      expect.objectContaining({ name: 'id', location: 'body', required: false }),
    ]));
    expect(result.parameters).toHaveLength(2);
    expect(result.diagnostics).toContainEqual(expect.objectContaining({ code: 'conflicting-parameter' }));
  });

  it('does not treat presence of a runtime query parameter as proof that it is optional', () => {
    const result = model({ source: 'runtime', endpoints: [endpoint('request', '/orders', {
      parameters: [{ name: 'filter', location: 'query', required: false }],
    })] });
    expect(result.parameters).toEqual([expect.objectContaining({ name: 'filter', location: 'query', required: null })]);
  });

  it('keeps an explicit source parameter requirement despite runtime presence observations', () => {
    const result = model(source([endpoint('route', '/orders', {
      parameters: [{ name: 'filter', location: 'query', required: true }],
    })]), { source: 'runtime', endpoints: [endpoint('request', '/orders?filter=latest', {
      parameters: [{ name: 'filter', location: 'query', required: false }],
    })] });
    expect(result.parameters).toEqual([expect.objectContaining({ name: 'filter', location: 'query', required: true })]);
    expect(result.diagnostics.some(item => item.code === 'conflicting-parameter')).toBe(false);
  });

  it('preserves multiple components and handlers for a shared logical route', () => {
    const handlerA = { file: 'src/orders.ts', startLine: 12, symbol: 'getOrder' };
    const handlerB = { file: 'src/router.ts', startLine: 3, symbol: 'orderProxy' };
    const other = { ...component, id: 'gateway', name: 'Gateway' };
    const result = model(source([endpoint('first', '/orders', { handler: handlerA })]),
      source([endpoint('second', '/orders', { componentId: other.id, handler: handlerB })], { components: [other] }));
    expect(result.endpoints).toHaveLength(1);
    expect(result.endpoints[0]!.componentIds).toEqual(expect.arrayContaining(['service', 'gateway']));
    expect(result.sourceHandlers.map(item => item.source)).toEqual(expect.arrayContaining([handlerA, handlerB]));
  });

  it('preserves original evidence bytes while remapping resource, signal and fact references', () => {
    const original = evidence('browser-owned', 'observed', { kind: 'resource-ownership', producerId: 'browser-port',
      facts: { observation: 'ownership', resourceId: 'order-102', ownerIdentityId: 'alice', nested: { unchanged: true } },
      artifactRef: 'artifact://ownership/102' });
    const before = JSON.stringify(original);
    const resource: Resource = { id: 'order-102', projectId: project.id, type: 'Order', externalKey: '102',
      ownerIdentityId: 'alice', endpointId: 'observed', evidenceIds: [original.id] };
    const signal: SecuritySignal = { id: 'candidate', projectId: project.id, producerId: 'browser-port', cweIds: ['CWE-639'],
      summary: 'Ownership observation', endpointId: 'observed', evidenceIds: [original.id] };
    const result = buildApplicationSecurityModel({ project,
      identities: [{ id: 'alice', label: 'Alice', authentication: 'session-cookie', roles: ['customer'] }],
      contributions: [source([endpoint('route')]), { source: 'browser', endpoints: [endpoint('observed', '/orders/102')],
        resources: [resource], signals: [signal], evidence: [original], facts: [{ kind: 'ownership', endpointIds: ['observed'],
          evidenceIds: [original.id], details: { resourceId: resource.id, ownerIdentityId: 'alice' } }] }],
    });
    const canonical = result.endpoints[0]!.id;
    expect(JSON.stringify(result.evidence.find(item => item.id === original.id))).toBe(before);
    expect(JSON.stringify(original)).toBe(before);
    expect(result.resources[0]!.endpointId).toBe(canonical);
    expect(result.signals[0]!.endpointId).toBe(canonical);
    expect(result.observedOwnership.length).toBeGreaterThan(0);
    expect(result.observedOwnership.every(item => item.endpointIds.includes(canonical))).toBe(true);
    expect(result.resourceTypes).toContainEqual(expect.objectContaining({ details: expect.objectContaining({ type: 'Order' }) }));
  });

  it('never infers ownership merely because an identity observed an HTTP response', () => {
    const result = buildApplicationSecurityModel({ project,
      identities: [{ id: 'alice', label: 'Alice', authentication: 'session-cookie', roles: ['customer'] }],
      contributions: [source([endpoint('route', '/orders')]), { source: 'runtime', evidence: [
      evidence('response', 'route', { kind: 'http-response', identityId: 'alice', facts: { status: 200 } }),
    ], resources: [{ id: 'order-102', projectId: project.id, type: 'Order', externalKey: '102',
      endpointId: 'route', evidenceIds: ['response'] }] }] });
    expect(result.observedOwnership).toEqual([]);
    expect(result.resources[0]!.ownerIdentityId).toBeUndefined();
  });

  it('retains competing explicitly evidenced owners instead of choosing one', () => {
    const observations = ['alice', 'bob'].map(ownerIdentityId => evidence(`ownership-${ownerIdentityId}`, 'route', {
      kind: 'resource-ownership', facts: { resourceId: 'order-102', ownerIdentityId },
    }));
    const result = buildApplicationSecurityModel({ project,
      identities: ['alice', 'bob'].map(id => ({ id, label: id, authentication: 'session-cookie', roles: ['customer'] })),
      contributions: [source([endpoint('route', '/orders')], { evidence: observations,
        resources: [{ id: 'order-102', projectId: project.id, type: 'Order', externalKey: '102',
          endpointId: 'route', evidenceIds: observations.map(item => item.id) }] })] });
    expect(result.observedOwnership.map(item => item.details.ownerIdentityId).sort()).toEqual(['alice', 'bob']);
    expect(result.diagnostics).toContainEqual(expect.objectContaining({ code: 'conflicting-ownership' }));
  });

  it('deeply freezes detached model data without freezing or retaining input objects', () => {
    const original = structuredClone({ project, contributions: [source([endpoint('route', '/orders', { evidenceIds: ['route-evidence'] })],
      { evidence: [evidence('route-evidence', 'route', { facts: { nested: { value: 'before' } } })] })] });
    const result = buildApplicationSecurityModel(original);
    expect(Object.isFrozen(original)).toBe(false);
    expect(Object.isFrozen(original.project)).toBe(false);
    expect(Object.isFrozen(original.contributions[0]!.endpoints![0])).toBe(false);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.endpoints[0]!.observations[0]!.endpoint.parameters)).toBe(true);
    expect(Object.isFrozen(result.evidence[0]!.facts.nested)).toBe(true);
    expect(() => { (result.endpoints as unknown as Endpoint[]).push(endpoint('mutated')); }).toThrow();
    (original.project as { name: string }).name = 'Changed';
    (original.contributions[0]!.evidence![0]!.facts as { nested: { value: string } }).nested.value = 'after';
    expect(result.project.name).toBe('Shop');
    expect(result.evidence[0]!.facts.nested).toEqual({ value: 'before' });
  });

  it('builds the same canonical model regardless of contribution order', () => {
    const a = source([endpoint('source')], { evidence: [evidence('source-fact', 'source')] });
    const b: ModelContribution = { source: 'runtime', endpoints: [endpoint('runtime', '/orders/102')], evidence: [
      evidence('runtime-fact', 'runtime', { kind: 'http-response', facts: { status: 200 } }),
    ] };
    expect(model(a, b)).toEqual(model(b, a));
  });

  it('rejects malformed references and cross-project records instead of silently rebinding them', () => {
    const invalid: SecurityModelInput[] = [
      { project, contributions: [source([endpoint('route', '/orders', { evidenceIds: ['missing'] })])] },
      { project, contributions: [source([endpoint('route')], { evidence: [evidence('foreign', 'route', { projectId: 'foreign' })] })] },
      { project, contributions: [source([endpoint('route')], { components: [{ ...component, projectId: 'foreign' }] })] },
      { project, contributions: [source([endpoint('route')], { resources: [{ id: 'foreign', projectId: 'foreign', type: 'Order',
        externalKey: '102', evidenceIds: [] }] })] },
      { project, contributions: [source([endpoint('route')], { signals: [{ id: 'foreign', projectId: 'foreign', producerId: 'adapter',
        summary: 'Foreign record', cweIds: ['CWE-639'], evidenceIds: [] }] })] },
      { project, contributions: [source([endpoint('route')], { evidence: [evidence('orphan', 'absent')] })] },
      { project, contributions: [source([endpoint('route')], { endpointOrigins: { route: 'not an origin' } })] },
    ];
    for (const input of invalid) expect(() => buildApplicationSecurityModel(input)).toThrow();
  });

  it('adapts existing public contracts without framework syntax or proprietary objects', () => {
    const analysis = { components: [component], endpoints: [endpoint('route')], resources: [], signals: [], evidence: [] };
    expect(fromFrameworkAnalysis(analysis).source).toBe('source');
    expect(fromStaticAnalysis({ signals: [], evidence: [] }).source).toBe('source');
    expect(fromBrowserObservation(analysis).source).toBe('browser');
    const context: AnalysisContext = { project, ...analysis, identities: [] };
    expect(fromAnalysisContext(context).source).toBe('declared');
    expect(model(fromFrameworkAnalysis(analysis)).endpoints).toHaveLength(1);
  });
});

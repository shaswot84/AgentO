import { describe, expect, it } from 'vitest';
import type { Evidence, Resource } from '@agento/core';
import type { ModelContribution, ModelDiagnostic, ModelFactKind } from '../src/contracts.js';
import { projectFacts } from '../src/projections.js';

function ownership(id: string, resourceId: string, ownerIdentityId: string): Evidence {
  return { id, projectId: 'project', kind: 'resource-ownership', producerId: 'observer',
    capturedAt: '2026-10-18T00:00:00.000Z', summary: 'Explicit ownership observation.',
    facts: { resourceId, ownerIdentityId } };
}

function resource(ownerIdentityId: string, evidenceIds: readonly string[]): Resource {
  return { id: 'order-102', projectId: 'project', type: 'Order', externalKey: '102', ownerIdentityId, evidenceIds };
}

describe('fact projection lineage', () => {
  it.each([
    ['another resource', 'order-103', 'alice'],
    ['another owner', 'order-102', 'bob'],
  ])('does not attribute evidence naming %s to the resource owner assertion', (_label, resourceId, ownerIdentityId) => {
    const proof = ownership('ownership', resourceId, ownerIdentityId);
    const asserted = resource('alice', [proof.id]);
    const before = structuredClone(asserted);
    const diagnostics: ModelDiagnostic[] = [];
    const result = projectFacts([{ source: 'browser', resources: [asserted], evidence: [proof] }],
      [], [asserted], [proof], {}, diagnostics);
    expect(result.observedOwnership).not.toContainEqual(expect.objectContaining({
      details: expect.objectContaining({ resourceId: asserted.id, ownerIdentityId: asserted.ownerIdentityId }),
    }));
    expect(diagnostics).toContainEqual({ code: 'missing-ownership-evidence', entityIds: [asserted.id] });
    expect(asserted).toEqual(before);
    expect(result.observedOwnership).toContainEqual(expect.objectContaining({
      evidenceIds: [proof.id], details: { resourceId, ownerIdentityId },
    }));
  });

  it('uses only consistent ownership evidence when a resource lists mixed observations', () => {
    const matching = ownership('matching', 'order-102', 'alice');
    const unrelated = ownership('unrelated', 'order-103', 'bob');
    const asserted = resource('alice', [matching.id, unrelated.id]);
    const result = projectFacts([{ source: 'browser', resources: [asserted], evidence: [matching, unrelated] }],
      [], [asserted], [matching, unrelated], {}, []);
    const ownerFacts = result.observedOwnership.filter(fact => fact.details.resourceId === asserted.id);
    expect(ownerFacts).toHaveLength(1);
    expect(ownerFacts[0]!.evidenceIds).toEqual([matching.id]);
    expect(result.resourceTypes[0]!.evidenceIds).toEqual([matching.id, unrelated.id]);
  });

  it('keeps source provenance attached to each distinct resource assertion sharing an ID', () => {
    const aliceProof = ownership('alice-proof', 'order-102', 'alice');
    const bobProof = ownership('bob-proof', 'order-102', 'bob');
    const alice = resource('alice', [aliceProof.id]);
    const bob = resource('bob', [bobProof.id]);
    const contributions: ModelContribution[] = [
      { source: 'browser', resources: [alice], evidence: [aliceProof] },
      { source: 'runtime', resources: [bob], evidence: [bobProof] },
    ];
    const diagnostics: ModelDiagnostic[] = [];
    const result = projectFacts(contributions, [], [alice, bob], [aliceProof, bobProof], {}, diagnostics);
    expect(result.observedOwnership).toHaveLength(2);
    expect(result.observedOwnership.map(fact => [fact.details.ownerIdentityId, fact.source]).sort()).toEqual([
      ['alice', 'browser'], ['bob', 'runtime'],
    ]);
    expect(result.resourceTypes.map(fact => [fact.evidenceIds, fact.source]).sort()).toEqual([
      [['alice-proof'], 'browser'], [['bob-proof'], 'runtime'],
    ]);
    expect(diagnostics).toContainEqual({ code: 'conflicting-ownership', entityIds: ['order-102', 'alice', 'bob'] });
    expect(projectFacts([...contributions].reverse(), [], [bob, alice], [bobProof, aliceProof], {}, []))
      .toEqual(result);
  });

  it.each<ModelFactKind>(['ownership', 'data-flow', 'database-operation', 'cookie', 'cors'])
    ('rejects an explicit %s fact with no evidence', kind => {
      expect(() => projectFacts([{ source: 'declared', facts: [{ kind, evidenceIds: [],
        details: { resourceId: 'order-102', ownerIdentityId: 'alice' } }] }], [], [], [], {}, []))
        .toThrow(/require at least one evidence reference/);
    });

  it('retains an explicitly declared resource type without manufacturing evidence', () => {
    const declared = { id: 'order-102', projectId: 'project', type: 'Order', externalKey: '102', evidenceIds: [] };
    const result = projectFacts([{ source: 'declared', resources: [declared] }], [], [declared], [], {}, []);
    expect(result.resourceTypes).toEqual([expect.objectContaining({ source: 'declared', evidenceIds: [],
      details: { resourceId: declared.id, type: declared.type, externalKey: declared.externalKey } })]);
  });
});

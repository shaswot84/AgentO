import { createHash } from 'node:crypto';
import type { InvestigationSnapshot, SecurityModelSnapshot } from '../src/client/types.ts';

export interface RetainedInvestigation {
  readonly fingerprint: string;
  readonly snapshot: InvestigationSnapshot;
}

export function modelFingerprint(source: SecurityModelSnapshot): string {
  return createHash('sha256').update(JSON.stringify([source.model, source.inputs, source.state])).digest('hex');
}

async function modules() {
  const [rules, hypotheses, plans] = await Promise.all([
    import('../../../plugins/cwe/dist/index.js'),
    import('../../../packages/hypothesis-engine/dist/index.js'),
    import('../../../packages/test-planner/dist/index.js'),
  ]);
  const plugins = [new rules.CWE79Plugin(), new rules.CWE89Plugin(), new rules.CWE639Plugin(),
    new rules.CWE862Plugin(), new rules.CWE942Plugin(), new rules.CWE1004Plugin(), new rules.CWE614Plugin()];
  return { plugins, engine: new hypotheses.SecurityHypothesisEngine({ plugins }), planner: new plans.SecurityTestPlanner({ plugins }) };
}

export async function emptyInvestigation(source: SecurityModelSnapshot): Promise<InvestigationSnapshot> {
  let coverage: InvestigationSnapshot['coverage'] = [];
  try {
    const { plugins } = await modules();
    coverage = plugins.map(plugin => {
      const { cweId, title, probeId, requiredCapabilities, optionalCapabilities } = plugin.metadata();
      return { cweId, title, probeId, requiredCapabilities, optionalCapabilities };
    });
  } catch {
    return { projectId: source.projectId, sourceType: source.sourceType, state: 'unavailable',
      generatedAt: null, sourceUpdatedAt: source.updatedAt, sourceState: source.state, hypotheses: [], plans: [], coverage: [],
      diagnostics: ['planning-packages-unavailable'], modelReview: 'disabled', execution: 'not-configured' };
  }
  return { projectId: source.projectId, sourceType: source.sourceType, state: 'empty', generatedAt: null,
    sourceUpdatedAt: source.updatedAt, sourceState: source.state, hypotheses: [], plans: [], coverage,
    diagnostics: [], modelReview: 'disabled', execution: 'not-configured' };
}

/** Runs pure analysis against retained observations. No model calls or target requests. */
export async function generateInvestigation(source: SecurityModelSnapshot, onHypotheses?: (count: number) => Promise<void>): Promise<RetainedInvestigation> {
  const { plugins, engine, planner } = await modules();
  const result = await engine.generate(source.model);
  await onHypotheses?.(result.hypotheses.length);
  const coverage = plugins.map(plugin => {
    const { cweId, title, probeId, requiredCapabilities, optionalCapabilities } = plugin.metadata();
    return { cweId, title, probeId, requiredCapabilities, optionalCapabilities };
  });
  const catalog = new Map(coverage.map(item => [item.cweId as string, item]));
  const evidence = new Map(source.model.evidence.map(item => [item.id, item]));
  const diagnostics = new Set<string>(result.diagnostics.map(item => item.code));
  const plans: InvestigationSnapshot['plans'][number][] = [];
  for (const hypothesis of result.hypotheses) {
    if (plans.length >= 200) { diagnostics.add('plan-limit'); break; }
    const planned = await planner.plan(source.model, hypothesis);
    planned.diagnostics.forEach(item => diagnostics.add(item.code));
    for (const plan of planned.plans) {
      if (plans.length >= 200) { diagnostics.add('plan-limit'); break; }
      plans.push({ id: plan.id, hypothesisId: plan.hypothesisId, cweId: plan.cweId,
        title: catalog.get(plan.cweId)?.title ?? plan.cweId, probeId: plan.probeId, readiness: plan.readiness,
        ...(plan.scope.parameter ? { testedInput: { name: plan.scope.parameter.name, location: plan.scope.parameter.location } } : {}),
        prerequisites: plan.prerequisites.map(item => ({ code: item.code, ...(item.parameter ? { parameter: { name: item.parameter.name, location: item.parameter.location } } : {}) })),
        requiredCapabilities: [...plan.requiredCapabilities], optionalCapabilities: [...plan.optionalCapabilities],
        steps: plan.steps.map(({ id, action, dependsOn, expectedObservation }) => ({ id, action, dependsOn: [...dependsOn], expectedObservation })),
        verification: { strategy: plan.verification.strategy, evidenceRequirements: [...plan.verification.evidenceRequirements] },
        limitations: [...plan.limitations], execution: 'not-run' });
    }
  }
  const hypotheses: InvestigationSnapshot['hypotheses'] = result.hypotheses.map(item => {
    const endpoint = source.model.endpoints.find(endpoint => endpoint.id === item.endpointId || endpoint.aliases.includes(item.endpointId ?? ''));
    return { id: item.id, cweId: item.cweId, title: catalog.get(item.cweId)?.title ?? item.cweId, reason: item.reason,
      origin: item.origin, endpoint: endpoint ? { method: endpoint.method, path: endpoint.path } : null,
      supports: item.rationale.map(support => ({ statement: support.statement, evidenceIds: [...support.evidenceIds] })),
      evidence: item.evidenceIds.flatMap(id => {
        const record = evidence.get(id);
        return record ? [{ id: record.id, kind: record.kind, producerId: record.producerId, capturedAt: record.capturedAt, summary: record.summary }] : [];
      }), limitations: [...item.limitations] };
  });
  return { fingerprint: modelFingerprint(source), snapshot: {
    projectId: source.projectId, sourceType: source.sourceType,
    state: source.state === 'stale' ? 'stale' : diagnostics.size || source.state === 'partial' ? 'partial' : source.state === 'empty' ? 'empty' : 'ready',
    generatedAt: new Date().toISOString(), sourceUpdatedAt: source.updatedAt, sourceState: source.state,
    hypotheses, plans, coverage, diagnostics: [...diagnostics], modelReview: 'disabled', execution: 'not-configured',
  } };
}

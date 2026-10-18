import type { Identity } from '@agento/core';
import type { ModelContribution } from '@agento/security-model';
import { buildApplicationSecurityModel } from '../../../packages/security-model/src/builder.ts';
import { fromBrowserObservation } from '../../../packages/security-model/src/contributions.ts';
import type { SecurityModelInputSummary, SecurityModelSnapshot } from '../src/client/types.ts';
import type { ProjectRecord } from './workspace.ts';

export interface RetainedModelSource {
  readonly version: 1;
  readonly scanId: string;
  readonly capturedAt: string;
  readonly status: 'completed' | 'partial' | 'failed' | 'skipped';
  readonly targetUrl: string;
  readonly repositoryPath: string;
  readonly allowedOrigins: readonly string[];
  readonly diagnostics: readonly { readonly code: string; readonly message: string }[];
  readonly contributions: readonly ModelContribution[];
}

/** Reconstructs from retained public observations only. Reading the model never runs a target or tool. */
export function securityModelFor(record: ProjectRecord): SecurityModelSnapshot {
  const { project } = record;
  let contributions: ModelContribution[] = [];
  let identities: Identity[] = [];
  let model = buildApplicationSecurityModel({ project });
  const inputs: SecurityModelInputSummary[] = [];
  const diagnostics: { code: string; message: string }[] = [];
  const accept = (next: readonly ModelContribution[], personas: readonly Identity[]) => {
    // Conflicting identity declarations cannot silently overwrite a different profile's persona.
    const known = new Map(identities.map(item => [item.id, item]));
    for (const persona of personas) {
      const previous = known.get(persona.id);
      if (previous && JSON.stringify(previous) !== JSON.stringify(persona)) throw new Error('Conflicting persona');
      known.set(persona.id, persona);
    }
    const combined = [...contributions, ...next], people = [...known.values()];
    const candidate = buildApplicationSecurityModel({ project, identities: people, contributions: combined });
    contributions = combined; identities = people; model = candidate;
  };
  if (record.modelSource) {
    const source = record.modelSource;
    let included = false;
    try {
      if (source.targetUrl !== project.baseUrl || source.repositoryPath !== project.repositoryPath
        || JSON.stringify([...source.allowedOrigins].sort()) !== JSON.stringify([...project.allowedOrigins].sort())) throw new Error('Source project binding changed');
      accept(source.contributions, []); included = true;
    }
    catch { diagnostics.push({ code: 'source-model-invalid', message: 'Retained source observations could not be merged. Run a new static scan to refresh them.' }); }
    inputs.push({ runId: source.scanId, source: 'source', capturedAt: source.capturedAt, outcome: source.status, included });
    if (source.status !== 'completed') diagnostics.push({ code: 'source-model-partial', message: 'The source scan was incomplete. Retained observations describe partial coverage.' });
    diagnostics.push(...source.diagnostics);
  } else if (record.scan) diagnostics.push({ code: 'source-model-missing', message: 'This scan has no retained application model. Run a new static scan to collect the full source context.' });
  else diagnostics.push({ code: 'source-model-missing', message: 'No source scan has contributed an application model yet.' });

  // Oldest first keeps a conflicting later observation from displacing an already included run.
  for (const result of [...(record.workflows ?? [])].sort((a, b) => a.executedAt.localeCompare(b.executedAt) || a.id.localeCompare(b.id))) {
    let included = false;
    try {
      if (result.projectId !== project.id || result.sourceType !== 'execution-api'
        || new URL(result.targetUrl).origin !== new URL(project.baseUrl).origin) throw new Error('Incompatible workflow');
      accept([fromBrowserObservation({ endpoints: result.endpoints, resources: result.resources ?? [],
        signals: result.signals ?? [], evidence: result.evidence })], result.identities ?? []);
      included = true;
    } catch { diagnostics.push({ code: 'workflow-model-invalid', message: `Workflow ${result.id} could not contribute to this model. Its original result remains available in Workflows. Run the workflow again to capture compatible model observations.` }); }
    inputs.push({ runId: result.id, source: 'browser', capturedAt: result.executedAt, outcome: result.outcome, included });
    if (included && result.outcome !== 'COMPLETED') diagnostics.push({ code: 'workflow-model-partial', message: `Workflow ${result.id} ${result.outcome.toLowerCase()}; any retained observations are partial.` });
  }
  if (!(record.workflows?.length)) diagnostics.push({ code: 'browser-model-missing', message: 'No browser workflow has contributed runtime observations yet.' });
  const stale = !!record.modelSource && !!record.scan && record.modelSource.scanId !== record.scan.id;
  if (stale) diagnostics.push({ code: 'source-model-stale', message: 'Source context is from an earlier scan. The latest scan has not replaced it; review run times before combining observations.' });
  const included = inputs.filter(item => item.included);
  const updatedAt = included.map(item => item.capturedAt).sort().at(-1) ?? null;
  return { projectId: project.id, sourceType: 'execution-api',
    state: stale ? 'stale' : !included.length ? 'empty' : diagnostics.length ? 'partial' : 'ready',
    updatedAt, inputs, diagnostics, model };
}

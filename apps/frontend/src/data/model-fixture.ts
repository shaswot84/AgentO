import type { ApplicationSecurityModel } from '@agento/security-model';
import type { ProjectSummary, SecurityModelSnapshot } from '../client/types.ts';
import fixture from './demo-security-model.json' with { type: 'json' };

/** Generated from explicitly synthetic observations; this never represents a live scan. */
export const demoSecurityModel = fixture as unknown as SecurityModelSnapshot;

export function emptySecurityModel(project: ProjectSummary): SecurityModelSnapshot {
  const model: ApplicationSecurityModel = { schemaVersion: 1, project, components: [], endpoints: [], identities: [],
    resources: [], signals: [], evidence: [], endpointAliases: {}, parameters: [], authenticationRequirements: [],
    userRoles: [], sourceHandlers: [], resourceTypes: [], observedOwnership: [], dataFlows: [], databaseOperations: [],
    cookies: [], corsConfigurations: [], runtimeObservations: [], diagnostics: [] };
  return { projectId: project.id, sourceType: 'demo-fixture', state: 'empty', updatedAt: null,
    model, inputs: [], diagnostics: [] };
}

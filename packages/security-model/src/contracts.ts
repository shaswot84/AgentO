import type {
  AnalysisContext, Component, Endpoint, Evidence, Identity, JsonValue, Project,
  Resource, SecuritySignal, SourceLocation,
} from '@agento/core';

export type KnowledgeSource = 'source' | 'browser' | 'runtime' | 'declared';
export type ModelFactKind = 'resource-type' | 'ownership' | 'data-flow' | 'database-operation' | 'cookie' | 'cors';

/** Adapter-neutral facts. Values describe observations, never security verdicts. */
export interface ModelFactInput {
  readonly kind: ModelFactKind;
  readonly endpointIds?: readonly string[];
  readonly evidenceIds: readonly string[];
  readonly details: Readonly<Record<string, JsonValue>>;
}

/** A contribution contains normalized public observations, never private runtime sessions. */
export interface ModelContribution {
  readonly source: KnowledgeSource;
  readonly components?: readonly Component[];
  readonly endpoints?: readonly Endpoint[];
  readonly resources?: readonly Resource[];
  readonly signals?: readonly SecuritySignal[];
  readonly evidence?: readonly Evidence[];
  /** Explicit origin binding when an endpoint path alone is insufficient. */
  readonly endpointOrigins?: Readonly<Record<string, string>>;
  readonly facts?: readonly ModelFactInput[];
}

export interface SecurityModelInput {
  readonly project: Project;
  readonly identities?: readonly Identity[];
  readonly contributions?: readonly ModelContribution[];
}

export interface EndpointObservation {
  readonly source: KnowledgeSource;
  readonly origin: string;
  readonly endpoint: Endpoint;
}

export interface ModelEndpoint extends Endpoint {
  readonly origin: string;
  readonly aliases: readonly string[];
  readonly componentIds: readonly string[];
  /** Retains competing requirements and parameter declarations without overwriting them. */
  readonly observations: readonly EndpointObservation[];
}

export interface ModelFact extends ModelFactInput {
  readonly id: string;
  readonly source: KnowledgeSource;
  readonly endpointIds: readonly string[];
}

export interface ModelParameter {
  readonly endpointId: string;
  readonly name: string;
  readonly location: Endpoint['parameters'][number]['location'];
  /** Unknown when providers disagree. Runtime presence does not establish requiredness. */
  readonly required: boolean | null;
  readonly evidenceIds: readonly string[];
}

export interface AuthenticationRequirement {
  readonly endpointId: string;
  readonly requirement: Endpoint['authentication'];
  readonly roles: readonly string[];
  readonly source: KnowledgeSource;
  readonly evidenceIds: readonly string[];
}

export interface UserRole {
  readonly name: string;
  readonly identityIds: readonly string[];
  readonly endpointIds: readonly string[];
  readonly evidenceIds: readonly string[];
}

export interface SourceHandler {
  readonly endpointId: string;
  readonly source: SourceLocation;
  readonly evidenceIds: readonly string[];
}

export interface ModelDiagnostic {
  readonly code: 'ambiguous-endpoint' | 'conflicting-authentication' | 'conflicting-parameter'
    | 'conflicting-ownership' | 'unbound-endpoint' | 'missing-ownership-evidence';
  readonly entityIds: readonly string[];
}

/** Original evidence is copied unchanged; aliases resolve provider endpoint IDs. */
export interface ApplicationSecurityModel extends AnalysisContext {
  readonly schemaVersion: 1;
  readonly endpoints: readonly ModelEndpoint[];
  readonly endpointAliases: Readonly<Record<string, string>>;
  readonly parameters: readonly ModelParameter[];
  readonly authenticationRequirements: readonly AuthenticationRequirement[];
  readonly userRoles: readonly UserRole[];
  readonly sourceHandlers: readonly SourceHandler[];
  readonly resourceTypes: readonly ModelFact[];
  readonly observedOwnership: readonly ModelFact[];
  readonly dataFlows: readonly ModelFact[];
  readonly databaseOperations: readonly ModelFact[];
  readonly cookies: readonly ModelFact[];
  readonly corsConfigurations: readonly ModelFact[];
  readonly runtimeObservations: readonly Evidence[];
  readonly diagnostics: readonly ModelDiagnostic[];
}

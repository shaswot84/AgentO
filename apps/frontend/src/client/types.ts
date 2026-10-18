import type { Endpoint, Evidence, Finding, Project, RemediationSuggestion } from '@agento/core';
import type { DiscoveryResult } from '@agento/discovery';

export interface ProjectInput {
  readonly name: string;
  readonly repositoryPath: string;
  readonly baseUrl: string;
  readonly allowedOrigins: readonly string[];
}

export type ProjectInputErrors = Partial<Record<keyof ProjectInput, string>>;

export interface ProjectSummary extends Project {
  readonly dataSource: 'demo-fixture' | 'saved-discovery' | 'project-input';
  readonly createdAt: string;
  readonly scanState?: ScanSnapshot['state'];
}

export interface ScanStage {
  readonly id: string;
  readonly label: string;
  readonly status: 'complete' | 'pending' | 'running' | 'failed' | 'unavailable';
  readonly details: string;
}

export interface ScanSnapshot {
  readonly id: string;
  readonly projectId: string;
  readonly source: 'demo-fixture' | 'execution-api';
  readonly state: 'pending' | 'running' | 'complete' | 'failed';
  readonly stages: readonly ScanStage[];
  readonly summary: string;
  readonly completedAt?: string;
  readonly diagnostics?: readonly { readonly code: string; readonly message: string }[];
}

export interface FindingDetail extends Finding {
  readonly sourceType: 'demo-fixture' | 'execution-api';
  readonly evidence: readonly Evidence[];
  readonly endpoint?: Endpoint;
  readonly remediation: RemediationSuggestion;
}

/** Browser-facing contract; repository access and execution stay on the host. */
export interface AgentOClient {
  readonly storage: 'disk' | 'memory';
  listProjects(): Promise<readonly ProjectSummary[]>;
  getProject(projectId: string): Promise<ProjectSummary>;
  createProject(input: ProjectInput, discovery?: DiscoveryResult): Promise<ProjectSummary>;
  importDiscovery(projectId: string, discovery: DiscoveryResult): Promise<ProjectSummary>;
  getDiscovery(projectId: string): Promise<DiscoveryResult>;
  getScan(projectId: string): Promise<ScanSnapshot>;
  startScan(projectId: string): Promise<ScanSnapshot>;
  getFindings(projectId: string): Promise<readonly FindingDetail[]>;
  getFinding(projectId: string, findingId: string): Promise<FindingDetail>;
}

export type ClientErrorCode = 'INVALID_INPUT' | 'INVALID_DISCOVERY' | 'PROJECT_NOT_FOUND'
  | 'DISCOVERY_UNAVAILABLE' | 'SCAN_UNAVAILABLE' | 'FINDING_NOT_FOUND' | 'CLIENT_UNAVAILABLE'
  | 'SCAN_IN_PROGRESS' | 'REQUEST_FORBIDDEN';

export class AgentOClientError extends Error {
  constructor(readonly code: ClientErrorCode, message: string) {
    super(message);
    this.name = 'AgentOClientError';
  }
}

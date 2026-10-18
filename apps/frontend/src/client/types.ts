import type { Endpoint, Evidence, Finding, Identity, Project, RemediationSuggestion, Resource, SecuritySignal } from '@agento/core';
import type { DiscoveryResult } from '@agento/discovery';
import type { ApplicationSecurityModel } from '@agento/security-model';
import type { InvestigationSnapshot } from './investigation.ts';
export type * from './investigation.ts';

export interface SecurityModelInputSummary {
  readonly runId: string;
  readonly source: 'source' | 'browser';
  readonly capturedAt: string;
  readonly outcome: string;
  readonly included: boolean;
}

export interface SecurityModelSnapshot {
  readonly projectId: string;
  readonly sourceType: 'demo-fixture' | 'execution-api';
  readonly state: 'empty' | 'ready' | 'partial' | 'stale';
  readonly updatedAt: string | null;
  readonly model: ApplicationSecurityModel;
  readonly inputs: readonly SecurityModelInputSummary[];
  readonly diagnostics: readonly { readonly code: string; readonly message: string }[];
}

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

export interface ObservedNetworkTraffic {
  readonly url: string;
  readonly method: string;
  readonly status: number | null;
  readonly resourceType: string;
  readonly blocked: boolean;
  readonly blockedReason?: 'origin-scope' | 'popup-unsupported' | 'worker-unsupported' | 'websocket-unsupported';
  readonly initiatingPage?: string;
  readonly timestamp?: string;
  readonly headers?: Readonly<Record<string, string>>;
}

export interface WorkflowStepRecord {
  readonly pageId?: string;
  readonly actionType: string;
  readonly outcome: 'completed' | 'failed' | 'rejected';
  readonly url?: string;
  readonly selector?: string;
  readonly code?: string;
  readonly details?: string;
}

export interface BrowserWorkflowResult {
  readonly id: string;
  readonly projectId: string;
  readonly goal: string;
  readonly identityId: string;
  readonly personaLabel?: string;
  readonly targetUrl: string;
  readonly outcome: 'COMPLETED' | 'FAILED' | 'SKIPPED';
  readonly completionType?: string;
  readonly durationMs?: number;
  readonly actionsCount: number;
  readonly recoveryAttempts?: number;
  readonly modelCalls?: number;
  readonly modelTokens?: number;
  readonly finalUrl?: string;
  readonly sourceType: 'demo-fixture' | 'execution-api';
  readonly executedAt: string;
  readonly endpoints: readonly Endpoint[];
  readonly resources?: readonly Resource[];
  readonly signals?: readonly SecuritySignal[];
  /** Public persona declarations only; excludes backend credentials and session material. */
  readonly identities?: readonly Identity[];
  readonly network: readonly ObservedNetworkTraffic[];
  readonly steps?: readonly WorkflowStepRecord[];
  readonly session?: {
    readonly personaId: string;
    readonly authenticated: boolean;
    readonly reused: boolean;
    readonly sessionRef?: string;
    readonly targetId?: string;
  };
  readonly pageModelSummary?: {
    readonly title: string;
    readonly headings: readonly string[];
    readonly interactiveElementCount: number;
  };
  readonly diagnostics: readonly { readonly code: string; readonly message: string }[];
  readonly evidence: readonly Evidence[];
}

export interface BrowserWorkflowInput {
  readonly goal: string;
  readonly identityId?: string;
  readonly targetName?: string;
  readonly planningMode?: 'automatic' | 'recipes';
}

/** Browser-facing contract; repository access and execution stay on the host. */
export interface AgentOClient {
  readonly storage: 'disk' | 'memory';
  listProjects(): Promise<readonly ProjectSummary[]>;
  getProject(projectId: string): Promise<ProjectSummary>;
  createProject(input: ProjectInput, discovery?: DiscoveryResult): Promise<ProjectSummary>;
  importDiscovery(projectId: string, discovery: DiscoveryResult): Promise<ProjectSummary>;
  getDiscovery(projectId: string): Promise<DiscoveryResult>;
  getSecurityModel(projectId: string): Promise<SecurityModelSnapshot>;
  getInvestigation(projectId: string): Promise<InvestigationSnapshot>;
  refreshInvestigation(projectId: string): Promise<InvestigationSnapshot>;
  getScan(projectId: string): Promise<ScanSnapshot>;
  startScan(projectId: string): Promise<ScanSnapshot>;
  deleteProject(projectId: string): Promise<void>;
  getFindings(projectId: string): Promise<readonly FindingDetail[]>;
  getFinding(projectId: string, findingId: string): Promise<FindingDetail>;
  getWorkflows(projectId: string): Promise<readonly BrowserWorkflowResult[]>;
  getWorkflow(projectId: string, workflowId: string): Promise<BrowserWorkflowResult>;
  runWorkflow(projectId: string, input: BrowserWorkflowInput): Promise<BrowserWorkflowResult>;
}

export type ClientErrorCode = 'INVALID_INPUT' | 'INVALID_DISCOVERY' | 'PROJECT_NOT_FOUND'
  | 'DISCOVERY_UNAVAILABLE' | 'SCAN_UNAVAILABLE' | 'FINDING_NOT_FOUND' | 'CLIENT_UNAVAILABLE'
  | 'SCAN_IN_PROGRESS' | 'REQUEST_FORBIDDEN' | 'WORKFLOW_NOT_FOUND' | 'WORKFLOW_FAILED';

export class AgentOClientError extends Error {
  constructor(readonly code: ClientErrorCode, message: string) {
    super(message);
    this.name = 'AgentOClientError';
  }
}


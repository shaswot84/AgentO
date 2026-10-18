import { AgentOClientError } from './types';
import type { AgentOClient, ClientErrorCode } from './types';

const codes: readonly ClientErrorCode[] = ['INVALID_INPUT', 'INVALID_DISCOVERY', 'PROJECT_NOT_FOUND',
  'DISCOVERY_UNAVAILABLE', 'SCAN_UNAVAILABLE', 'FINDING_NOT_FOUND', 'CLIENT_UNAVAILABLE',
  'SCAN_IN_PROGRESS', 'REQUEST_FORBIDDEN', 'WORKFLOW_NOT_FOUND', 'WORKFLOW_FAILED'];

/** No fixture fallback: service failures remain visible to the user. */
export function createHttpClient(transport: typeof fetch = (...args) => fetch(...args)): AgentOClient {
  async function request<T>(path: string, body?: unknown): Promise<T> {
    try {
      const response = await transport(`/api/projects${path}`, body === undefined ? {} : {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      });
      const value = await response.json() as { ok?: boolean; data?: T; error?: string; code?: ClientErrorCode };
      if (!response.ok || value.ok !== true || value.data === undefined) {
        const code = value.code && codes.includes(value.code) ? value.code : 'CLIENT_UNAVAILABLE';
        throw new AgentOClientError(code, value.error ?? 'The local workspace service is unavailable.');
      }
      return value.data;
    } catch (error) {
      if (error instanceof AgentOClientError) throw error;
      throw new AgentOClientError('CLIENT_UNAVAILABLE', 'Cannot connect to the local workspace service. Start the frontend with npm run dev or npm run preview.');
    }
  }
  const projectPath = (id: string) => `/${encodeURIComponent(id)}`;
  return {
    storage: 'disk',
    listProjects: () => request(''),
    getProject: id => request(projectPath(id)),
    createProject: (input, discovery) => request('', { input, discovery }),
    importDiscovery: (id, discovery) => request(`${projectPath(id)}/discovery`, { discovery }),
    getDiscovery: id => request(`${projectPath(id)}/discovery`),
    startScan: id => request(`${projectPath(id)}/scan`, {}),
    getScan: id => request(`${projectPath(id)}/scan`),
    getFindings: id => request(`${projectPath(id)}/findings`),
    getFinding: (id, findingId) => request(`${projectPath(id)}/findings/${encodeURIComponent(findingId)}`),
    getWorkflows: id => request(`${projectPath(id)}/workflows`),
    getWorkflow: (id, workflowId) => request(`${projectPath(id)}/workflows/${encodeURIComponent(workflowId)}`),
    runWorkflow: (id, input) => request(`${projectPath(id)}/workflows`, input),
  };
}


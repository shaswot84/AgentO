/** Public fixture metadata only. Authentication and model configuration stay on the host. */
export const workflowProfiles = [
  { id: 'storefront', label: 'Storefront (REST & Cookies)',
    personas: [{ id: 'alice', label: 'Alice' }, { id: 'bob', label: 'Bob' }, { id: 'admin', label: 'Admin' }],
    recipeGoals: ['open orders', 'open newest order'],
    suggestedGoal: 'Explore my order history and inspect my newest order.' },
  { id: 'purchases', label: 'Purchases (JWT)',
    personas: [{ id: 'buyer-one', label: 'BuyerOne' }, { id: 'buyer-two', label: 'BuyerTwo' }, { id: 'manager', label: 'Manager' }],
    recipeGoals: ['open newest order', 'open latest purchase'],
    suggestedGoal: 'Find my purchase history and open the latest purchase.' },
  { id: 'portal', label: 'Portal (MPA & CSRF)',
    personas: [{ id: 'analyst', label: 'Analyst' }, { id: 'admin', label: 'Administrator' }],
    recipeGoals: ['open newest order', 'open latest report', 'open audit report'],
    suggestedGoal: 'Find the audit reports and open the latest report.' },
  { id: 'edge-spa', label: 'Edge SPA (Strict Scope)',
    personas: [{ id: 'operator', label: 'Operator' }, { id: 'supervisor', label: 'Supervisor' }],
    recipeGoals: ['open newest order', 'open latest telemetry', 'open telemetry report'],
    suggestedGoal: 'Explore the workspace and load the latest telemetry.' },
  { id: 'ops-console', label: 'Cloud Ops Console',
    personas: [{ id: 'responder', label: 'Incident Responder' }, { id: 'commander', label: 'Incident Commander' }],
    recipeGoals: [],
    suggestedGoal: 'Find the security incidents and inspect the highest priority incident.' },
];

export function workflowNotification(workflow: { outcome: string; goal: string; diagnostics: readonly { message: string }[] }): string {
  const label = workflow.outcome === 'COMPLETED' ? 'completed' : workflow.outcome === 'SKIPPED' ? 'skipped' : 'failed';
  return `Workflow ${label}: ${workflow.goal}${workflow.outcome !== 'COMPLETED' && workflow.diagnostics[0] ? ` — ${workflow.diagnostics[0].message}` : ''}`;
}

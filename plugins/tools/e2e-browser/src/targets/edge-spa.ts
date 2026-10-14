import type {
  AuthenticationPreparation,
  AuthenticationStrategy,
  Persona,
  TargetApplicationProfile,
  WorkflowDecision,
  WorkflowPlanner,
  WorkflowPlannerInput,
} from '@agento/core';
import { FormLoginStrategy } from '../authentication.js';
import type { TesterArmyE2EOptions } from '../types.js';

export const EDGE_SPA_PERSONAS: readonly Persona[] = Object.freeze([
  { id: 'operator', label: 'Operator', roles: ['operator'], authentication: 'jwt', credentialsRef: 'edge:operator', expectedRole: 'operator' },
  { id: 'supervisor', label: 'Supervisor', roles: ['supervisor'], authentication: 'jwt', credentialsRef: 'edge:supervisor', expectedRole: 'supervisor' },
]);

/** Custom declarative multi-step authentication strategy */
export class EdgeMultiStepStrategy implements AuthenticationStrategy {
  readonly id = 'edge-multi-step';

  prepare(persona: Persona): AuthenticationPreparation {
    return {
      verification: {
        url: '/workspace',
        identitySelector: '#user-account',
        expectedIdentity: persona.id,
        role: { selector: '#user-role', expected: persona.expectedRole! },
      },
      actions: [
        { action: 'navigate', url: '/login' },
        { action: 'fill-credential', selector: '#identifier', field: 'username' },
        { action: 'click', selector: '#btn-next', response: { url: '/api/auth/lookup*', method: 'GET', status: 200 } },
        { action: 'wait-visible', selector: '#password' },
        { action: 'fill-credential', selector: '#password', field: 'password' },
        { action: 'click', selector: '#btn-submit', response: { url: '/api/auth/login', method: 'POST', status: 200 } },
        { action: 'wait-visible', selector: '#workspace-section' },
      ],
    };
  }
}

export function createEdgeSpaProfile(
  baseOrigins: readonly string[],
  id = 'edge-spa',
  defaultStrategy: 'edge-multi-step' | 'edge-single-step' = 'edge-multi-step'
): TargetApplicationProfile {
  return {
    id,
    baseOrigins: [...baseOrigins],
    personas: EDGE_SPA_PERSONAS,
    authentication: [
      new EdgeMultiStepStrategy(),
      // Standard single-step strategy provided for testing multi-step failure boundaries
      new FormLoginStrategy({
        loginUrl: '/login',
        usernameSelector: '#identifier',
        passwordSelector: '#password',
        submitSelector: '#btn-submit',
        response: { url: '/api/auth/login', method: 'POST', status: 200 },
        verification: persona => ({
          url: '/workspace',
          identitySelector: '#user-account',
          expectedIdentity: persona.id,
          role: { selector: '#user-role', expected: persona.expectedRole! },
        }),
      }, 'edge-single-step'),
    ],
    defaultAuthenticationStrategyId: defaultStrategy,
    workflowHints: {
      loadLabel: 'Open latest telemetry',
      completeLabel: 'Telemetry loaded',
      itemUrl: '/api/telemetry/*',
      statusSelector: '#telemetry-status',
    },
  };
}

export class EdgeSpaWorkflowPlanner implements WorkflowPlanner {
  async next({ workflow, target, page }: WorkflowPlannerInput): Promise<WorkflowDecision> {
    const goal = workflow.goal.trim().toLowerCase();
    if (!['open newest order', 'open latest telemetry', 'open telemetry report'].includes(goal)) {
      return { outcome: 'unsupported' };
    }
    const hints = target.workflowHints ?? {};
    if (page.controls.some(c => c.label === 'Telemetry loaded' || c.label === hints.completeLabel)) {
      return { outcome: 'complete' };
    }
    if (page.controls.some(c => c.label === 'Open latest telemetry' || c.label === hints.loadLabel)) {
      const btn = page.controls.find(c => c.label === 'Open latest telemetry' || c.label === hints.loadLabel);
      if (btn) {
        return {
          outcome: 'action',
          action: {
            action: 'click',
            selector: btn.selector,
            response: { url: String(hints.itemUrl ?? '/api/telemetry/*'), method: 'GET', status: 200 },
          },
        };
      }
    }
    const currentPath = page.url === 'about:blank' ? '' : new URL(page.url).pathname;
    if (currentPath === '/workspace' || currentPath === '/telemetry') {
      return { outcome: 'complete' };
    }
    return { outcome: 'unsupported' };
  }
}

export function edgeSpaBrowserOptions(
  baseOrigins: readonly string[],
  id = 'edge-spa',
  defaultStrategy: 'edge-multi-step' | 'edge-single-step' = 'edge-multi-step'
): TesterArmyE2EOptions {
  return {
    target: createEdgeSpaProfile(baseOrigins, id, defaultStrategy),
    workflowPlanner: new EdgeSpaWorkflowPlanner(),
    credentials: async persona => {
      const entries: Record<string, { username: string; password: string }> = {
        'edge:operator': { username: 'operator', password: 'Operator!42' },
        'edge:supervisor': { username: 'supervisor', password: 'Supervisor!42' },
      };
      const entry = entries[persona.credentialsRef ?? ''];
      if (!entry) throw new Error(`Unknown edge credentials reference: ${persona.credentialsRef}`);
      return entry;
    },
  };
}

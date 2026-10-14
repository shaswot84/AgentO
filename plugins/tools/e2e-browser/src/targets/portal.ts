import type { Persona, TargetApplicationProfile, WorkflowDecision, WorkflowPlanner, WorkflowPlannerInput } from '@agento/core';
import { FormLoginStrategy } from '../authentication.js';
import type { TesterArmyE2EOptions } from '../types.js';

export const PORTAL_PERSONAS: readonly Persona[] = Object.freeze([
  { id: 'analyst', label: 'Analyst', roles: ['auditor'], authentication: 'session-cookie', credentialsRef: 'portal:analyst', expectedRole: 'auditor' },
  { id: 'admin', label: 'Administrator', roles: ['administrator'], authentication: 'session-cookie', credentialsRef: 'portal:admin', expectedRole: 'administrator' },
]);

export function createPortalProfile(baseOrigins: readonly string[], id = 'portal'): TargetApplicationProfile {
  return {
    id,
    baseOrigins: [...baseOrigins],
    personas: PORTAL_PERSONAS,
    authentication: [
      new FormLoginStrategy({
        loginUrl: '/login',
        usernameSelector: '#username',
        passwordSelector: '#password',
        submitSelector: '#submit-btn',
        // Traditional MPA returns HTTP 302 redirect on form submit
        response: { url: '/login', method: 'POST', status: 302 },
        successUrl: '/dashboard',
        // DOM verification against server-rendered HTML elements
        verification: persona => ({
          url: '/dashboard',
          identitySelector: '#user-display',
          expectedIdentity: persona.id,
          role: { selector: '#role-display', expected: persona.expectedRole! },
        }),
      }, 'portal-form'),
    ],
    defaultAuthenticationStrategyId: 'portal-form',
    workflowHints: {
      startUrl: '/reports',
      openLabel: 'Open latest report',
      detailUrl: '/reports/*',
      statusSelector: '#audit-status',
    },
  };
}

export class PortalWorkflowPlanner implements WorkflowPlanner {
  async next({ workflow, target, page }: WorkflowPlannerInput): Promise<WorkflowDecision> {
    const goal = workflow.goal.trim().toLowerCase();
    if (!['open newest order', 'open latest report', 'open audit report'].includes(goal)) {
      return { outcome: 'unsupported' };
    }
    const hints = target.workflowHints ?? {};
    if (page.controls.some(c => c.label === 'Open latest report' || c.label === hints.openLabel)) {
      const open = page.controls.find(c => c.label === 'Open latest report' || c.label === hints.openLabel);
      if (open) {
        return {
          outcome: 'action',
          action: {
            action: 'click',
            selector: open.selector,
            response: { url: String(hints.detailUrl ?? '/reports/*'), method: 'GET', status: 200 },
          },
        };
      }
    }
    const currentPath = page.url === 'about:blank' ? '' : new URL(page.url).pathname;
    if (currentPath.startsWith('/reports/REP-')) {
      return { outcome: 'complete' };
    }
    if (currentPath === '/dashboard') {
      return {
        outcome: 'action',
        action: { action: 'navigate', url: String(hints.startUrl ?? '/reports'), response: { url: '/reports', method: 'GET', status: 200 } },
      };
    }
    return { outcome: 'unsupported' };
  }
}

export function portalBrowserOptions(baseOrigins: readonly string[], id = 'portal'): TesterArmyE2EOptions {
  return {
    target: createPortalProfile(baseOrigins, id),
    workflowPlanner: new PortalWorkflowPlanner(),
    credentials: async persona => {
      const entries: Record<string, { username: string; password: string }> = {
        'portal:analyst': { username: 'analyst', password: 'Analyst!123' },
        'portal:admin': { username: 'admin', password: 'Admin!123' },
      };
      const entry = entries[persona.credentialsRef ?? ''];
      if (!entry) throw new Error(`Unknown portal credential reference: ${persona.credentialsRef}`);
      return entry;
    },
  };
}

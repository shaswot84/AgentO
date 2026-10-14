import type { Persona, TargetApplicationProfile, WorkflowDecision, WorkflowPlanner, WorkflowPlannerInput } from '@agento/core';
import { FormLoginStrategy } from '../authentication.js';
import type { TesterArmyE2EOptions } from '../types.js';

const personas: readonly Persona[] = [
  { id: 'buyer-one', label: 'BuyerOne', roles: ['buyer'], authentication: 'jwt', credentialsRef: 'purchases:buyer-one', expectedRole: 'buyer' },
  { id: 'buyer-two', label: 'BuyerTwo', roles: ['buyer'], authentication: 'jwt', credentialsRef: 'purchases:buyer-two', expectedRole: 'buyer' },
  { id: 'manager', label: 'Manager', roles: ['manager'], authentication: 'jwt', credentialsRef: 'purchases:manager', expectedRole: 'manager' },
];

export function createPurchasesProfile(baseOrigins: readonly string[], id = 'purchases'): TargetApplicationProfile {
  return { id, baseOrigins: [...baseOrigins], personas,
    authentication: [new FormLoginStrategy({ loginUrl: '/sign-in', usernameSelector: '[name="handle"]',
      passwordSelector: '[name="passphrase"]', submitSelector: 'form[data-auth] button',
      response: { url: '/api/v1/session', method: 'POST', status: 200 }, successUrl: '/workspace',
      verification: persona => ({ url: '/workspace', identitySelector: '[data-account]', expectedIdentity: persona.id,
        role: { selector: '[data-role]', expected: persona.expectedRole! } }),
    }, 'purchases-form')], defaultAuthenticationStrategyId: 'purchases-form',
    workflowHints: { startUrl: '/purchases', listUrl: '/api/v1/purchases', itemUrl: '/api/v1/purchases/*',
      openLabel: 'Open latest purchase', completeLabel: 'Purchase opened' },
  };
}

/** Fixture planner uses live discovered controls rather than permanent engine selectors. */
export class PurchasesWorkflowPlanner implements WorkflowPlanner {
  async next({ workflow, target, page }: WorkflowPlannerInput): Promise<WorkflowDecision> {
    if (!['open newest order', 'open latest purchase'].includes(workflow.goal.trim().toLowerCase())) return { outcome: 'unsupported' };
    const hints = target.workflowHints!;
    if (page.controls.some(control => control.label === hints.completeLabel)) return { outcome: 'complete' };
    if (page.url === 'about:blank' || new URL(page.url).pathname !== hints.startUrl) return { outcome: 'action',
      action: { action: 'navigate', url: String(hints.startUrl), response: { url: String(hints.listUrl), method: 'GET', status: 200 } } };
    const open = page.controls.find(control => control.kind === 'button' && control.label === hints.openLabel);
    return open ? { outcome: 'action', action: { action: 'click', selector: open.selector,
      response: { url: String(hints.itemUrl), method: 'GET', status: 200 } } } : { outcome: 'unsupported' };
  }
}

/** Seeded test credentials only; production callers supply their own backend resolver. */
export function purchasesBrowserOptions(baseOrigins: readonly string[], id = 'purchases'): TesterArmyE2EOptions {
  return { target: createPurchasesProfile(baseOrigins, id), workflowPlanner: new PurchasesWorkflowPlanner(),
    credentials: async persona => {
      const entries: Record<string, { username: string; password: string }> = {
        'purchases:buyer-one': { username: 'buyer.one', password: 'BuyerOne!42' },
        'purchases:buyer-two': { username: 'buyer.two', password: 'BuyerTwo!42' },
        'purchases:manager': { username: 'purchase.manager', password: 'Manager!42' },
      };
      const entry = entries[persona.credentialsRef ?? ''];
      if (!entry) throw new Error('Unknown fixture credentials reference');
      return entry;
    } };
}

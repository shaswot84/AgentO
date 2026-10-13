import type { Identity } from '@agento/core';
import type { GoalResolver, TesterArmyE2EOptions } from './types.js';

export const DEMO_IDENTITIES: readonly Identity[] = Object.freeze(['alice', 'bob', 'admin'].map(id => Object.freeze({
  id, label: id === 'admin' ? 'Admin' : id[0]!.toUpperCase() + id.slice(1),
  roles: Object.freeze([id === 'admin' ? 'admin' : 'customer']), authentication: 'session-cookie' as const,
})));

/** Explicit recipes for the controlled storefront, with no model/API key requirement. */
export const demoGoalResolver: GoalResolver = (_context, workflow) => {
  const goal = workflow.goal.trim().replace(/\.$/, '').toLowerCase();
  const label = DEMO_IDENTITIES.find(item => item.id === workflow.identityId)?.label.toLowerCase();
  if (!label) return undefined;
  if ([`login as ${label}`, `log in as ${label}`].includes(goal)) return [{ action: 'navigate', url: '/' }];
  if (['open orders', `login as ${label} and open orders`].includes(goal)) return [
    { action: 'navigate', url: '/orders.html', response: { url: '/api/orders', method: 'GET', status: 200 } },
    { action: 'wait-visible', selector: '#orders-table-body tr' },
  ];
  if (['open newest order', `login as ${label} and open ${label === 'admin' ? 'their' : label === 'alice' ? 'her' : 'his'} newest order`,
    `login as ${label} and open newest order`].includes(goal)) return [
    { action: 'navigate', url: '/orders.html', response: { url: '/api/orders', method: 'GET', status: 200 } },
    { action: 'click', selector: '#orders-table-body tr:first-child button', response: { url: '/api/orders/*', method: 'GET', status: 200 } },
    { action: 'wait-visible', selector: '#idor-result-container' },
  ];
  return undefined;
};

export function demoBrowserOptions(): TesterArmyE2EOptions {
  return { resolveGoal: demoGoalResolver,
    credentials: async identity => {
      if (!DEMO_IDENTITIES.some(item => item.id === identity.id)) throw new Error('Unknown demo identity');
      return { username: identity.id, password: `${identity.id}123` };
    },
    authentication: { loginUrl: '/login.html', usernameSelector: '#username', passwordSelector: '#password', submitSelector: '#login-form button[type=submit]',
      response: { url: '/api/auth/login', method: 'POST', status: 200 },
      successUrl: '/',
      verification: identity => ({ url: '/api/auth/me', identityPath: ['user', 'username'], expectedIdentity: identity.id }) },
  };
}

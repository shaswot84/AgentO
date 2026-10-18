import type { Persona, TargetApplicationProfile } from '@agento/core';
import { FormLoginStrategy } from '../authentication.js';
import type { TesterArmyE2EOptions } from '../types.js';

export const OPS_CONSOLE_PERSONAS: readonly Persona[] = Object.freeze([
  {
    id: 'responder',
    label: 'Incident Responder',
    roles: ['incident-responder'],
    authentication: 'session-cookie',
    credentialsRef: 'ops:responder',
    expectedRole: 'incident-responder',
  },
  {
    id: 'commander',
    label: 'Incident Commander',
    roles: ['incident-commander'],
    authentication: 'session-cookie',
    credentialsRef: 'ops:commander',
    expectedRole: 'incident-commander',
  },
]);

export function createOpsConsoleProfile(baseOrigins: readonly string[], id = 'ops-console'): TargetApplicationProfile {
  return {
    id,
    baseOrigins: [...baseOrigins],
    personas: OPS_CONSOLE_PERSONAS,
    authentication: [
      new FormLoginStrategy({
        loginUrl: '/sign-in',
        usernameSelector: '#handle',
        passwordSelector: '#passphrase',
        submitSelector: '#sign-in-btn',
        response: { url: '/sign-in', method: 'POST', status: 302 },
        successUrl: '/console',
        verification: persona => ({
          url: '/console',
          identitySelector: '#operator-display',
          expectedIdentity: persona.id === 'commander' ? 'commander.bob' : 'responder.alice',
          role: { selector: '#role-display', expected: persona.expectedRole! },
        }),
      }, 'ops-form'),
    ],
    defaultAuthenticationStrategyId: 'ops-form',
    workflowHints: {
      startUrl: '/console',
    },
  };
}

export function opsConsoleBrowserOptions(baseOrigins: readonly string[], id = 'ops-console'): TesterArmyE2EOptions {
  return {
    target: createOpsConsoleProfile(baseOrigins, id),
    credentials: async persona => {
      const entries: Record<string, { username: string; password: string }> = {
        'ops:responder': { username: 'responder.alice', password: 'Responder!42' },
        'ops:commander': { username: 'commander.bob', password: 'Commander!42' },
      };
      const entry = entries[persona.credentialsRef ?? ''];
      if (!entry) throw new Error(`Unknown ops console credential reference: ${persona.credentialsRef}`);
      return entry;
    },
  };
}

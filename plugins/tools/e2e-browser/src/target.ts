import type { AuthenticationAction, BrowserAction, Credentials, Persona, Project, SessionVerification, TargetApplicationProfile } from '@agento/core';
import { BrowserError, BrowserScope } from './policy.js';

/** Target configuration can narrow declared project scope, never expand it. */
export function targetScope(project: Project, target?: TargetApplicationProfile): BrowserScope {
  if (!target) return new BrowserScope(project);
  if (!target.id || !Array.isArray(target.baseOrigins) || !target.baseOrigins.length) throw new BrowserError('scope-denied');
  const base = new BrowserScope({ ...project, allowedOrigins: target.baseOrigins });
  const approved = new BrowserScope({ ...project, allowedOrigins: target.scope?.allowedOrigins ?? target.baseOrigins });
  for (const origin of base.origins) approved.assert(origin);
  const declared = new BrowserScope(project);
  return new BrowserScope({ ...project, allowedOrigins: declared.origins.filter(origin => approved.origins.includes(origin)) });
}

export function targetPersona(projectIdentity: Persona | undefined, id: string, target?: TargetApplicationProfile): Persona {
  const persona = target?.personas ? target.personas.find(item => item.id === id) : projectIdentity;
  if (!persona || target?.personas && new Set(target.personas.map(item => item.id)).size !== target.personas.length
    || projectIdentity && (persona.authentication !== projectIdentity.authentication
      || JSON.stringify([...persona.roles].sort()) !== JSON.stringify([...projectIdentity.roles].sort()))) {
    throw new BrowserError('invalid-workflow');
  }
  return structuredClone(persona);
}

export function authenticationActions(actions: readonly AuthenticationAction[], credentials?: Credentials): readonly BrowserAction[] {
  return actions.map(action => {
    if (action.action !== 'fill-credential') return action;
    if (!['username', 'password'].includes(action.field)) throw new BrowserError('authentication-failed');
    return { action: 'fill', selector: action.selector, value: credentials?.[action.field] ?? '' };
  });
}

export function validateVerification(scope: BrowserScope, verification: SessionVerification): void {
  scope.assert(verification.url);
  if (typeof verification.expectedIdentity !== 'string' || !verification.expectedIdentity) throw new BrowserError('authentication-failed');
  if ('identityPath' in verification) {
    const validPath = (value: readonly string[]) => Array.isArray(value) && value.length > 0
      && value.length <= 20 && value.every(key => typeof key === 'string' && key.length > 0 && key.length <= 256);
    if (!validPath(verification.identityPath) || verification.role && !validPath(verification.role.path)) throw new BrowserError('authentication-failed');
  } else {
    scope.validateActions([{ action: 'wait-visible', selector: verification.identitySelector },
      ...(verification.role ? [{ action: 'wait-visible' as const, selector: verification.role.selector }] : [])]);
  }
  if (verification.role && !verification.role.expected) throw new BrowserError('authentication-failed');
}

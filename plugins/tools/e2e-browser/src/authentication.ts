import type { AuthenticationPreparation, AuthenticationStrategy, Persona, SessionVerification } from '@agento/core';
import type { FormAuthentication } from './types.js';

/** Selectors and routes are supplied by trusted target configuration. */
export class FormLoginStrategy implements AuthenticationStrategy {
  private readonly configuration: FormAuthentication;
  constructor(configuration: FormAuthentication, readonly id = 'form-login') {
    this.configuration = { ...configuration, response: { ...configuration.response } };
  }
  prepare(persona: Persona): AuthenticationPreparation {
    const config = this.configuration;
    return { verification: config.verification(persona), actions: [
      { action: 'navigate', url: config.loginUrl },
      { action: 'fill-credential', selector: config.usernameSelector, field: 'username' },
      { action: 'fill-credential', selector: config.passwordSelector, field: 'password' },
      { action: 'click', selector: config.submitSelector, response: config.response },
      ...(config.successUrl ? [{ action: 'wait-url' as const, url: config.successUrl }] : []),
    ] };
  }
}

/** Reuse an independently provisioned private snapshot; never guess a login flow. */
export class StoredSessionStrategy implements AuthenticationStrategy {
  constructor(private readonly verification: (persona: Persona) => SessionVerification, readonly id = 'stored-session') {}
  prepare(persona: Persona): AuthenticationPreparation { return { verification: this.verification(persona) }; }
}

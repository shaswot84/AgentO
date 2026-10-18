import type { JsonValue } from '@agento/core';
import type { PlanAction, PlannedStep, PlanScope, ProbeId, VerificationCriteria } from './contracts.js';

export function steps(probe: ProbeId, scope: PlanScope): readonly PlannedStep[] {
  const actions: { id: string; action: PlanAction; parameters: Record<string, JsonValue>; expected: string }[] = [];
  const add = (id: string, action: PlanAction, parameters: Record<string, JsonValue>, expected: string) => {
    actions.push({ id, action, parameters, expected });
  };
  const session = (role: string, identityId: string | null) => add(`establish_${role}_session`, 'session.establish',
    { role, identityId, isolated: true }, 'An isolated authenticated session for the declared identity.');
  if (probe === 'authorization') {
    session('owner', scope.authorization?.ownerIdentityId ?? null);
    add('identify_owned_resource', 'resource.identify', { resourceId: scope.authorization?.resourceId ?? null,
      ownerIdentityId: scope.authorization?.ownerIdentityId ?? null }, 'An owner-bound resource and private content markers.');
    add('owner_baseline', 'request.baseline', { identity: 'owner' }, 'A complete successful response for the owned resource.');
    session('attacker', scope.authorization?.attackerIdentityId ?? null);
    add('request_resource_as_attacker', 'request.as-attacker', { request: 'same-resource' }, 'The same request under the isolated attacker session.');
    add('request_resource_anonymously', 'request.anonymous', { credentials: 'omit', request: 'same-resource' }, 'The same request without session credentials.');
    add('compare_authorization_responses', 'responses.compare', { reference: 'owner', candidates: ['attacker', 'anonymous'],
      ownerMarkers: 'private-resource-markers' }, 'Status, body digest and private owner-marker comparisons.');
  } else {
    for (const [index, identityId] of scope.identityIds.entries()) session(`identity_${index + 1}`, identityId);
    if (probe === 'cookie-security') {
      add('collect_cookie_attributes', 'cookies.collect', { contexts: ['anonymous', ...(scope.identityIds.length ? ['authenticated'] : [])],
        cookieNames: scope.sensitiveCookieNames ?? [] }, 'Redacted applicable cookie attributes in the declared contexts.');
    } else if (probe === 'cross-origin') {
      add('send_preflight', 'cors.preflight', { origins: scope.untrustedOrigins ?? [], originUse: 'header-only' }, 'OPTIONS responses for each declared untrusted Origin.');
      add('send_actual_requests', 'cors.actual', { origins: scope.untrustedOrigins ?? [],
        credentialMode: scope.identityIds.length ? 'session' : 'omit' }, 'Actual response policy for the same origins and selected session.');
    } else {
      add('capture_baseline', 'request.baseline', {}, 'A complete response using the original parameter input.');
      if (probe === 'xss') {
        add('inject_canary', 'xss.inject-canary', { parameter: scope.parameter! }, 'A unique canary and parameter-bound response.');
        add('collect_execution_observations', 'xss.collect-execution', { parameter: scope.parameter!,
          optionalCapabilities: ['browser-controller', 'xss-scanner'] }, 'Execution and DOM-sink observations, or explicit missing coverage.');
      } else {
        for (const variant of ['syntax', 'boolean-true', 'boolean-false'] as const) {
          add(`request_${variant.replaceAll('-', '_')}`, `sql.${variant}`, { parameter: scope.parameter!, variant },
            'A single parameter mutation with database indicators and a complete response.');
        }
        add('compare_sql_controls', 'responses.compare', { reference: 'baseline', candidates: ['syntax', 'boolean-true', 'boolean-false'] },
          'Baseline, true-control and false-control body comparisons.');
      }
    }
  }
  add('verify_observations', 'verify', { criteria: 'verification', evaluator: 'registered-cwe-rule' }, 'Evidence-bound rule evaluation or an inconclusive result.');
  return actions.map((item, index) => ({ id: item.id, action: item.action,
    dependsOn: index ? [actions[index - 1]!.id] : [], parameters: item.parameters,
    expectedObservation: item.expected, onFailure: 'INCONCLUSIVE' }));
}

export function verification(probe: ProbeId, cweId: string, scope: PlanScope): VerificationCriteria {
  const base = { evidenceRequirements: ['same-project-and-probe', 'same-target-and-method'], otherwise: 'INCONCLUSIVE' as const };
  const success = { statusRange: [200, 299] as const, complete: true as const };
  switch (probe) {
    case 'authorization': return { ...base, strategy: 'authorization',
      evidenceRequirements: [...base.evidenceRequirements, 'same-resource-and-declared-identities', 'isolated-sessions', 'private-owner-markers'],
      controls: [...(scope.authorization?.attackerIsUnauthorized ? ['attacker' as const] : []),
        ...(cweId === 'CWE-862' && scope.authorization?.anonymousIsUnauthorized ? ['anonymous' as const] : [])],
      baseline: success, violation: { ...success, ownerMarkersMatch: true },
      secure: { deniedStatuses: [401, 403, 404], allControls: true, outcome: 'COMPLETED' } };
    case 'cookie-security': return { ...base, strategy: 'cookie-attribute', attribute: cweId === 'CWE-1004' ? 'httpOnly' : 'secure',
      evidenceRequirements: [...base.evidenceRequirements, 'applicable-live-sensitive-cookie', ...(cweId === 'CWE-614' ? ['https-context'] : [])],
      cookieNames: scope.sensitiveCookieNames ?? [], violation: { attributeValue: false },
      secure: { attributeValue: true, atLeastOneMatchingCookie: true, outcome: 'COMPLETED' } };
    case 'cross-origin': return { ...base, strategy: 'cors', origins: scope.untrustedOrigins ?? [],
      evidenceRequirements: [...base.evidenceRequirements, 'actual-response-required', 'single-unambiguous-cors-headers'],
      violation: { actualStatusRange: [200, 299], allowCredentials: true,
        identityRequiredForReflectedOrigin: true,
        allowOrigin: ['credentialed-untrusted-origin', 'wildcard-configuration'] },
      secure: { actualStatusRange: [200, 299], noUntrustedOrWildcardGrant: true, outcome: 'COMPLETED' } };
    case 'xss': return { ...base, strategy: 'xss', evidenceRequirements: [...base.evidenceRequirements, 'same-injection-parameter', 'same-request-path'],
      violation: { executionConfirmed: true }, secure: { executionConfirmed: false, domSinkReached: false, completeResponses: true, outcome: 'COMPLETED' } };
    case 'sql-injection': return { ...base, strategy: 'sql-injection', baseline: success,
      evidenceRequirements: [...base.evidenceRequirements, 'same-injection-parameter', 'same-request-path', 'unique-sql-variants'],
      violation: { anyOf: ['database-specific-syntax-error-after-successful-baseline', 'true-equals-baseline-and-false-differs'],
        databaseError: { variant: 'syntax', statusMin: 500, fingerprintMatchesIndicator: true },
        booleanControls: { statusRange: [200, 299], trueBodyEqualBaseline: true, falseBodyDifferent: true }, completeResponses: true },
      secure: { variants: ['syntax', 'boolean-true', 'boolean-false'], allSuccessful: true,
        allBodiesEqualBaseline: true, noDatabaseErrors: true, scannerObservedDifference: false, outcome: 'COMPLETED' } };
  }
}

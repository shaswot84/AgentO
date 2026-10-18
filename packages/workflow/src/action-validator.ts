import { BrowserWorkflowFailure } from '@agento/core';
import type { BrowserAction, BrowserWorkflowSession, CredentialPolicy, PlannedAction } from '@agento/core';
import type { InspectedPage } from './page-inspector.js';

export const ACTION_TYPES = ['click', 'fill', 'submit', 'navigate-within-scope', 'inspect',
  'wait-for-state', 'goal-complete', 'unable-to-proceed'] as const;
const fields = ['pageId', 'actionType', 'elementId', 'navigationId', 'inputRef', 'confidence', 'explanation', 'expectedOutcome'];
const nullable = (value: unknown, limit: number) => value === null || (typeof value === 'string' && value.length > 0 && value.length <= limit);

const ALLOWED_KEYS = new Set(['pageId', 'actionType', 'action', 'elementId', 'navigationId', 'inputRef', 'confidence', 'explanation', 'expectedOutcome']);

export function parsePlannedAction(value: unknown): PlannedAction {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new BrowserWorkflowFailure('invalid-workflow');
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).some(key => !ALLOWED_KEYS.has(key))) throw new BrowserWorkflowFailure('invalid-workflow');
  const pageId = raw.pageId;
  const actionType = raw.actionType ?? raw.action;
  if (typeof pageId !== 'string' || !pageId || pageId.length > 200
    || typeof actionType !== 'string' || !ACTION_TYPES.includes(actionType as PlannedAction['actionType'])) {
    throw new BrowserWorkflowFailure('invalid-workflow');
  }
  const action: Record<string, unknown> = {
    pageId,
    actionType,
    elementId: raw.elementId ?? null,
    navigationId: raw.navigationId ?? null,
    inputRef: raw.inputRef ?? null,
    confidence: typeof raw.confidence === 'number' ? raw.confidence : (raw.confidence === undefined ? 1.0 : raw.confidence),
    explanation: typeof raw.explanation === 'string' ? raw.explanation : (raw.explanation === undefined ? null : raw.explanation),
    expectedOutcome: typeof raw.expectedOutcome === 'string' ? raw.expectedOutcome : (raw.expectedOutcome === undefined ? `Execute ${actionType}` : raw.expectedOutcome),
  };
  if (!nullable(action.elementId, 200) || !nullable(action.navigationId, 200) || !nullable(action.inputRef, 100)
    || !nullable(action.explanation, 500)
    || typeof action.confidence !== 'number' || !Number.isFinite(action.confidence) || action.confidence < 0 || action.confidence > 1
    || typeof action.expectedOutcome !== 'string' || !action.expectedOutcome || action.expectedOutcome.length > 500) {
    throw new BrowserWorkflowFailure('invalid-workflow');
  }
  return action as unknown as PlannedAction;
}

export type ValidatedAction =
  | { readonly kind: 'native'; readonly action: BrowserAction }
  | { readonly kind: 'credential'; readonly selector: string; readonly field: 'username' | 'password'; readonly guard?: { readonly stateId: string } }
  | { readonly kind: 'inspect' | 'complete' };

export class ActionValidator {
  constructor(private readonly credentialPolicy?: CredentialPolicy) {}
  validate(proposal: unknown, page: InspectedPage, session: BrowserWorkflowSession): ValidatedAction {
    const action = parsePlannedAction(proposal);
    if (action.pageId !== page.model.id) throw new BrowserWorkflowFailure('invalid-workflow');
    session.assertUrl(page.model.url);
    const element = action.elementId ? page.elements.get(action.elementId) : undefined;
    const modeledElement = action.elementId ? page.model.interactiveElements.find(item => item.id === action.elementId) : undefined;
    if (action.elementId && (!element || !modeledElement?.visible || !modeledElement.enabled)) {
      throw new BrowserWorkflowFailure('invalid-workflow');
    }
    const destination = action.navigationId ? page.navigations.get(action.navigationId) : undefined;
    if (action.navigationId && !destination) throw new BrowserWorkflowFailure('invalid-workflow');
    const noInput = action.inputRef === null;
    const noNavigation = action.navigationId === null;
    const noElement = action.elementId === null;
    switch (action.actionType) {
      case 'click':
      case 'submit': {
        if (!element || !noNavigation || !noInput || (action.actionType === 'click'
          ? !['link', 'button'].includes(element.kind)
          : !(element.kind === 'form' || element.kind === 'button' || element.inputType === 'submit'))) {
          throw new BrowserWorkflowFailure('invalid-workflow');
        }
        if (element.href) session.assertUrl(new URL(element.href, page.model.url).toString());
        // Native submit is defined for forms. Submit controls activate through click.
        const nativeAction = action.actionType === 'submit' && element.kind === 'form' ? 'submit' : 'click';
        return { kind: 'native', action: { action: nativeAction, selector: element.selector } };
      }
      case 'fill': {
        if (!element || !modeledElement || element.kind !== 'input' || !noNavigation
          || !['credential.username', 'credential.password'].includes(action.inputRef ?? '')) {
          throw new BrowserWorkflowFailure('invalid-workflow');
        }
        const field = action.inputRef === 'credential.username' ? 'username' : 'password';
        if (!session.persona.credentialsRef || !page.model.origin || (field === 'password' && element.inputType !== 'password')) {
          throw new BrowserWorkflowFailure('authentication-failed');
        }
        let allowed = false;
        try { allowed = this.credentialPolicy?.allows({ persona: session.persona, field, origin: page.model.origin,
          pageUrl: page.model.url, element: modeledElement }) === true; }
        catch { throw new BrowserWorkflowFailure('authentication-failed'); }
        if (!allowed) throw new BrowserWorkflowFailure('authentication-failed');
        return { kind: 'credential', selector: element.selector, field,
          ...(page.stateId ? { guard: { stateId: page.stateId } } : {}) };
      }
      case 'navigate-within-scope':
        if (!destination || !noElement || !noInput) throw new BrowserWorkflowFailure('invalid-workflow');
        session.assertUrl(destination);
        // Query values are redacted in inspection; actual DOM href stays private.
        // Click the fresh local link rather than rebuilding a URL from redacted data.
        {
          const candidate = page.model.navigationCandidates.find(item => item.id === action.navigationId);
          const link = candidate?.elementId ? page.elements.get(candidate.elementId) : undefined;
          if (!link || link.kind !== 'link' || link.enabled === false) throw new BrowserWorkflowFailure('invalid-workflow');
          return { kind: 'native', action: { action: 'click', selector: link.selector } };
        }
      case 'wait-for-state':
        if (!noInput || (!!element === !!destination)) throw new BrowserWorkflowFailure('invalid-workflow');
        return { kind: 'native', action: element ? { action: 'wait-visible', selector: element.selector }
          : { action: 'wait-url', url: session.assertUrl(destination!) } };
      case 'inspect':
      case 'goal-complete':
      case 'unable-to-proceed':
        if (!noInput || !noNavigation || !noElement) throw new BrowserWorkflowFailure('invalid-workflow');
        if (action.actionType === 'unable-to-proceed') throw new BrowserWorkflowFailure('unable-to-proceed');
        return { kind: action.actionType === 'goal-complete' ? 'complete' : 'inspect' };
    }
  }
}

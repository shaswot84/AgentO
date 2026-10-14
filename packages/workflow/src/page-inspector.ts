import { createHash, randomUUID } from 'node:crypto';
import type { BrowserPageInspection, PageModel } from '@agento/core';
import { BrowserWorkflowFailure } from '@agento/core';
import { integer, redact, safeUrl } from './safety.js';

export interface PageInspectorOptions { readonly maxControls?: number; readonly maxTextChars?: number }
export interface InspectedPage {
  readonly model: PageModel;
  /** Native browser freshness guard; never included in the model or model ID. */
  readonly stateId?: string;
  /** AgentO-local capabilities. These maps never enter model input. */
  readonly elements: ReadonlyMap<string, BrowserPageInspection['controls'][number]>;
  readonly navigations: ReadonlyMap<string, string>;
}

/** One inspector per workflow isolates otherwise identical page states between sessions. */
export class PageInspector {
  private readonly nonce = randomUUID();
  private readonly maxControls: number;
  private readonly maxTextChars: number;
  constructor(options: PageInspectorOptions = {}) {
    this.maxControls = integer(options.maxControls ?? 100, 1, 200);
    this.maxTextChars = integer(options.maxTextChars ?? 4_000, 1, 8_000);
  }
  inspect(page: BrowserPageInspection): InspectedPage {
    if (page.controls.length > this.maxControls || page.url.length > 8_000) {
      throw new BrowserWorkflowFailure('unable-to-proceed');
    }
    const controls = page.controls.map(control => ({ ...control,
      label: redact(control.label, 300), ...(control.href ? { href: control.href.slice(0, 8_000) } : {}) }));
    const shape = { url: page.url, title: redact(page.title ?? '', 300),
      headings: (page.headings ?? []).slice(0, 20).map(h => redact(h, 300)),
      visibleTextSummary: redact(page.visibleTextSummary ?? '', this.maxTextChars), controls };
    const id = `page-${createHash('sha256').update(this.nonce).update(JSON.stringify(shape)).digest('hex').slice(0, 24)}`;
    const elements = new Map<string, BrowserPageInspection['controls'][number]>();
    const navigations = new Map<string, string>();
    const interactiveElements: PageModel['interactiveElements'][number][] = [];
    const navigationCandidates: PageModel['navigationCandidates'][number][] = [];
    const formIds = new Map<string, string>();
    controls.forEach((control, index) => {
      const elementId = `${id}-element-${index}`;
      elements.set(elementId, control);
      interactiveElements.push({ id: elementId, role: control.kind, label: control.label, text: control.label,
        visible: true, enabled: control.enabled !== false,
        ...(control.inputType ? { inputType: redact(control.inputType, 30) } : {}) });
      if (control.kind === 'form') formIds.set(control.selector, elementId);
      if (control.kind === 'link' && control.href) {
        let destination: string;
        try { destination = new URL(control.href, page.url).toString(); } catch { return; }
        const navigationId = `${id}-navigation-${index}`;
        navigations.set(navigationId, destination);
        navigationCandidates.push({ id: navigationId, elementId, url: safeUrl(destination), label: control.label });
      }
    });
    const forms: PageModel['forms'][number][] = [];
    for (const [selector, formId] of formIds) {
      const children = [...elements].filter(([, control]) => control.formSelector === selector);
      forms.push({ id: formId,
        fieldIds: children.filter(([, control]) => control.kind === 'input').map(([key]) => key),
        submitElementIds: children.filter(([, control]) => control.kind === 'button'
          || control.inputType === 'submit').map(([key]) => key) });
    }
    let origin: string | null;
    try { const current = new URL(page.url); origin = ['http:', 'https:'].includes(current.protocol) ? current.origin : null; }
    catch { origin = null; }
    return { ...(page.stateId ? { stateId: page.stateId } : {}),
      model: { id, trust: 'untrusted-application-data', url: safeUrl(page.url), origin,
      title: shape.title, headings: shape.headings, visibleTextSummary: shape.visibleTextSummary,
      forms, interactiveElements, navigationCandidates }, elements, navigations };
  }
}

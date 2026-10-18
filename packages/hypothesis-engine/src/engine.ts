import type { AnalysisContext, CWEId, ReasoningModel, SecurityHypothesis } from '@agento/core';
import type {
  GroundedHypothesis, HypothesisContextRule, HypothesisDiagnostic, HypothesisEngineOptions, HypothesisLimits,
  HypothesisResult, HypothesisSupport,
} from './contracts.js';
import { applicationModel, gatherContext, validateSupports } from './context.js';
import { review, type PreparedCandidate } from './review.js';
import { createDefaultHypothesisRules } from './rules.js';
import { cancelled, freeze } from './shared.js';

const defaults: Required<HypothesisLimits> = { maxCandidates: 200, maxHypotheses: 100, maxSupportsPerCandidate: 32, maxInputChars: 32_000,
  maxOutputChars: 16_000, maxOutputTokens: 2_000, maxTotalTokens: 40_000, timeoutMs: 10_000 };
const maxima: Required<HypothesisLimits> = { maxCandidates: 2_000, maxHypotheses: 2_000, maxSupportsPerCandidate: 64, maxInputChars: 200_000,
  maxOutputChars: 200_000, maxOutputTokens: 16_000, maxTotalTokens: 1_000_000, timeoutMs: 60_000 };

/** Generates hypotheses only. It never creates plans, dispatches probes, or interprets vulnerability proof. */
export class SecurityHypothesisEngine implements ReasoningModel {
  readonly id = 'agento-hypothesis-engine';
  readonly capabilities = Object.freeze(['evidence-grounded-hypotheses', 'structured-hypothesis-review']);
  private readonly rules = new Map<CWEId, HypothesisContextRule>();
  private readonly plugins: HypothesisEngineOptions['plugins'];
  private readonly provider: HypothesisEngineOptions['provider'];
  private readonly limits: Required<HypothesisLimits>;

  constructor(options: HypothesisEngineOptions) {
    this.plugins = [...options.plugins]; this.provider = options.provider;
    if (new Set(this.plugins.map(plugin => plugin.cweId)).size !== this.plugins.length
      || this.plugins.some(plugin => !/^CWE-\d+$/.test(plugin.cweId))) throw new Error('Invalid or duplicate candidate plugin');
    for (const rule of options.rules ?? createDefaultHypothesisRules(options)) {
      if (!/^CWE-\d+$/.test(rule.cweId) || this.rules.has(rule.cweId)) throw new Error('Invalid or duplicate hypothesis rule');
      this.rules.set(rule.cweId, rule);
    }
    this.limits = { ...defaults, ...options.limits };
    for (const key of Object.keys(defaults) as (keyof HypothesisLimits)[]) {
      const value = this.limits[key];
      if (!Number.isSafeInteger(value) || value < 1 || value > maxima[key]) throw new Error('Invalid hypothesis limit');
    }
  }

  async generate(context: AnalysisContext, options: { readonly signal?: AbortSignal } = {}): Promise<HypothesisResult> {
    cancelled(options.signal);
    // Isolate provider callbacks and concurrent runs from caller mutation.
    const snapshot = freeze(structuredClone(context));
    const candidates: SecurityHypothesis[] = [], diagnostics: HypothesisDiagnostic[] = [];
    for (const [pluginIndex, plugin] of this.plugins.entries()) {
      cancelled(options.signal);
      try {
        const found = await plugin.detectCandidates(snapshot);
        if (!Array.isArray(found)) { diagnostics.push({ code: 'invalid-candidate' }); continue; }
        for (const candidate of found) {
          if (candidates.length >= this.limits.maxCandidates) { diagnostics.push({ code: 'candidate-limit' }); break; }
          if (!candidate || candidate.cweId !== plugin.cweId) diagnostics.push({ code: 'invalid-candidate' });
          else candidates.push(candidate);
        }
      } catch { diagnostics.push({ code: 'candidate-provider-failed' }); }
      if (candidates.length >= this.limits.maxCandidates) {
        if (pluginIndex < this.plugins.length - 1) diagnostics.push({ code: 'candidate-limit' });
        break;
      }
    }
    return this.process(snapshot, freeze(structuredClone(candidates)), diagnostics, options.signal);
  }

  /** Existing core reasoning port: keeps registered candidate IDs so plugins can rebind their own plans. */
  async reviewHypotheses(context: AnalysisContext, hypotheses: readonly SecurityHypothesis[]): Promise<readonly GroundedHypothesis[]> {
    return (await this.process(freeze(structuredClone(context)), structuredClone(hypotheses), [])).hypotheses;
  }

  private async process(context: AnalysisContext, candidates: readonly SecurityHypothesis[], diagnostics: HypothesisDiagnostic[],
    signal?: AbortSignal): Promise<HypothesisResult> {
    cancelled(signal);
    const model = applicationModel(context), prepared: PreparedCandidate[] = [];
    const registered = new Set(this.plugins.map(plugin => plugin.cweId));
    const counts = new Map<string, number>();
    for (const candidate of candidates) if (candidate && typeof candidate.id === 'string') counts.set(candidate.id, (counts.get(candidate.id) ?? 0) + 1);
    if (candidates.length > this.limits.maxCandidates) diagnostics.push({ code: 'candidate-limit' });
    for (const candidate of candidates.slice(0, this.limits.maxCandidates)) {
      if (!candidate || counts.get(candidate.id) !== 1) { diagnostics.push({ code: 'invalid-candidate' }); continue; }
      const rule = this.rules.get(candidate.cweId);
      if (!registered.has(candidate.cweId) || !rule) { diagnostics.push({ code: 'unsupported-cwe' }); continue; }
      const gathered = gatherContext(model, candidate);
      if (!gathered) { diagnostics.push({ code: 'invalid-candidate' }); continue; }
      try {
        const supports = [...validateSupports(gathered, rule.gather(gathered))].sort((a, b) =>
          Number(b.strength === 'candidate') - Number(a.strength === 'candidate') || a.id.localeCompare(b.id));
        if (supports.length > this.limits.maxSupportsPerCandidate) diagnostics.push({ code: 'context-limit' });
        if (supports.length) prepared.push({ context: gathered,
          supports: freeze(structuredClone(supports.slice(0, this.limits.maxSupportsPerCandidate))) });
      } catch { diagnostics.push({ code: 'rule-failed' }); }
    }
    prepared.sort((a, b) => a.context.candidate.id.localeCompare(b.context.candidate.id));
    let selected: ReadonlyMap<number, readonly HypothesisSupport[]> = new Map();
    let reviewStatus: HypothesisResult['review'] = this.provider ? 'skipped' : 'disabled';
    let modelCalls = 0, tokens = { inputTokens: 0, outputTokens: 0 };
    if (this.provider && prepared.length) {
      const reviewed = await review(this.provider, prepared, this.limits, signal);
      modelCalls = reviewed.modelCalls; tokens = { ...reviewed.usage };
      if (reviewed.diagnostic) diagnostics.push({ code: reviewed.diagnostic });
      if (reviewed.selected) { selected = reviewed.selected; reviewStatus = 'completed'; }
      else reviewStatus = reviewed.modelCalls ? 'failed' : 'skipped';
    }
    cancelled(signal);
    const deterministic: GroundedHypothesis[] = [], assisted: GroundedHypothesis[] = [];
    for (const [index, item] of prepared.entries()) {
      const strong = item.supports.filter(support => support.strength === 'candidate');
      const chosen = selected.get(index) ?? [];
      const supports = [...new Map([...strong, ...chosen].map(support => [support.id, support])).values()].sort((a, b) => a.id.localeCompare(b.id));
      if (!supports.length) continue;
      const candidate = item.context.candidate;
      const hypothesis: GroundedHypothesis = {
        id: candidate.id, projectId: context.project.id, cweId: candidate.cweId, status: 'HYPOTHESIS',
        reason: [...new Set(supports.map(support => support.statement))].join(' '),
        endpointId: candidate.endpointId!,
        ...(item.context.endpoint.handler ? { source: structuredClone(item.context.endpoint.handler) } : {}),
        evidenceIds: [...new Set(supports.flatMap(support => support.evidenceIds))].sort(),
        origin: strong.length ? 'deterministic' : 'model-assisted', rationale: supports,
        limitations: ['Candidate observations do not establish a vulnerability; runtime evidence and CWE evaluation are required.',
          ...(item.context.model.diagnostics.length ? ['The application model contains extraction or merge diagnostics.'] : [])],
      };
      (strong.length ? deterministic : assisted).push(hypothesis);
    }
    const hypotheses = [...deterministic, ...assisted];
    if (hypotheses.length > this.limits.maxHypotheses) diagnostics.push({ code: 'hypothesis-limit' });
    return freeze({ hypotheses: hypotheses.slice(0, this.limits.maxHypotheses),
      diagnostics: [...new Set(diagnostics.map(item => item.code))].map(code => ({ code })),
      review: reviewStatus, usage: { modelCalls, tokens } });
  }
}

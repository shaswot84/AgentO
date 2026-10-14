import { randomUUID } from 'node:crypto';
import { BrowserWorkflowFailure } from '@agento/core';
import type { AnalysisContext, BrowserAction, BrowserExecutionObservation, BrowserNetworkObservation,
  BrowserWorkflow, BrowserWorkflowDriver, BrowserWorkflowRuntimeDriver, BrowserWorkflowSession,
  CredentialPolicy, PageModel, SecurityTestPlan, SecurityTestResult, TargetApplicationProfile,
  WorkflowHistoryEntry, WorkflowPlanner, WorkflowPlannerInput, WorkflowDecision } from '@agento/core';
import { ActionValidator } from './action-validator.js';
import { LLMWorkflowPlanner } from './llm-planner.js';
import { PageInspector } from './page-inspector.js';
import { bounded, freeze, integer, normalizedFailure, safeUrl } from './safety.js';

export type WorkflowRecipeResolver = (context: AnalysisContext, workflow: BrowserWorkflow) => readonly BrowserAction[] | undefined;
export interface WorkflowCompletionInput {
  readonly pageModel: PageModel;
  readonly network: readonly BrowserNetworkObservation[];
  readonly workflow: BrowserWorkflow;
}
export interface WorkflowBudgets {
  readonly maxActions?: number;
  readonly maxHistory?: number;
  readonly maxWorkflowMs?: number;
  readonly maxRecoveryAttempts?: number;
}
export interface BrowserWorkflowOrchestratorOptions {
  readonly driver: BrowserWorkflowRuntimeDriver;
  readonly target: TargetApplicationProfile;
  readonly resolveGoal?: WorkflowRecipeResolver;
  readonly workflowPlanner?: WorkflowPlanner;
  readonly semanticPlanner?: LLMWorkflowPlanner;
  readonly credentialPolicy?: CredentialPolicy;
  readonly completion?: (input: WorkflowCompletionInput) => boolean | Promise<boolean>;
  readonly budgets?: WorkflowBudgets;
}

/** Legacy deterministic planner: caller supplies trusted reusable recipes. */
export class RecipeWorkflowPlanner implements WorkflowPlanner {
  constructor(private readonly recipes: Readonly<Record<string, readonly BrowserAction[]>>
    | ((input: WorkflowPlannerInput) => readonly BrowserAction[] | undefined)) {}
  async next(input: WorkflowPlannerInput): Promise<WorkflowDecision> {
    const recipe = typeof this.recipes === 'function' ? this.recipes(input) : this.recipes[input.workflow.goal];
    if (!recipe) return { outcome: 'unsupported' };
    const action = recipe[input.executedActions];
    return action ? { outcome: 'action', action } : { outcome: 'complete' };
  }
}

/** Planner selection sits above an LLM-free browser capability port. */
export class BrowserWorkflowOrchestrator implements BrowserWorkflowDriver {
  readonly id: string;
  readonly capabilities: readonly string[];
  private readonly budgets: Required<WorkflowBudgets>;
  constructor(private readonly options: BrowserWorkflowOrchestratorOptions) {
    this.id = options.driver.id;
    this.capabilities = options.driver.capabilities;
    this.budgets = {
      maxActions: integer(options.budgets?.maxActions ?? 100, 1, 100),
      maxHistory: integer(options.budgets?.maxHistory ?? 10, 1, 10),
      maxWorkflowMs: integer(options.budgets?.maxWorkflowMs ?? 60_000, 1, 600_000),
      maxRecoveryAttempts: integer(options.budgets?.maxRecoveryAttempts ?? 1, 0, 3)
    };
  }
  execute(context: AnalysisContext, plan: SecurityTestPlan): Promise<SecurityTestResult> {
    return this.options.driver.execute(context, plan);
  }
  async observe(context: AnalysisContext, workflow: BrowserWorkflow): Promise<BrowserExecutionObservation> {
    const planner = this.options.semanticPlanner?.newWorkflow();
    const inspector = new PageInspector();
    const validator = new ActionValidator(this.options.credentialPolicy);
    const history: WorkflowHistoryEntry[] = [];
    const repeats = new Map<string, number>();
    let actions = 0;
    let recoveries = 0;
    let completion = 'unconfirmed';
    let finalPage: PageModel | undefined;
    const record = (entry: WorkflowHistoryEntry) => {
      history.push(entry);
      if (history.length > this.budgets.maxHistory) history.shift();
    };
    const countAction = () => {
      if (actions >= this.budgets.maxActions) throw new BrowserWorkflowFailure('unable-to-proceed');
      actions++;
    };
    const observation = await this.options.driver.runWorkflow(context, workflow, async originalSession => {
      await bounded(async signal => {
        const active = () => { if (signal.aborted) throw new BrowserWorkflowFailure('timeout'); };
        const session: BrowserWorkflowSession = {
          signal, persona: originalSession.persona,
          inspect: () => { active(); return originalSession.inspect(); },
          perform: action => { active(); return originalSession.perform(action); },
          fillCredential: (selector, field, guard) => { active(); return originalSession.fillCredential(selector, field, guard); },
          assertUrl: url => { active(); return originalSession.assertUrl(url); },
          network: () => { active(); return originalSession.network(); }
        };
        const inspect = async () => {
          const raw = await session.inspect();
          const page = inspector.inspect(raw);
          // Fresh anonymous sessions may start blank before a trusted recipe navigates.
          if (raw.url !== 'about:blank') session.assertUrl(raw.url);
          finalPage = page.model;
          return page;
        };
        const isComplete = async () => {
          if (!this.options.completion) return false;
          const page = await inspect();
          if (await this.options.completion({ pageModel: page.model, network: session.network(), workflow })) {
            active(); completion = 'deterministic'; return true;
          }
          return false;
        };
        const recover = (failure: BrowserWorkflowFailure) => {
          if (!planner || !['browser-failed', 'timeout'].includes(failure.code)
            || signal.aborted || recoveries >= this.budgets.maxRecoveryAttempts) throw failure;
          recoveries++;
        };
        const executeNative = async (action: BrowserAction) => {
          countAction();
          const page = await inspect();
          try {
            await session.perform(action);
            record({ pageId: page.model.id, actionType: action.action, outcome: 'completed', url: page.model.url });
          } catch (error) {
            const failure = normalizedFailure(error);
            record({ pageId: page.model.id, actionType: action.action, outcome: 'failed', url: page.model.url, code: failure.code });
            throw failure;
          }
        };
        const deterministic = async (): Promise<'complete' | 'unsupported'> => {
          if (!this.options.workflowPlanner) return 'unsupported';
          let executedActions = 0;
          while (true) {
            active();
            const rawPage = await session.inspect();
            const decision = await this.options.workflowPlanner.next({ target: this.options.target,
              persona: session.persona, workflow, page: rawPage, executedActions });
            if (decision.outcome !== 'action') return decision.outcome;
            await executeNative(decision.action); executedActions++;
          }
        };
        let recipe: readonly BrowserAction[] | undefined;
        try { recipe = this.options.resolveGoal?.(context, workflow); }
        catch { throw new BrowserWorkflowFailure('invalid-workflow'); }
        let deterministicComplete = false;
        if (recipe) {
          if (recipe.length > this.budgets.maxActions) throw new BrowserWorkflowFailure('invalid-workflow');
          // Authorize every configured destination before the first potentially mutating step.
          for (const action of recipe) {
            if ('url' in action) session.assertUrl(action.url);
            if ('response' in action && action.response) session.assertUrl(action.response.url);
          }
          try { for (const action of recipe) await executeNative(action); deterministicComplete = true; }
          catch (error) { recover(normalizedFailure(error)); }
        } else if (this.options.workflowPlanner) {
          try { deterministicComplete = await deterministic() === 'complete'; }
          catch (error) { recover(normalizedFailure(error)); }
        }
        if (deterministicComplete) {
          if (!this.options.completion) { completion = 'recipe-completed'; return; }
          if (await isComplete()) return;
          if (!planner || recoveries >= this.budgets.maxRecoveryAttempts) throw new BrowserWorkflowFailure('unable-to-proceed');
          recoveries++;
        }
        if (!planner) throw new BrowserWorkflowFailure('unable-to-proceed');
        if (!recipe && !deterministicComplete) {
          if (await isComplete()) return;
          const entry = await inspect();
          // Authentication verification may leave a JSON endpoint, and anonymous
          // sessions start blank. The trusted project URL is the generic UI entry.
          if ((entry.model.url === 'about:blank' || entry.model.interactiveElements.length === 0)
            && entry.model.url !== safeUrl(context.project.baseUrl)) {
            const entryUrl = session.assertUrl(context.project.baseUrl);
            await executeNative({ action: 'navigate', url: entryUrl });
          }
        }
        while (true) {
          active();
          if (await isComplete()) return;
          const page = await inspect();
          let proposal;
          try {
            proposal = await planner.next({ goal: workflow.goal, pageModel: page.model, history: [...history],
              target: { id: this.options.target.id, baseOrigins: [...this.options.target.baseOrigins] },
              persona: { id: session.persona.id, label: session.persona.label, roles: [...session.persona.roles] }, signal });
          } catch (error) {
            const failure = normalizedFailure(error);
            // Explicit trusted planner can handle provider/schema failure; policy denials never reach this path.
            if (this.options.workflowPlanner && ['unable-to-proceed', 'invalid-workflow', 'model-budget'].includes(failure.code)) {
              try {
                if (await deterministic() === 'complete') {
                  if (!this.options.completion) { completion = 'recipe-completed'; return; }
                  if (await isComplete()) return;
                }
              } catch (fallbackError) { throw normalizedFailure(fallbackError); }
            }
            throw failure;
          }
          // Inspect after provider latency. IDs include state + a workflow-local nonce.
          const fresh = await inspect();
          const repeatKey = JSON.stringify([proposal.pageId, proposal.actionType, proposal.elementId, proposal.navigationId, proposal.inputRef]);
          repeats.set(repeatKey, (repeats.get(repeatKey) ?? 0) + 1);
          if (repeats.get(repeatKey)! > 2) throw new BrowserWorkflowFailure('unable-to-proceed');
          let validated;
          try {
            if (page.stateId && fresh.stateId && page.stateId !== fresh.stateId) throw new BrowserWorkflowFailure('invalid-workflow');
            validated = validator.validate(proposal, fresh, session);
          }
          catch (error) {
            const failure = normalizedFailure(error);
            record({ pageId: fresh.model.id, actionType: proposal.actionType, outcome: 'rejected', url: fresh.model.url, code: failure.code });
            throw failure;
          }
          if (validated.kind === 'complete') {
            if (this.options.completion) {
              if (!await isComplete()) throw new BrowserWorkflowFailure('unable-to-proceed');
            } else completion = 'planner-assessed';
            return;
          }
          countAction();
          try {
            if (validated.kind === 'native') await session.perform(validated.action);
            if (validated.kind === 'credential') await session.fillCredential(validated.selector, validated.field, validated.guard);
            record({ pageId: fresh.model.id, actionType: proposal.actionType,
              ...(proposal.elementId ? { elementId: proposal.elementId } : {}), outcome: 'completed', url: fresh.model.url });
          } catch (error) {
            const failure = normalizedFailure(error);
            record({ pageId: fresh.model.id, actionType: proposal.actionType, outcome: 'failed', url: fresh.model.url, code: failure.code });
            recover(failure);
          }
        }
      }, originalSession.signal, this.budgets.maxWorkflowMs);
    }, this.options.target);
    return freeze({ ...observation, evidence: [...observation.evidence, {
      id: `workflow-evidence:${randomUUID()}`, projectId: context.project.id, producerId: this.id,
      kind: 'browser-observation', capturedAt: new Date().toISOString(), identityId: workflow.identityId,
      summary: 'Bounded browser workflow planning outcome', facts: {
        workflowId: workflow.id, completion: observation.outcome === 'COMPLETED' ? completion : 'unconfirmed',
        modelCalls: planner?.usage.modelCalls ?? 0, modelTokens: planner?.usage.tokens ?? 0,
        actions, recoveryAttempts: recoveries,
        ...(finalPage ? { pageId: finalPage.id, url: finalPage.url } : {})
      }
    }] });
  }
}

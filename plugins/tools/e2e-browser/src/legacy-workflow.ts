import { BrowserWorkflowFailure, type BrowserWorkflow, type BrowserWorkflowSession,
  type TargetApplicationProfile, type WorkflowPlanner } from '@agento/core';

/** Compatibility orchestration for existing trusted deterministic planner callbacks. */
export function legacyWorkflowExecutor(planner: WorkflowPlanner, target: TargetApplicationProfile,
  workflow: BrowserWorkflow): (session: BrowserWorkflowSession) => Promise<void> {
  return async session => {
    for (let executedActions = 0; ; executedActions++) {
      const decision = await planner.next(freeze({
        target: { id: target.id, baseOrigins: [...target.baseOrigins],
          ...(target.workflowHints ? { workflowHints: structuredClone(target.workflowHints) } : {}) },
        persona: structuredClone(session.persona), workflow: structuredClone(workflow),
        page: await session.inspect(), executedActions,
      }));
      if (decision.outcome === 'complete') return;
      if (decision.outcome !== 'action') throw new BrowserWorkflowFailure('invalid-workflow');
      await session.perform(structuredClone(decision.action));
    }
  };
}
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value); for (const child of Object.values(value)) freeze(child);
  }
  return value;
}

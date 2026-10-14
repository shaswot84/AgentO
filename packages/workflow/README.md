# AgentO Workflow

Optional semantic browser planning above a deterministic browser driver. Trusted
recipes run first and make no model calls. Unfamiliar interfaces and safe selector
failures can use structured model proposals, with local validation before execution.

## Use

```ts
import { BrowserWorkflowOrchestrator, LLMWorkflowPlanner } from '@agento/workflow';

const workflows = new BrowserWorkflowOrchestrator({
  driver: browserDriver,
  target: targetProfile,
  resolveGoal: trustedRecipeResolver,
  semanticPlanner: new LLMWorkflowPlanner(modelProvider),
  completion: ({ pageModel, network }) =>
    pageModel.url.endsWith('/purchases/latest') &&
    network.some(request => !request.blocked && request.status === 200 &&
      request.url.endsWith('/api/purchases/latest')),
});

const observation = await workflows.observe(context, {
  id: 'open-purchase', identityId: 'buyer', goal: 'Open the newest purchase',
});
```

The target, authentication, personas, recipes and completion predicate are trusted
caller configuration. `execute(context, plan)` delegates existing structured
security test plans unchanged. `RecipeWorkflowPlanner` also implements the existing
deterministic planner contract. `OpenAIModelProvider` is supplied by the separate
`@agento/model-openai` adapter; this package has no model SDK dependency.

Without a matching recipe, semantic workflows starting blank or at a verification
endpoint without controls navigate once to the trusted `context.project.baseUrl`.
This entry step keeps native scope guards and uses no application route assumptions.

## Boundaries

- `PageInspector` creates bounded, redacted, explicitly untrusted page data. Local
  selector mappings and native freshness guards never enter model requests.
- `LLMWorkflowPlanner` sends only the goal, normalized page model and bounded
  history. Structured responses must match `PLANNED_ACTION_SCHEMA`.
- `ActionValidator` rejects unknown, stale, disabled and incompatible references.
  Native navigation, redirects and network requests retain runtime scope guards.
  Navigation candidates dispatch through their fresh local links, preserving
  private query values without reconstructing URLs from redacted model data.
- Credential fills accept only `credential.username` and `credential.password`.
  An explicit `CredentialPolicy` must allow the active persona, origin and field
  before the browser privately resolves credentials. Permission is denied by default.
- A deterministic completion predicate takes precedence over a model completion
  claim. Without one, evidence records `planner-assessed` provenance. Neither
  workflow completion nor model confidence establishes a vulnerability verdict.
- Safe browser/selector failures can recover within budget. Scope and credential
  denials stop the workflow. Provider failure can use an explicitly configured
  deterministic planner; errors and provider payloads stay out of evidence.

## Defaults

| Limit | Default |
| --- | ---: |
| Browser actions / history entries / recovery attempts | 100 / 10 / 1 |
| Workflow time | 60 seconds |
| Model calls / aggregate reported tokens | 8 / 16,000 |
| Input characters, including instructions and schema | 24,000 |
| Output tokens / output characters | 600 / 8,000 |
| Model call time / retries / minimum confidence | 10 seconds / 1 / 0.5 |

Configure workflow limits through `budgets` and model limits through
`LLMWorkflowPlanner(provider, options)`. Limits are validated, finite and isolated
per workflow. Invalid or excessive token usage fails closed. Failed calls without
usage are charged conservatively. Recipes still run with `maxModelCalls: 0`.
Repeated ineffective proposals stop after two completed attempts on the same state.

## Verify

Build `../core` first, then run `npm ci` and `npm run check` here. Unit tests use
`FakeModelProvider`, which accepts queued results or a response function and records
bounded requests. No API key or paid API is needed. Browser integration tests live
with the browser driver. Live provider behavior requires separate explicit
configuration; the verification suite uses fake models and mocked transport.

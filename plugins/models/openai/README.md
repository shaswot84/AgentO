# OpenAI model provider

Optional implementation of the core `ModelProvider` contract using the OpenAI Responses API. It returns normalized JSON and token usage; the workflow planner and deterministic validator decide whether any proposed action is allowed.

```ts
import { OpenAIModelProvider } from '@agento/model-openai';

const provider = new OpenAIModelProvider({
  model: selectedModelId,
  resolveApiKey: async (signal) => backendSecrets.resolve('openai-api-key', signal),
});
```

Select a model that supports [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses) (such as `gemma4:31b` via Ollama Cloud or OpenAI models). An optional `endpoint` can be specified to target OpenAI-compatible services like Ollama Cloud (`https://ollama.com/v1/responses`). Resolve the API key in the backend; never put keys, passwords, cookies or tokens in planner input.

For convenience, `createOpenAIModelProvider()` instantiates a provider using environment variables (`OPENAI_API_KEY` / `OLLAMA_API_KEY`, `OPENAI_BASE_URL` / `OLLAMA_BASE_URL`, and `OPENAI_MODEL` / `OLLAMA_MODEL` defaulting to `gemma4:31b`):

```ts
import { createOpenAIModelProvider } from '@agento/model-openai';

const provider = createOpenAIModelProvider();
```

Each request uses strict `text.format` JSON schema, `store: false`, no tools, disabled truncation and the configured endpoint (defaulting to `https://api.openai.com/v1/responses`). Markdown code fences (` ```json `) emitted by open-weight models are safely stripped during JSON extraction. Redirects are rejected. Requests default to a 256 KiB limit; responses are read with a 512 KiB limit. Output tokens default to a maximum of 16,384, and the request deadline defaults to a maximum of 120 seconds. Caller requests must fit these configured ceilings; optional ceilings can be lowered or raised within the adapter's hard limits.

Refusals, incomplete responses, unsupported output, malformed JSON, missing usage, HTTP failures, cancellation and timeout return stable codes. Server text, exception details and raw API objects are discarded. Valid reported usage is preserved when available; transport failures and timeouts may have no reported usage, so callers should reserve their token budget before dispatching.

`fetch` injection is for trusted backend transports and mocked tests. Ordinary tests never make live API calls or access API credentials. Live integration tests can be run explicitly via `npm run test:integration` when configured with valid credentials.

```sh
npm install
npm run check
npm run test:integration
```

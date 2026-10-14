# OpenAI model provider

Optional implementation of the core `ModelProvider` contract using the OpenAI Responses API. It returns normalized JSON and token usage; the workflow planner and deterministic validator decide whether any proposed action is allowed.

```ts
import { OpenAIModelProvider } from '@agento/model-openai';

const provider = new OpenAIModelProvider({
  model: selectedModelId,
  resolveApiKey: async (signal) => backendSecrets.resolve('openai-api-key', signal),
});
```

Select a model that supports [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses). There is no default model and no automatic environment-key lookup. Resolve the API key in the backend; never put keys, passwords, cookies or tokens in planner input.

Each request uses strict `text.format` JSON schema, `store: false`, no tools, disabled truncation and the fixed `https://api.openai.com/v1/responses` endpoint. Redirects are rejected. Requests default to a 256 KiB limit; responses are read with a 512 KiB limit. Output tokens default to a maximum of 16,384, and the request deadline defaults to a maximum of 120 seconds. Caller requests must fit these configured ceilings; optional ceilings can be lowered or raised within the adapter's hard limits.

Refusals, incomplete responses, unsupported output, malformed JSON, missing usage, HTTP failures, cancellation and timeout return stable codes. Server text, exception details and raw API objects are discarded. Valid reported usage is preserved when available; transport failures and timeouts may have no reported usage, so callers should reserve their token budget before dispatching.

`fetch` injection is for trusted backend transports and mocked tests. Ordinary tests never make live API calls or access API credentials.

```sh
npm install
npm run check
```

import { describe, expect, it } from 'vitest';
import { createOpenAIModelProvider } from '../src/index.js';

const suite = process.env.AGENTO_OPENAI_INTEGRATION === '1' ? describe : describe.skip;

suite('Ollama Cloud / OpenAI live integration', () => {
  it('generates structured outputs matching schema using configured provider', async () => {
    const provider = createOpenAIModelProvider();
    const result = await provider.generateStructured({
      instructions: 'Answer with a JSON object conforming strictly to the schema.',
      input: { question: 'What is 5 plus 7?' },
      schema: {
        name: 'addition_result',
        jsonSchema: {
          type: 'object',
          properties: {
            answer: { type: 'number' },
            explanation: { type: 'string' },
          },
          required: ['answer'],
          additionalProperties: false,
        },
      },
      maxOutputTokens: 100,
      timeoutMs: 30_000,
      signal: new AbortController().signal,
    });

    expect(result.status).toBe('completed');
    if (result.status === 'completed') {
      expect(result.value).toHaveProperty('answer', 12);
      expect(result.usage.inputTokens).toBeGreaterThan(0);
      expect(result.usage.outputTokens).toBeGreaterThan(0);
    }
  });
});

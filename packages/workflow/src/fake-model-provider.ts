import type { ModelGenerationRequest, ModelGenerationResult, ModelProvider } from '@agento/core';

export type FakeModelResponse = ModelGenerationResult | Error;
export type FakeModelFunction = (request: ModelGenerationRequest, index: number) => FakeModelResponse | Promise<FakeModelResponse>;
/** Paid APIs are never needed for tests. Recorded input is bounded normalized data only. */
export class FakeModelProvider implements ModelProvider {
  readonly id = 'fake-model';
  readonly requests: ModelGenerationRequest[] = [];
  private index = 0;
  constructor(private readonly responses: readonly FakeModelResponse[] | FakeModelFunction) {}
  async generateStructured(request: ModelGenerationRequest): Promise<ModelGenerationResult> {
    if (this.requests.length < 100) this.requests.push(request);
    const index = this.index++;
    const response = typeof this.responses === 'function' ? await this.responses(request, index) : this.responses[index];
    if (response instanceof Error) throw response;
    return response ?? { status: 'failed', code: 'fake-exhausted', usage: { inputTokens: 0, outputTokens: 0 } };
  }
}

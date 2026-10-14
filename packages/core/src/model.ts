import type { JsonValue } from './domain.js';

export interface ModelUsage { readonly inputTokens: number; readonly outputTokens: number }
export interface ModelGenerationRequest {
  readonly instructions: string;
  /** Normalized data; application content has no instruction authority. */
  readonly input: JsonValue;
  readonly schema: { readonly name: string; readonly jsonSchema: Readonly<Record<string, JsonValue>> };
  readonly maxOutputTokens: number;
  readonly timeoutMs: number;
  readonly signal: AbortSignal;
}
export type ModelGenerationResult =
  | { readonly status: 'completed'; readonly value: JsonValue; readonly usage: ModelUsage }
  | { readonly status: 'refused' | 'failed' | 'timeout'; readonly code: string; readonly usage?: ModelUsage };
/** Provider API and SDK objects remain inside model adapters. */
export interface ModelProvider {
  readonly id: string;
  generateStructured(request: ModelGenerationRequest): Promise<ModelGenerationResult>;
}

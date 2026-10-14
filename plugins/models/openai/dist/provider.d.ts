import type { ModelGenerationRequest, ModelGenerationResult, ModelProvider } from '@agento/core';
export interface OpenAIModelProviderOptions {
    /** Explicit API model id; this adapter never selects a default model. */
    readonly model: string;
    /** Backend-only resolver. The API key is never part of the model request input. */
    readonly resolveApiKey: (signal: AbortSignal) => string | undefined | Promise<string | undefined>;
    /** Trusted transport injection for tests; production uses native fetch. */
    readonly fetch?: typeof globalThis.fetch;
    readonly maxRequestBytes?: number;
    readonly maxResponseBytes?: number;
    readonly maxOutputTokens?: number;
    readonly maxTimeoutMs?: number;
}
/** Optional provider; generation never executes browser actions or confirms findings. */
export declare class OpenAIModelProvider implements ModelProvider {
    private readonly options;
    readonly id = "openai";
    private readonly transport;
    private readonly maxRequestBytes;
    private readonly maxResponseBytes;
    private readonly maxOutputTokens;
    private readonly maxTimeoutMs;
    constructor(options: OpenAIModelProviderOptions);
    generateStructured(request: ModelGenerationRequest): Promise<ModelGenerationResult>;
    private generate;
}

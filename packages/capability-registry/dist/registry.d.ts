import type { CapabilityResolution, LookupRequest, RegistryOptions, SelectionRequest, ToolAvailability, ToolMetadata, ToolRegistration } from './contracts.js';
/** Selects adapters, then binds their existing runtime ports. It does not execute probes or tools. */
export declare class CapabilityRegistry {
    private readonly tools;
    private readonly timeoutMs;
    private readonly probes;
    constructor(options?: RegistryOptions);
    register(adapter: ToolRegistration): this;
    list(): readonly ToolMetadata[];
    /** Returns all compatible candidates in stable preference order, without running checks. */
    lookup(request: LookupRequest): readonly ToolMetadata[];
    /** Fresh checks on each call; the report contains no executable paths or callback output. */
    preflight(options?: {
        readonly signal?: AbortSignal;
    }): Promise<readonly ToolAvailability[]>;
    resolvePlan(plan: SelectionRequest, options?: {
        readonly signal?: AbortSignal;
    }): Promise<CapabilityResolution>;
    resolveProbe(probeId: string, request: Omit<SelectionRequest, 'probeId' | 'requiredCapabilities'> & {
        readonly requiredCapabilities?: readonly string[];
    }, options?: {
        readonly signal?: AbortSignal;
    }): Promise<CapabilityResolution>;
    resolve(input: SelectionRequest, options?: {
        readonly signal?: AbortSignal;
    }): Promise<CapabilityResolution>;
    private entries;
    private check;
}

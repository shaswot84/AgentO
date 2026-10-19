import type { ExecutionGuard } from '@agento/core';
import { CapabilityRegistry } from '@agento/runtime';
import type { CapabilityResolution } from '@agento/capability-registry';
export interface BindingHost {
    readonly signal: AbortSignal;
    readonly allowedOrigins: readonly string[];
    guardFor(toolId: string): ExecutionGuard;
    tool<T>(toolId: string, execute: () => Promise<T>): Promise<T>;
}
export declare function bindCapabilities(resolution: CapabilityResolution, host: BindingHost): {
    capabilities: CapabilityRegistry;
    close: () => Promise<void>;
};

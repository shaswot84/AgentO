import type { CWEId } from '@agento/core';
import type { CWEMetadata, CWEPlugin } from './contracts.js';
/** Registration only: this registry never dispatches probes or chooses vulnerability logic. */
export declare class CWEPluginRegistry {
    private readonly entries;
    register(plugin: CWEPlugin): this;
    get(cweId: CWEId): CWEPlugin;
    plugins(): readonly CWEPlugin[];
    list(): readonly CWEMetadata[];
}

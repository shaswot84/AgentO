import type { CWEId } from '@agento/core';
import type { CWEMetadata, CWEPlugin } from './contracts.js';
import { freeze } from './shared.js';

/** Registration only: this registry never dispatches probes or chooses vulnerability logic. */
export class CWEPluginRegistry {
  private readonly entries = new Map<CWEId, CWEPlugin>();
  register(plugin: CWEPlugin): this {
    if (!/^CWE-\d+$/.test(plugin.cweId) || plugin.metadata().cweId !== plugin.cweId || this.entries.has(plugin.cweId)) {
      throw new Error('Invalid or duplicate CWE plugin');
    }
    this.entries.set(plugin.cweId, plugin); return this;
  }
  get(cweId: CWEId): CWEPlugin {
    const plugin = this.entries.get(cweId);
    if (!plugin) throw new Error('CWE plugin is not registered');
    return plugin;
  }
  plugins(): readonly CWEPlugin[] { return Object.freeze([...this.entries.values()]); }
  list(): readonly CWEMetadata[] { return freeze([...this.entries.values()].map(plugin => structuredClone(plugin.metadata()))); }
}

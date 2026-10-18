import { freeze } from './shared.js';
/** Registration only: this registry never dispatches probes or chooses vulnerability logic. */
export class CWEPluginRegistry {
    entries = new Map();
    register(plugin) {
        if (!/^CWE-\d+$/.test(plugin.cweId) || plugin.metadata().cweId !== plugin.cweId || this.entries.has(plugin.cweId)) {
            throw new Error('Invalid or duplicate CWE plugin');
        }
        this.entries.set(plugin.cweId, plugin);
        return this;
    }
    get(cweId) {
        const plugin = this.entries.get(cweId);
        if (!plugin)
            throw new Error('CWE plugin is not registered');
        return plugin;
    }
    plugins() { return Object.freeze([...this.entries.values()]); }
    list() { return freeze([...this.entries.values()].map(plugin => structuredClone(plugin.metadata()))); }
}

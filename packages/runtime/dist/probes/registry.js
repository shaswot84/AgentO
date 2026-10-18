import { freeze, RuntimeError } from '../safety.js';
export class CapabilityRegistry {
    entries = new Map();
    register(id, capability) {
        if (this.entries.has(id) || !capability)
            throw new RuntimeError('invalid-request');
        this.entries.set(id, capability);
        return this;
    }
    has(id) { return this.entries.has(id); }
    get(id) {
        if (!this.entries.has(id))
            throw new RuntimeError('unsupported-capability');
        return this.entries.get(id);
    }
}
export class ProbeRegistry {
    entries = new Map();
    register(id, probe) {
        if (this.entries.has(id) || probe.metadata().id !== id)
            throw new RuntimeError('invalid-request');
        this.entries.set(id, probe);
        return this;
    }
    get(id) {
        if (!this.entries.has(id))
            throw new RuntimeError('unsupported-capability');
        return this.entries.get(id);
    }
    list() {
        return freeze([...this.entries.values()].map(probe => structuredClone(probe.metadata())));
    }
}

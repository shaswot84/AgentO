import type {
  AuthenticationManager, BrowserController, CookieAnalyzer, CookieInspector,
  HeaderAnalyzer, RequestExecutor, ResponseCollector,
} from '../contracts.js';
import { freeze, RuntimeError } from '../safety.js';
import type {
  AuthorizationContext, AuthorizationEvidence, CookieSecurityContext, CookieSecurityEvidence,
  CrossOriginContext, CrossOriginEvidence, InjectionContext, ProbeMetadata, ResponseComparator,
  SecurityProbe, SQLInjectionEvidence, SQLScanner, XSSEvidence, XSSScanner,
} from './contracts.js';

/** Extend through declaration merging when adding capabilities or probe families. */
export interface CapabilityCatalog {
  'request-executor': RequestExecutor;
  'response-collector': ResponseCollector;
  'header-analyzer': HeaderAnalyzer;
  'cookie-analyzer': CookieAnalyzer;
  'authentication-manager': AuthenticationManager;
  'cookie-inspector': CookieInspector;
  'browser-controller': BrowserController;
  'response-comparator': ResponseComparator;
  'xss-scanner': XSSScanner;
  'sql-scanner': SQLScanner;
}
export class CapabilityRegistry {
  private readonly entries = new Map<keyof CapabilityCatalog, unknown>();
  register<K extends keyof CapabilityCatalog>(id: K, capability: CapabilityCatalog[K]): this {
    if (this.entries.has(id) || !capability) throw new RuntimeError('invalid-request');
    this.entries.set(id, capability); return this;
  }
  has(id: keyof CapabilityCatalog): boolean { return this.entries.has(id); }
  get<K extends keyof CapabilityCatalog>(id: K): CapabilityCatalog[K] {
    if (!this.entries.has(id)) throw new RuntimeError('unsupported-capability');
    return this.entries.get(id) as CapabilityCatalog[K];
  }
}
export interface ProbeCatalog {
  'cookie-security': SecurityProbe<CookieSecurityContext, CookieSecurityEvidence>;
  'cross-origin': SecurityProbe<CrossOriginContext, CrossOriginEvidence>;
  authorization: SecurityProbe<AuthorizationContext, AuthorizationEvidence>;
  xss: SecurityProbe<InjectionContext, XSSEvidence>;
  'sql-injection': SecurityProbe<InjectionContext, SQLInjectionEvidence>;
}
export class ProbeRegistry {
  private readonly entries = new Map<keyof ProbeCatalog, unknown>();
  register<K extends keyof ProbeCatalog>(id: K, probe: ProbeCatalog[K]): this {
    if (this.entries.has(id) || probe.metadata().id !== id) throw new RuntimeError('invalid-request');
    this.entries.set(id, probe); return this;
  }
  get<K extends keyof ProbeCatalog>(id: K): ProbeCatalog[K] {
    if (!this.entries.has(id)) throw new RuntimeError('unsupported-capability');
    return this.entries.get(id) as ProbeCatalog[K];
  }
  list(): readonly ProbeMetadata[] {
    return freeze([...this.entries.values()].map(probe =>
      structuredClone((probe as SecurityProbe<never, unknown>).metadata())));
  }
}

import type { AuthenticationManager, BrowserController, CookieAnalyzer, CookieInspector, HeaderAnalyzer, RequestExecutor, ResponseCollector } from '../contracts.js';
import type { AuthorizationContext, AuthorizationEvidence, CookieSecurityContext, CookieSecurityEvidence, CrossOriginContext, CrossOriginEvidence, InjectionContext, ProbeMetadata, ResponseComparator, SecurityProbe, SQLInjectionEvidence, SQLScanner, XSSEvidence, XSSScanner } from './contracts.js';
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
export declare class CapabilityRegistry {
    private readonly entries;
    register<K extends keyof CapabilityCatalog>(id: K, capability: CapabilityCatalog[K]): this;
    has(id: keyof CapabilityCatalog): boolean;
    get<K extends keyof CapabilityCatalog>(id: K): CapabilityCatalog[K];
}
export interface ProbeCatalog {
    'cookie-security': SecurityProbe<CookieSecurityContext, CookieSecurityEvidence>;
    'cross-origin': SecurityProbe<CrossOriginContext, CrossOriginEvidence>;
    authorization: SecurityProbe<AuthorizationContext, AuthorizationEvidence>;
    xss: SecurityProbe<InjectionContext, XSSEvidence>;
    'sql-injection': SecurityProbe<InjectionContext, SQLInjectionEvidence>;
}
export declare class ProbeRegistry {
    private readonly entries;
    register<K extends keyof ProbeCatalog>(id: K, probe: ProbeCatalog[K]): this;
    get<K extends keyof ProbeCatalog>(id: K): ProbeCatalog[K];
    list(): readonly ProbeMetadata[];
}

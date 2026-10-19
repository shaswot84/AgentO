import type { ScannerRequest, SecurityScannerRequest, XSSScanner } from '@agento/runtime';
import { ScannerAdapter } from './adapter.js';
import type { ScannerOptions } from './contracts.js';
export declare class DalfoxAdapter extends ScannerAdapter implements XSSScanner {
    readonly id = "dalfox-adapter";
    readonly capabilities: readonly string[];
    protected readonly headPreflight = true;
    constructor(options?: ScannerOptions);
    registration(): {
        executable: string;
        checkAvailability(signal: AbortSignal): Promise<boolean>;
        metadata: {
            id: string;
            protocols: readonly ('http' | 'https')[];
            risk: 'active';
            capabilities: readonly ['security-scanner', 'xss-scanner'];
            supportedCwes: readonly ['CWE-79'];
        };
        capabilities: {
            'request-executor'?: import("@agento/runtime").RequestExecutor;
            'response-collector'?: import("@agento/runtime").ResponseCollector;
            'header-analyzer'?: import("@agento/runtime").HeaderAnalyzer;
            'cookie-analyzer'?: import("@agento/runtime").CookieAnalyzer;
            'authentication-manager'?: import("@agento/runtime").AuthenticationManager;
            'cookie-inspector'?: import("@agento/runtime").CookieInspector;
            'browser-controller'?: import("@agento/runtime").BrowserController;
            'response-comparator'?: import("@agento/runtime").ResponseComparator;
            'sql-scanner'?: import("@agento/runtime").SQLScanner;
            'security-scanner'?: import("@agento/runtime").SecurityScannerPort;
            'xss-scanner': {
                scan: (input: ScannerRequest) => Promise<Readonly<{
                    executionConfirmed: null;
                    domSinkReached: null;
                    diagnostic?: "scanner-failed" | "scanner-skipped";
                }>>;
            };
        };
    };
    protected prepare(input: SecurityScannerRequest, url: string, directory: string): Promise<{
        args: string[];
        acceptedExits: number[];
    }>;
    protected normalize(text: string, url: string): import("./contracts.js").ScannerObservation[];
    scan(input: ScannerRequest): Promise<Readonly<{
        executionConfirmed: null;
        domSinkReached: null;
        diagnostic?: "scanner-failed" | "scanner-skipped";
    }>>;
}

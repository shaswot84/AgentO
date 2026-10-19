import type { DatabaseFingerprint, ScannerRequest, SecurityScannerRequest, SQLScanner } from '@agento/runtime';
import { ScannerAdapter } from './adapter.js';
import type { ScannerOptions } from './contracts.js';
export declare class SqlmapAdapter extends ScannerAdapter implements SQLScanner {
    readonly id = "sqlmap-adapter";
    readonly capabilities: readonly string[];
    constructor(options?: ScannerOptions);
    registration(): {
        executable: string;
        checkAvailability(signal: AbortSignal): Promise<boolean>;
        metadata: {
            id: string;
            protocols: readonly ('http' | 'https')[];
            risk: 'active';
            capabilities: readonly ['security-scanner', 'sql-scanner'];
            supportedCwes: readonly ['CWE-89'];
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
            'xss-scanner'?: import("@agento/runtime").XSSScanner;
            'security-scanner'?: import("@agento/runtime").SecurityScannerPort;
            'sql-scanner': {
                scan: (input: ScannerRequest) => Promise<Readonly<{
                    technique: "boolean" | "error" | "time";
                    dbmsFingerprint: DatabaseFingerprint | null;
                    observedDifference: null;
                    diagnostic?: "scanner-failed" | "scanner-skipped";
                }>>;
            };
        };
    };
    protected prepare(input: SecurityScannerRequest, url: string, directory: string): Promise<{
        args: string[];
    }>;
    protected normalize(text: string, url: string): import("./contracts.js").ScannerObservation[];
    scan(input: ScannerRequest): Promise<Readonly<{
        technique: "boolean" | "error" | "time";
        dbmsFingerprint: DatabaseFingerprint | null;
        observedDifference: null;
        diagnostic?: "scanner-failed" | "scanner-skipped";
    }>>;
}

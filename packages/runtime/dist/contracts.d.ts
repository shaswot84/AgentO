import type { BrowserAction, BrowserPageInspection, BrowserWorkflowSession, ExecutionGuard, Persona } from '@agento/core';
export type HttpHeaders = Readonly<Record<string, readonly string[]>>;
export interface HttpRequest {
    readonly url: string;
    readonly method?: string;
    readonly headers?: Readonly<Record<string, string>>;
    readonly body?: string;
    readonly signal?: AbortSignal;
}
export interface ResponseBody {
    readonly encoding: 'base64';
    readonly data: string;
    readonly byteLength: number;
    readonly truncated: boolean;
}
export interface ResponseTimings {
    readonly startedAt: string;
    readonly firstByteMs: number;
    readonly durationMs: number;
}
/** Private backend result: raw headers and body may contain authentication material. */
export interface HttpResponse {
    readonly id: string;
    readonly url: string;
    readonly method: string;
    readonly status: number;
    readonly headers: HttpHeaders;
    readonly body: ResponseBody;
    readonly timings: ResponseTimings;
}
export interface HttpResponseEvidence {
    readonly responseId: string;
    readonly url: string;
    readonly method: string;
    readonly status: number;
    readonly body: {
        readonly sha256: string;
        readonly byteLength: number;
        readonly truncated: boolean;
    };
    readonly timings: ResponseTimings;
}
export interface TransportRequest {
    readonly url: string;
    readonly method: string;
    readonly headers: Readonly<Record<string, string>>;
    readonly body?: string;
    readonly signal: AbortSignal;
    readonly maxBodyBytes: number;
}
export interface TransportResponse {
    readonly status: number;
    readonly headers: HttpHeaders;
    readonly body: Uint8Array;
    readonly truncated: boolean;
    readonly firstByteMs: number;
}
/** A single HTTP exchange, with no redirects, retries, ambient credentials or cookie storage. */
export interface HttpTransport {
    send(request: TransportRequest): Promise<TransportResponse>;
}
export interface RequestExecutor {
    execute(request: HttpRequest): Promise<HttpResponse>;
}
export interface ResponseCollector {
    collect(request: {
        readonly url: string;
        readonly method: string;
    }, response: TransportResponse, timings: ResponseTimings): HttpResponse;
    evidence(response: HttpResponse): HttpResponseEvidence;
}
export interface HeaderEvidence {
    readonly responseId: string;
    readonly cors: {
        readonly allowOrigin: readonly string[];
        readonly allowCredentials: readonly (boolean | null)[];
        readonly allowMethods: readonly string[];
        readonly allowHeaders: readonly string[];
        readonly exposeHeaders: readonly string[];
        readonly maxAge: readonly (number | null)[];
    };
    readonly security: HttpHeaders;
    readonly caching: {
        readonly cacheControl: readonly {
            readonly name: string;
            readonly value: string | null;
        }[];
        readonly pragma: readonly string[];
        readonly vary: readonly string[];
        readonly expires: readonly string[];
        readonly age: readonly (number | null)[];
    };
}
export interface HeaderAnalyzer {
    analyze(response: HttpResponse): Promise<HeaderEvidence>;
}
export interface CookieMetadata {
    readonly name: string;
    readonly domain: string;
    readonly path: string;
    readonly hostOnly: boolean;
    readonly httpOnly: boolean;
    readonly secure: boolean;
    readonly sameSite: 'Strict' | 'Lax' | 'None' | null;
    readonly expiresAt: string | null;
    readonly maxAge: number | null;
    readonly partitioned: boolean;
}
export interface CookieEvidence extends CookieMetadata {
    readonly value: '[REDACTED]';
    readonly source: 'response' | 'browser' | 'jar';
    readonly responseId?: string;
    readonly sessionId?: string;
}
/** Private cookie material, consumed only by trusted backend execution. */
export interface RuntimeCookie extends CookieMetadata {
    readonly value: string;
}
export interface CookieAnalyzer {
    analyze(response: HttpResponse): Promise<readonly CookieEvidence[]>;
}
export type TestIdentity = Persona;
export interface NetworkEvidence {
    readonly sessionId: string;
    readonly identityId: string;
    readonly source: 'browser' | 'http';
    readonly url: string;
    readonly method: string;
    readonly status: number | null;
    readonly blocked: boolean;
}
/** Valid only within BrowserController.withSession; retained handles are revoked. */
export interface BrowserSession {
    readonly id: string;
    readonly identityId: string;
    inspect(): Promise<BrowserPageInspection>;
    perform(action: BrowserAction): Promise<void>;
    network(): readonly NetworkEvidence[];
    cookies(): Promise<readonly CookieEvidence[]>;
    /** Private backend transfer. Never pass to a planner or evidence renderer. */
    transferCookies(): Promise<readonly RuntimeCookie[]>;
    /** Replace the private context jar before subsequent page actions. */
    importCookies(cookies: readonly RuntimeCookie[]): Promise<void>;
    /** Read only a random canary marker. No caller-supplied code is evaluated. */
    readCanary?(marker: string): Promise<{
        readonly executed: boolean;
        readonly elementPresent: boolean;
    }>;
}
export interface BrowserController {
    withGuard?(guard: ExecutionGuard): BrowserController;
    withSession<T>(identity: TestIdentity, execute: (session: BrowserSession) => Promise<T>): Promise<T>;
}
export interface AuthSession {
    readonly id: string;
    readonly identityId: string;
    readonly expiresAt: string;
    readonly http: RequestExecutor;
    withBrowser<T>(execute: (session: BrowserSession) => Promise<T>): Promise<T>;
    cookies(): Promise<readonly CookieEvidence[]>;
    network(): readonly NetworkEvidence[];
    close(): Promise<void>;
}
export interface AuthenticationManager {
    withGuard?(guard: ExecutionGuard): AuthenticationManager;
    establishSession(identity: TestIdentity): Promise<AuthSession>;
    close?(): Promise<void>;
}
export interface NetworkObserver {
    observe(session: BrowserSession | AuthSession): Promise<readonly NetworkEvidence[]>;
}
export interface CookieInspector {
    inspect(session: BrowserSession | AuthSession): Promise<readonly CookieEvidence[]>;
}
/** Runtime uses only the guarded port, never vendor SDK objects. */
export type BrowserCapabilityPort = BrowserWorkflowSession;

import type { AuthSession, AuthenticationManager, BrowserController, TestIdentity } from './contracts.js';
import { type HttpExecutorOptions } from './http.js';
export interface SessionManagerOptions {
    readonly browser: BrowserController;
    readonly http: HttpExecutorOptions;
    readonly identities: readonly TestIdentity[];
    readonly ttlMs?: number;
    readonly maxSessions?: number;
    readonly maxNetworkRecords?: number;
    readonly maxCookies?: number;
}
/** Session-cookie transfer only. Other authentication transports need an explicit binding. */
export declare class RuntimeAuthenticationManager implements AuthenticationManager {
    private readonly options;
    private readonly sessions;
    private readonly pending;
    private readonly identities;
    private readonly scope;
    private readonly ttlMs;
    private readonly maximum;
    private readonly networkMaximum;
    private readonly httpOptions;
    private disposed;
    constructor(options: SessionManagerOptions);
    establishSession(identity: TestIdentity): Promise<AuthSession>;
    private create;
    close(): Promise<void>;
}

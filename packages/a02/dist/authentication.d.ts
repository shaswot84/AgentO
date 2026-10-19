import type { ExecutionGuard } from '@agento/core';
import { DeterministicRequestExecutor } from '@agento/runtime';
import type { AuthenticationManager, AuthSession, HttpRequest, TestIdentity } from '@agento/runtime';
export interface HttpCookieAuthenticationOptions {
    readonly executor: DeterministicRequestExecutor;
    /** Private host callback. Return a same-origin JSON/form login request. */
    readonly login: (identity: TestIdentity) => Promise<HttpRequest>;
}
/** A small HTTP cookie login adapter. Each policy binding and identity gets a fresh jar. */
export declare class HttpCookieAuthenticationManager implements AuthenticationManager {
    private readonly options;
    private readonly guard?;
    private readonly sessions;
    private closed;
    constructor(options: HttpCookieAuthenticationOptions, guard?: ExecutionGuard | undefined);
    withGuard(guard: ExecutionGuard): HttpCookieAuthenticationManager;
    establishSession(identity: TestIdentity): Promise<AuthSession>;
    close(): Promise<void>;
}

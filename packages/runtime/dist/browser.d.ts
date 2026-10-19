import type { AnalysisContext, BrowserContextCookie, BrowserWorkflowRuntimeDriver, ExecutionGuard, TargetApplicationProfile } from '@agento/core';
import type { BrowserController, BrowserSession, CookieInspector, NetworkEvidence, NetworkObserver, RuntimeCookie, TestIdentity } from './contracts.js';
import { RuntimeScope } from './safety.js';
export interface WorkflowBrowserOptions {
    readonly driver: BrowserWorkflowRuntimeDriver;
    readonly context: AnalysisContext;
    readonly target?: TargetApplicationProfile;
    readonly maxNetworkRecords?: number;
}
/** Adapts a workflow driver's guarded lifecycle to reusable runtime capabilities. */
export declare class WorkflowBrowserController implements BrowserController {
    private readonly options;
    private readonly context;
    private readonly target;
    private readonly maximum;
    private readonly scope;
    constructor(options: WorkflowBrowserOptions);
    withGuard(guard: ExecutionGuard): WorkflowBrowserController;
    withSession<T>(identity: TestIdentity, execute: (session: BrowserSession) => Promise<T>): Promise<T>;
}
export declare function fromBrowser(cookie: BrowserContextCookie, scope: RuntimeScope): RuntimeCookie;
export declare class SessionNetworkObserver implements NetworkObserver {
    observe(session: Parameters<NetworkObserver['observe']>[0]): Promise<readonly NetworkEvidence[]>;
}
export declare class SessionCookieInspector implements CookieInspector {
    inspect(session: Parameters<CookieInspector['inspect']>[0]): Promise<readonly import("./contracts.js").CookieEvidence[]>;
}

import type { CookieAnalyzer, CookieEvidence, HttpResponse, RuntimeCookie } from './contracts.js';
import { RuntimeScope } from './safety.js';
export declare function defaultCookiePath(path: string): string;
export declare function parseSetCookie(line: string, responseUrl: string, now?: number): RuntimeCookie | undefined;
export declare function cookieEvidence(cookie: RuntimeCookie, source: CookieEvidence['source'], reference?: {
    responseId?: string;
    sessionId?: string;
}): CookieEvidence;
export declare class NormalizedCookieAnalyzer implements CookieAnalyzer {
    analyze(response: HttpResponse): Promise<readonly CookieEvidence[]>;
}
/** Private, bounded jar. Every cookie is bound to an exact origin in addition to domain/path. */
export declare class SessionCookieJar {
    private readonly scope;
    private readonly entries;
    private readonly maximum;
    constructor(scope: RuntimeScope, maximum?: number);
    update(response: HttpResponse): void;
    replaceFromBrowser(cookies: readonly RuntimeCookie[], origin: string): void;
    private transaction;
    private validate;
    private set;
    private prune;
    header(requestUrl: string): string;
    privateCookies(origin?: string): readonly RuntimeCookie[];
    inspect(sessionId: string): readonly CookieEvidence[];
    clear(): void;
}

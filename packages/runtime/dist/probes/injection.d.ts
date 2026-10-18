import type { AuthSession, RequestExecutor } from '../contracts.js';
import type { InjectionContext, ScannerRequest } from './contracts.js';
export declare function withInjectionExecutor<T>(context: InjectionContext, execute: (executor: RequestExecutor, session?: AuthSession) => Promise<T>): Promise<T>;
export declare function scan<T>(context: InjectionContext, executor: RequestExecutor, canary: string, invoke: (input: ScannerRequest) => Promise<T>): Promise<T>;

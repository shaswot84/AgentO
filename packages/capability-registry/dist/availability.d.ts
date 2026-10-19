import type { AvailabilityCode, ToolAvailability } from './contracts.js';
/** File-only check. Never interpolate a command, spawn a process or return a private path. */
export declare function executableAvailable(command: string): Promise<boolean>;
export declare function validExecutable(command: unknown): command is string;
export declare function checkAvailability(toolId: string, check: (signal: AbortSignal) => Promise<AvailabilityCode>, timeoutMs: number, signal?: AbortSignal): Promise<ToolAvailability>;

import type { FrameworkAdapter, Project } from '@agento/core';

export type DependencyKind = 'dependencies' | 'devDependencies' | 'optionalDependencies' | 'peerDependencies';

export interface DiscoveredDependency {
  readonly name: string;
  readonly version: string;
  readonly kind: DependencyKind;
  /** Repository-relative package.json path. Transitive lockfile entries are excluded. */
  readonly manifest: string;
}

export interface DiscoveredManifest {
  readonly file: string;
  readonly directory: string;
  readonly name?: string;
  readonly workspacePatterns: readonly string[];
}

/** Probable middleware, not proof of mounting, configuration, or vulnerability. */
export interface MiddlewareObservation {
  readonly kind: 'cors' | 'session' | 'cookie';
  readonly name: string;
  readonly file: string;
  readonly basis: 'dependency' | 'import' | 'header';
  readonly line?: number;
}

export interface DiscoveryDiagnostic {
  readonly code: 'repository-unavailable' | 'read-failed' | 'invalid-manifest' | 'parse-failed' | 'limit-reached';
  readonly file: string;
  readonly message: string;
}

/** Only register real, installed adapters. Metadata advertises compatibility;
 * the core still calls adapter.supports(project) before extraction. */
export interface RegisteredFrameworkAdapter {
  readonly framework: string;
  readonly languages: readonly string[];
  readonly adapter: FrameworkAdapter;
}

export interface DiscoveryOptions {
  readonly adapters?: readonly RegisteredFrameworkAdapter[];
}

export interface DiscoveryResult {
  readonly repositoryPath: string;
  readonly name: string;
  readonly languages: readonly string[];
  readonly frameworks: readonly string[];
  readonly dependencies: readonly DiscoveredDependency[];
  /** Probable engines, ORM packages, and auth styles; configuration is not evaluated. */
  readonly databases: readonly string[];
  readonly orms: readonly string[];
  readonly authentication: readonly ('session' | 'jwt' | 'passport' | 'auth-provider')[];
  readonly authenticationPackages: readonly string[];
  readonly middleware: readonly MiddlewareObservation[];
  readonly structure: {
    readonly manifests: readonly DiscoveredManifest[];
    readonly directories: readonly string[];
    readonly sourceDirectories: readonly string[];
    readonly testDirectories: readonly string[];
    readonly staticDirectories: readonly string[];
    readonly sourceFileCount: number;
  };
  readonly expressAdapterAvailable: boolean;
  readonly availableAdapterIds: readonly string[];
  readonly supportedCodeAwareMode: boolean;
  readonly mode: Project['mode'];
  readonly fallbackReasons: readonly string[];
  readonly diagnostics: readonly DiscoveryDiagnostic[];
}

export interface ProjectTarget {
  readonly id: string;
  readonly name?: string;
  readonly baseUrl: string;
  /** Caller-supplied scope declaration; discovery grants no authorization. */
  readonly allowedOrigins: readonly string[];
}

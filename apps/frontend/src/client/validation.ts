import type { DiscoveryResult } from '@agento/discovery';
import type { ProjectInput, ProjectInputErrors } from './types';

function httpUrl(value: string): URL | undefined {
  if (value.length > 4096 || !/^https?:\/\//iu.test(value) || /[\u0000-\u0020\u007f\\]/u.test(value)
    || /^https?:\/\/[^/?#]*@/iu.test(value)) return undefined;
  try {
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hostname.includes('*')) return undefined;
    return parsed;
  } catch {
    return undefined;
  }
}

/** Format and declared-scope checks only; this does not grant target authorization. */
export function validateProjectInput(input: ProjectInput): ProjectInputErrors {
  const errors: ProjectInputErrors = {};
  if (!input.name.trim()) errors.name = 'Enter a project name.';
  else if (input.name.trim().length > 120) errors.name = 'Use a name with 120 characters or fewer.';
  if (!input.repositoryPath.trim()) errors.repositoryPath = 'Enter a repository path.';
  else if (input.repositoryPath.length > 4096 || /[\u0000-\u001f\u007f]/u.test(input.repositoryPath)) {
    errors.repositoryPath = 'Enter a valid repository path.';
  }

  const target = httpUrl(input.baseUrl.trim());
  if (!target) errors.baseUrl = 'Enter an HTTP or HTTPS target URL without credentials.';

  if (input.allowedOrigins.length === 0) {
    errors.allowedOrigins = 'Declare at least one allowed origin.';
  } else if (input.allowedOrigins.length > 100) {
    errors.allowedOrigins = 'Declare 100 origins or fewer.';
  } else {
    const origins = input.allowedOrigins.map((value) => {
      const normalized = value.trim();
      const parsed = httpUrl(normalized);
      return parsed && parsed.pathname === '/' && !normalized.includes('?') && !normalized.includes('#') ? parsed.origin : undefined;
    });
    if (origins.some((value) => value === undefined)) {
      errors.allowedOrigins = 'Use explicit HTTP or HTTPS origins without paths, credentials, queries, or wildcards.';
    } else if (target && !origins.includes(target.origin)) {
      errors.allowedOrigins = 'The allowlist must include the target URL origin.';
    }
  }
  return errors;
}

type Guard = (value: unknown) => boolean;
const string: Guard = (value) => typeof value === 'string' && value.length <= 4096;
const boolean: Guard = (value) => typeof value === 'boolean';
const nonNegativeInteger: Guard = (value) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const positiveInteger: Guard = (value) => nonNegativeInteger(value) && (value as number) > 0;
const enumeration = (...options: readonly string[]): Guard => (value) => typeof value === 'string' && options.includes(value);

function object(required: Readonly<Record<string, Guard>>, optional: Readonly<Record<string, Guard>> = {}): Guard {
  return (value) => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length > Object.keys(required).length + Object.keys(optional).length) return false;
    for (const key of keys) {
      if (typeof key !== 'string' || key === '__proto__' || key === 'constructor' || key === 'prototype') return false;
      const descriptor = descriptors[key];
      const guard = Object.hasOwn(required, key) ? required[key] : Object.hasOwn(optional, key) ? optional[key] : undefined;
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || !guard || !guard(descriptor.value)) return false;
    }
    return Object.keys(required).every((key) => Object.hasOwn(descriptors, key));
  };
}

function array(item: Guard): Guard {
  return (value) => {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > 20000) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).length !== value.length + 1) return false;
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[index];
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || !item(descriptor.value)) return false;
    }
    return true;
  };
}

const strings = array(string);
const discoveryGuard = object({
  repositoryPath: string,
  name: string,
  languages: strings,
  frameworks: strings,
  dependencies: array(object({ name: string, version: string,
    kind: enumeration('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'), manifest: string })),
  databases: strings,
  orms: strings,
  authentication: array(enumeration('session', 'jwt', 'passport', 'auth-provider')),
  authenticationPackages: strings,
  middleware: array(object({ kind: enumeration('cors', 'session', 'cookie'), name: string, file: string,
    basis: enumeration('dependency', 'import', 'header') }, { line: positiveInteger })),
  structure: object({
    manifests: array(object({ file: string, directory: string, workspacePatterns: strings }, { name: string })),
    directories: strings, sourceDirectories: strings, testDirectories: strings, staticDirectories: strings,
    sourceFileCount: nonNegativeInteger,
  }),
  expressAdapterAvailable: boolean,
  availableAdapterIds: strings,
  supportedCodeAwareMode: boolean,
  mode: enumeration('code-aware', 'black-box'),
  fallbackReasons: strings,
  diagnostics: array(object({ code: enumeration('repository-unavailable', 'read-failed', 'invalid-manifest', 'parse-failed', 'limit-reached'),
    file: string, message: string })),
});

export type SavedDiscoveryParseResult = { readonly ok: true; readonly value: DiscoveryResult }
  | { readonly ok: false; readonly error: string };

/** Reject malformed uploads, inherited fields, accessors, extra keys, and unsafe shapes.
 * Error text never echoes upload data, filenames, or parser diagnostics. */
export function parseSavedDiscovery(value: unknown): SavedDiscoveryParseResult {
  const error = 'This file is not a valid saved AgentO discovery result.';
  try {
    if (!discoveryGuard(value)) return { ok: false, error };
    const result = value as DiscoveryResult;
    if ((result.mode === 'code-aware') !== result.supportedCodeAwareMode) return { ok: false, error };
    // Copy only after validating every property as ordinary JSON data.
    const serialized = JSON.stringify(result);
    if (new TextEncoder().encode(serialized).byteLength > 2 * 1024 * 1024) return { ok: false, error };
    return { ok: true, value: JSON.parse(serialized) as DiscoveryResult };
  } catch {
    return { ok: false, error };
  }
}

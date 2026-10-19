export { ExpressRemediationProvider } from './provider.js';
export { RemediationError } from './contracts.js';
export type { ExpressRemediationOptions, SourceSnapshot, PreparedRemediation, RemediationErrorCode } from './contracts.js';
export { sha256 as sourceDigest } from './value.js';
/** Files the host snapshots; source content never enters the provider through a filesystem port. */
export declare const EXPRESS_STOREFRONT_SOURCE_PATHS: readonly string[];

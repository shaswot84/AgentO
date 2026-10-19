export { ExpressRemediationProvider } from './provider.js';
export { RemediationError } from './contracts.js';
export type { ExpressRemediationOptions, SourceSnapshot, PreparedRemediation, RemediationErrorCode } from './contracts.js';
export { sha256 as sourceDigest } from './value.js';
import { recipes } from './catalog.js';
/** Files the host snapshots; source content never enters the provider through a filesystem port. */
export const EXPRESS_STOREFRONT_SOURCE_PATHS: readonly string[] = Object.freeze([...new Set(recipes.flatMap(recipe => recipe.files.map(file => file.path)))].sort());

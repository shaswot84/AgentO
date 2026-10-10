import { Request } from 'express';

export type SecurityMode = 'vulnerable' | 'fixed';

let currentMode: SecurityMode = (process.env.SECURITY_MODE as SecurityMode) || 'vulnerable';

export function getSecurityMode(): SecurityMode {
  return currentMode;
}

export function setSecurityMode(mode: SecurityMode) {
  if (mode === 'vulnerable' || mode === 'fixed') {
    currentMode = mode;
  }
}

/**
 * Determine whether a request should be processed in FIXED or VULNERABLE mode.
 * Precedence:
 * 1. Request header 'x-security-mode'
 * 2. Query param '?security_mode='
 * 3. Global application setting (currentMode)
 */
export function isFixedMode(req?: Request): boolean {
  if (req) {
    const header = req.headers['x-security-mode'];
    if (header === 'fixed') return true;
    if (header === 'vulnerable') return false;

    const query = req.query?.security_mode;
    if (query === 'fixed') return true;
    if (query === 'vulnerable') return false;
  }

  return currentMode === 'fixed';
}

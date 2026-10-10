import { Request, Response, NextFunction } from 'express';
import { isFixedMode } from '../config.js';

/**
 * Middleware to ensure user is logged in
 */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'You must be logged in to access this resource.'
    });
  }
  next();
}

/**
 * Middleware to check admin role
 * CWE-862 (Missing Authorization) vulnerability occurs when this role check is skipped or bypassed.
 */
export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'You must be logged in.'
    });
  }

  const fixed = isFixedMode(req);

  if (fixed) {
    // FIXED: Enforce role-based access control
    if (req.session.user.role !== 'admin') {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Administrator privilege required.'
      });
    }
    next();
  } else {
    // VULNERABLE (CWE-862): Missing Authorization check
    // Allows any authenticated user (e.g. Alice or Bob) to invoke administrative functions
    next();
  }
}

/**
 * Helper to attach cookies demonstrating CWE-1004 (HttpOnly) & CWE-614 (Secure)
 */
export function attachSessionCookies(req: Request, res: Response, userSessionToken: string) {
  const fixed = isFixedMode(req);

  if (fixed) {
    // FIXED:
    // CWE-1004: httpOnly = true (prevents XSS script from stealing cookie)
    // CWE-614: secure = true (cookie only transmitted over HTTPS / secure connection)
    res.cookie('auth_token', userSessionToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/'
    });

    if (req.session) {
      req.session.cookie.httpOnly = true;
      req.session.cookie.sameSite = 'lax';
      if (req.secure || process.env.COOKIE_SECURE === 'true') {
        req.session.cookie.secure = true;
      }
    }
  } else {
    // VULNERABLE:
    // CWE-1004: httpOnly = false (accessible via document.cookie in browser JavaScript)
    // CWE-614: secure = false (transmitted in cleartext over unencrypted HTTP)
    res.cookie('auth_token', userSessionToken, {
      httpOnly: false,
      secure: false,
      sameSite: 'lax',
      path: '/'
    });

    if (req.session) {
      req.session.cookie.httpOnly = false;
      req.session.cookie.secure = false;
      req.session.cookie.sameSite = 'lax';
    }
  }
}

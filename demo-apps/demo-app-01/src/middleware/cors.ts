import { Request, Response, NextFunction } from 'express';
import { isFixedMode } from '../config.js';

const TRUSTED_ORIGINS = ['http://localhost:3000', 'http://127.0.0.1:3000'];

/**
 * CORS Middleware illustrating CWE-942 (Permissive Cross-domain Policy)
 */
export function corsMiddleware(req: Request, res: Response, next: NextFunction) {
  const origin = req.headers.origin;
  const fixed = isFixedMode(req);

  if (fixed) {
    // FIXED: Only whitelist approved origins, do not reflect arbitrary origins with credentials
    if (origin && TRUSTED_ORIGINS.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    } else {
      // Disallow or allow null without credentials
      res.setHeader('Access-Control-Allow-Origin', 'null');
    }
  } else {
    // VULNERABLE (CWE-942): Dynamically reflect any untrusted Origin header with credentials
    if (origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    } else {
      res.setHeader('Access-Control-Allow-Origin', '*');
    }
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-Security-Mode');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  next();
}

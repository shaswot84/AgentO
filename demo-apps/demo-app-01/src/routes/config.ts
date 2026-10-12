import { Router, Request, Response } from 'express';
import { getSecurityMode, setSecurityMode } from '../config.js';
import { initDatabase, db } from '../db/database.js';

export const configRouter = Router();

const CWE_CATALOG = [
  {
    cwe: 'CWE-639',
    name: 'Authorization Bypass Through User-Controlled Key (IDOR)',
    category: 'A01 — Broken Access Control',
    endpoint: 'GET /api/orders/:id',
    vulnerableBehavior: 'Authenticated customer can view other customers orders by changing :id parameter.',
    fixedBehavior: 'Verifies user ownership (order.user_id === session.user.id) before returning order data.'
  },
  {
    cwe: 'CWE-862',
    name: 'Missing Authorization',
    category: 'A01 — Broken Access Control',
    endpoint: 'GET /api/admin/users',
    vulnerableBehavior: 'Any logged-in user (Alice/Bob) can view user records without admin role verification.',
    fixedBehavior: 'Enforces requireAdmin middleware checking session.user.role === "admin".'
  },
  {
    cwe: 'CWE-942',
    name: 'Permissive Cross-domain Policy with Untrusted Domains',
    category: 'A02 — Security Misconfiguration',
    endpoint: 'CORS Middleware (All endpoints)',
    vulnerableBehavior: 'Reflects arbitrary request Origin header with Access-Control-Allow-Credentials: true.',
    fixedBehavior: 'Whitelists only approved domains and does not reflect untrusted origins with credentials.'
  },
  {
    cwe: 'CWE-1004',
    name: 'Sensitive Cookie Without HttpOnly Flag',
    category: 'A02 — Security Misconfiguration',
    endpoint: 'POST /api/auth/login',
    vulnerableBehavior: 'Session cookie auth_token is issued with httpOnly: false (readable via document.cookie).',
    fixedBehavior: 'Session cookie is issued with httpOnly: true.'
  },
  {
    cwe: 'CWE-614',
    name: 'Sensitive Cookie in HTTPS Session Without Secure Attribute',
    category: 'A02 — Security Misconfiguration',
    endpoint: 'POST /api/auth/login',
    vulnerableBehavior: 'Session cookie auth_token is set without secure: true attribute.',
    fixedBehavior: 'Session cookie is set with secure: true.'
  },
  {
    cwe: 'CWE-79',
    name: 'Improper Neutralization of Input During Web Page Generation (XSS)',
    category: 'A05 — Injection',
    endpoint: 'GET /search?q=',
    vulnerableBehavior: 'Reflects raw unsanitized user query parameter in server-rendered HTML.',
    fixedBehavior: 'Escapes all HTML special characters before rendering into response.'
  },
  {
    cwe: 'CWE-89',
    name: 'Improper Neutralization of Special Elements used in an SQL Command (SQLi)',
    category: 'A05 — Injection',
    endpoint: 'GET /api/search?q=',
    vulnerableBehavior: 'Direct string interpolation of search term into SQLite SELECT query.',
    fixedBehavior: 'Parameterized prepared statement with bound placeholders.'
  }
];

configRouter.get('/security-mode', (req: Request, res: Response) => {
  return res.json({
    currentMode: getSecurityMode(),
    availableModes: ['vulnerable', 'fixed'],
    supportedCWEs: CWE_CATALOG
  });
});

configRouter.post('/security-mode', (req: Request, res: Response) => {
  const { mode } = req.body;
  if (mode !== 'vulnerable' && mode !== 'fixed') {
    return res.status(400).json({ error: 'Mode must be either "vulnerable" or "fixed"' });
  }

  setSecurityMode(mode);
  return res.json({
    message: `Security mode successfully updated to "${mode}"`,
    currentMode: getSecurityMode()
  });
});

configRouter.post('/reset-db', (req: Request, res: Response) => {
  db.exec('DROP TABLE IF EXISTS orders; DROP TABLE IF EXISTS products; DROP TABLE IF EXISTS users;');
  initDatabase();
  return res.json({ message: 'Database reset and re-seeded with initial Alice, Bob, and Admin data' });
});

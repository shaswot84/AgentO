import express, { type Request, type Response, type NextFunction } from 'express';
import cookieParser from 'cookie-parser';
import { randomBytes } from 'node:crypto';

export interface PortalAccount {
  readonly id: string;
  readonly username: string;
  readonly passphrase: string;
  readonly role: string;
  readonly reportId: string;
}

export const PORTAL_ACCOUNTS: readonly PortalAccount[] = Object.freeze([
  { id: 'analyst', username: 'analyst', passphrase: 'Analyst!123', role: 'auditor', reportId: 'REP-501' },
  { id: 'admin', username: 'admin', passphrase: 'Admin!123', role: 'administrator', reportId: 'REP-999' },
]);

export function createApp() {
  const app = express();
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());
  app.use(cookieParser('portal-secret-key-42'));

  const sessions = new Map<string, PortalAccount>();
  const validCsrfTokens = new Set<string>();

  const requireAuth = (req: Request, res: Response, next: NextFunction) => {
    const sessionId = req.cookies['portal_session'];
    const account = sessionId ? sessions.get(sessionId) : undefined;
    if (!account) {
      if (req.path.startsWith('/api/')) {
        res.status(401).json({ error: 'unauthorized' });
        return;
      }
      res.redirect(302, '/login');
      return;
    }
    (req as Request & { account: PortalAccount }).account = account;
    next();
  };

  app.get('/', (req, res) => {
    const sessionId = req.cookies['portal_session'];
    if (sessionId && sessions.has(sessionId)) {
      res.redirect(302, '/dashboard');
    } else {
      res.redirect(302, '/login');
    }
  });

  app.get('/login', (_req, res) => {
    const csrfToken = randomBytes(16).toString('hex');
    validCsrfTokens.add(csrfToken);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Audit Portal — Sign In</title>
</head>
<body>
  <main>
    <h1>Audit Portal Login</h1>
    <form action="/login" method="POST" id="login-form">
      <input type="hidden" name="_csrf" id="csrf-token" value="${csrfToken}">
      <div>
        <label for="username">Username</label>
        <input name="username" id="username" autocomplete="username" required>
      </div>
      <div>
        <label for="password">Password</label>
        <input name="password" id="password" type="password" autocomplete="current-password" required>
      </div>
      <button type="submit" id="submit-btn">Sign In</button>
    </form>
  </main>
</body>
</html>`);
  });

  app.post('/login', (req, res) => {
    const { username, password, _csrf } = req.body ?? {};
    if (!_csrf || !validCsrfTokens.has(_csrf)) {
      res.status(403).send('Invalid or missing CSRF token');
      return;
    }
    validCsrfTokens.delete(_csrf);

    const account = PORTAL_ACCOUNTS.find(a => a.username === username && a.passphrase === password);
    if (!account) {
      res.status(401).send('Invalid credentials');
      return;
    }

    const sessionId = randomBytes(24).toString('hex');
    sessions.set(sessionId, account);

    res.cookie('portal_session', sessionId, {
      httpOnly: true,
      path: '/',
      sameSite: 'lax',
    });

    // Traditional MPA redirects to dashboard upon successful login (302/303 redirect)
    res.redirect(302, '/dashboard');
  });

  app.get('/dashboard', requireAuth, (req, res) => {
    const account = (req as Request & { account: PortalAccount }).account;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Audit Portal — Dashboard</title>
</head>
<body>
  <header>
    <h1>Audit Portal Workspace</h1>
    <div id="user-info">
      User: <span id="user-display">${account.username}</span>
      Role: <span id="role-display">${account.role}</span>
    </div>
  </header>
  <nav>
    <a href="/reports" id="link-reports">Audit Reports</a>
    <form action="/logout" method="POST" style="display:inline;">
      <button type="submit" id="btn-logout">Logout</button>
    </form>
  </nav>
  <main>
    <p>Welcome to the financial audit management system.</p>
  </main>
</body>
</html>`);
  });

  app.get('/reports', requireAuth, (req, res) => {
    const account = (req as Request & { account: PortalAccount }).account;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Audit Portal — Reports</title>
</head>
<body>
  <main>
    <h1>Audit Reports</h1>
    <table>
      <thead>
        <tr><th>Report ID</th><th>Action</th></tr>
      </thead>
      <tbody id="reports-table">
        <tr>
          <td>${account.reportId}</td>
          <td><a href="/reports/${account.reportId}" id="open-report-btn">Open latest report</a></td>
        </tr>
      </tbody>
    </table>
  </main>
</body>
</html>`);
  });

  app.get('/reports/:id', requireAuth, (req, res) => {
    const account = (req as Request & { account: PortalAccount }).account;
    const reportId = req.params.id;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Report ${reportId}</title>
</head>
<body>
  <main>
    <div id="report-view" data-report-id="${reportId}">
      <h1>Financial Audit Report ${reportId}</h1>
      <p>Auditor: ${account.username}</p>
      <span id="audit-status">Report Opened</span>
    </div>
  </main>
</body>
</html>`);
  });

  app.get('/api/session', requireAuth, (req, res) => {
    const account = (req as Request & { account: PortalAccount }).account;
    res.json({
      user: account.username,
      role: account.role,
      reportId: account.reportId,
    });
  });

  app.post('/logout', requireAuth, (req, res) => {
    const sessionId = req.cookies['portal_session'];
    if (sessionId) sessions.delete(sessionId);
    res.clearCookie('portal_session');
    res.redirect(302, '/login');
  });

  return app;
}

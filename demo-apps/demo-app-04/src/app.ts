import express, { type Request, type Response } from 'express';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export interface EdgeAccount {
  readonly id: string;
  readonly handle: string;
  readonly passphrase: string;
  readonly role: string;
  readonly telemetryId: string;
}

export const EDGE_ACCOUNTS: readonly EdgeAccount[] = Object.freeze([
  { id: 'operator', handle: 'operator', passphrase: 'Operator!42', role: 'operator', telemetryId: 'TEL-900' },
  { id: 'supervisor', handle: 'supervisor', passphrase: 'Supervisor!42', role: 'supervisor', telemetryId: 'TEL-901' },
]);

export function createApp(options: { unapprovedCdnOrigin?: string } = {}) {
  const app = express();
  app.use(express.json());

  const jwtSecret = randomBytes(32);
  const unapprovedCdn = options.unapprovedCdnOrigin ?? 'http://cdn.unapproved.example';

  const signJwt = (payload: Record<string, unknown>): string => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = createHmac('sha256', jwtSecret).update(`${header}.${body}`).digest('base64url');
    return `${header}.${body}.${sig}`;
  };

  const verifyJwt = (token: string): Record<string, unknown> | null => {
    try {
      const [header, body, sig] = token.split('.');
      if (!header || !body || !sig) return null;
      const expected = createHmac('sha256', jwtSecret).update(`${header}.${body}`).digest();
      const actual = Buffer.from(sig, 'base64url');
      if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
      const decoded = JSON.parse(Buffer.from(body, 'base64url').toString()) as Record<string, unknown>;
      if (typeof decoded.exp === 'number' && decoded.exp < Date.now() / 1000) return null;
      return decoded;
    } catch {
      return null;
    }
  };

  const authenticate = (req: Request, res: Response): EdgeAccount | null => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Missing or malformed Authorization header' });
      return null;
    }
    const token = authHeader.slice(7);
    const decoded = verifyJwt(token);
    if (!decoded || typeof decoded.sub !== 'string') {
      res.status(401).json({ error: 'Invalid or expired token' });
      return null;
    }
    const account = EDGE_ACCOUNTS.find(a => a.id === decoded.sub);
    if (!account) {
      res.status(401).json({ error: 'User not found' });
      return null;
    }
    return account;
  };

  // Step 1: Identifier lookup
  app.get('/api/auth/lookup', (req, res) => {
    const identifier = String(req.query.identifier ?? '').trim();
    const account = EDGE_ACCOUNTS.find(a => a.handle === identifier || a.id === identifier);
    if (!account) {
      res.status(404).json({ exists: false, error: 'Identifier not recognized' });
      return;
    }
    res.json({ exists: true, handle: account.handle });
  });

  // Step 2: Login with identifier and password
  app.post('/api/auth/login', (req, res) => {
    const { identifier, password } = req.body ?? {};
    const account = EDGE_ACCOUNTS.find(
      a => (a.handle === identifier || a.id === identifier) && a.passphrase === password
    );
    if (!account) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }
    const token = signJwt({
      sub: account.id,
      role: account.role,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    res.json({ token, user: account.id, role: account.role });
  });

  // Workspace endpoint requiring Bearer token
  app.get('/api/workspace', (req, res) => {
    const account = authenticate(req, res);
    if (!account) return;
    res.json({
      user: account.id,
      role: account.role,
      telemetryId: account.telemetryId,
    });
  });

  // Telemetry item endpoint
  app.get('/api/telemetry/:id', (req, res) => {
    const account = authenticate(req, res);
    if (!account) return;
    res.json({
      id: req.params.id,
      status: 'NOMINAL',
      operator: account.id,
      metrics: { cpu: '14%', memory: '42%' },
    });
  });

  // Worker script fixture
  app.get('/worker.js', (_req, res) => {
    res.setHeader('Content-Type', 'text/javascript');
    res.send(`postMessage('ready');`);
  });

  // Single-Page Application (SPA) HTML for all frontend routes
  app.get(['/', '/login', '/workspace', '/telemetry', '/escape/:mode'], (req, res) => {
    const escapeMode = req.params.mode ?? '';
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Edge Telemetry Operations Hub</title>
</head>
<body>
  <main>
    <h1>Edge Telemetry Hub</h1>

    <!-- Multi-Step Login Form -->
    <section id="auth-section">
      <form id="multi-step-form">
        <div id="step-identifier">
          <label for="identifier">Operator Identifier</label>
          <input name="identifier" id="identifier" placeholder="Enter identifier" autocomplete="username">
          <button type="button" id="btn-next">Next</button>
        </div>

        <div id="step-password" style="display: none;">
          <label for="password">Security Passphrase</label>
          <input name="password" id="password" type="password" placeholder="Enter passphrase" autocomplete="current-password">
          <button type="submit" id="btn-submit">Sign In</button>
        </div>
      </form>
    </section>

    <!-- Workspace Section (Authenticated via sessionStorage) -->
    <section id="workspace-section" style="display: none;">
      <header>
        <span id="user-account"></span>
        <span id="user-role"></span>
      </header>
      <div id="workspace-content">
        <button type="button" id="btn-load-telemetry">Open latest telemetry</button>
        <div id="telemetry-view"></div>
      </div>
    </section>
  </main>

  <script>
    const escapeMode = ${JSON.stringify(escapeMode)};
    const unapprovedCdn = ${JSON.stringify(unapprovedCdn)};

    // Scope boundary escape triggers (testing strict scope blocking)
    if (escapeMode === 'websocket') {
      try {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const ws = new WebSocket(proto + '//' + location.host + '/ws/live');
        ws.onopen = () => { document.body.dataset.wsDone = 'true'; };
        ws.onclose = () => { document.body.dataset.wsDone = 'true'; };
        ws.onerror = () => { document.body.dataset.wsDone = 'true'; };
      } catch (e) {}
    } else if (escapeMode === 'worker') {
      try {
        new Worker('/worker.js');
      } catch (e) {}
    } else if (escapeMode === 'cdn') {
      try {
        fetch(unapprovedCdn + '/assets/telemetry.json').catch(() => {});
      } catch (e) {}
    }

    const form = document.getElementById('multi-step-form');
    const step1 = document.getElementById('step-identifier');
    const step2 = document.getElementById('step-password');
    const btnNext = document.getElementById('btn-next');
    const authSection = document.getElementById('auth-section');
    const workspaceSection = document.getElementById('workspace-section');
    const userAccount = document.getElementById('user-account');
    const userRole = document.getElementById('user-role');
    const btnLoad = document.getElementById('btn-load-telemetry');
    const telemetryView = document.getElementById('telemetry-view');

    // Multi-Step Auth Flow: Step 1 -> Lookup -> Reveal Step 2
    btnNext.addEventListener('click', async () => {
      const idVal = document.getElementById('identifier').value.trim();
      if (!idVal) return;
      const res = await fetch('/api/auth/lookup?identifier=' + encodeURIComponent(idVal));
      if (res.ok) {
        step1.style.display = 'none';
        step2.style.display = 'block';
        document.getElementById('password').focus();
      }
    });

    // Multi-Step Auth Flow: Step 2 -> Submit -> Store in sessionStorage
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const identifier = document.getElementById('identifier').value.trim();
      const password = document.getElementById('password').value.trim();
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier, password }),
      });
      if (res.ok) {
        const data = await res.json();
        // Stores token in sessionStorage (NOT localStorage or cookies)
        sessionStorage.setItem('edge_session', data.token);
        history.pushState({}, '', '/workspace');
        loadWorkspace();
      }
    });

    async function loadWorkspace() {
      const token = sessionStorage.getItem('edge_session');
      if (!token) return;
      const res = await fetch('/api/workspace', {
        headers: { 'Authorization': 'Bearer ' + token },
      });
      if (res.ok) {
        const data = await res.json();
        userAccount.textContent = data.user;
        userRole.textContent = data.role;
        authSection.style.display = 'none';
        workspaceSection.style.display = 'block';
      }
    }

    btnLoad.addEventListener('click', async () => {
      const token = sessionStorage.getItem('edge_session');
      if (!token) return;
      const res = await fetch('/api/telemetry/TEL-900', {
        headers: { 'Authorization': 'Bearer ' + token },
      });
      if (res.ok) {
        const data = await res.json();
        btnLoad.style.display = 'none';
        const doneBtn = document.createElement('button');
        doneBtn.disabled = true;
        doneBtn.id = 'btn-telemetry-done';
        doneBtn.textContent = 'Telemetry loaded';
        telemetryView.dataset.record = data.id;
        telemetryView.replaceChildren(doneBtn);
      }
    });

    // Check if session exists on load
    if (sessionStorage.getItem('edge_session')) {
      loadWorkspace();
    }
  </script>
</body>
</html>`);
  });

  return app;
}

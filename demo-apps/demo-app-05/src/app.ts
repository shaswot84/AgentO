import express, { type Request, type Response, type NextFunction } from 'express';
import cookieParser from 'cookie-parser';
import { randomBytes } from 'node:crypto';

export interface OpsAccount {
  readonly id: string;
  readonly username: string;
  readonly passphrase: string;
  readonly role: string;
  readonly department: string;
}

export const OPS_ACCOUNTS: readonly OpsAccount[] = Object.freeze([
  { id: 'responder', username: 'responder.alice', passphrase: 'Responder!42', role: 'incident-responder', department: 'SecOps-Triage' },
  { id: 'commander', username: 'commander.bob', passphrase: 'Commander!42', role: 'incident-commander', department: 'SecOps-Command' },
]);

export function createApp() {
  const app = express();
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());
  app.use(cookieParser('ops-secret-key-99'));

  const sessions = new Map<string, OpsAccount>();
  const incidentStatuses = new Map<string, string>([
    ['INC-9942', 'Awaiting Triage'],
  ]);

  const requireAuth = (req: Request, res: Response, next: NextFunction) => {
    const sessionId = req.cookies['ops_session'];
    const account = sessionId ? sessions.get(sessionId) : undefined;
    if (!account) {
      if (req.path.startsWith('/api/')) {
        res.status(401).json({ error: 'unauthorized' });
        return;
      }
      res.redirect(302, '/sign-in');
      return;
    }
    (req as Request & { account: OpsAccount }).account = account;
    next();
  };

  app.get('/', (req, res) => {
    const sessionId = req.cookies['ops_session'];
    if (sessionId && sessions.has(sessionId)) {
      res.redirect(302, '/console');
    } else {
      res.redirect(302, '/sign-in');
    }
  });

  app.get('/sign-in', (_req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Cloud Ops Console — Sign In</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0b0f19; color: #f3f4f6; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
    .card { background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 2rem; width: 340px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
    h1 { font-size: 1.25rem; margin-top: 0; color: #60a5fa; }
    .field { margin-bottom: 1rem; }
    label { display: block; font-size: 0.875rem; margin-bottom: 0.25rem; color: #9ca3af; }
    input { width: 100%; box-sizing: border-box; background: #1f2937; border: 1px solid #374151; color: white; border-radius: 4px; padding: 0.5rem; }
    button { width: 100%; background: #2563eb; color: white; border: none; border-radius: 4px; padding: 0.6rem; font-weight: 600; cursor: pointer; }
    button:hover { background: #1d4ed8; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Cloud Ops Portal</h1>
    <form action="/sign-in" method="POST" id="auth-form">
      <div class="field">
        <label for="handle">Operator Handle</label>
        <input name="handle" id="handle" autocomplete="username" required>
      </div>
      <div class="field">
        <label for="passphrase">Passphrase</label>
        <input name="passphrase" id="passphrase" type="password" autocomplete="current-password" required>
      </div>
      <button type="submit" id="sign-in-btn">Authenticate</button>
    </form>
  </div>
</body>
</html>`);
  });

  app.post('/sign-in', (req, res) => {
    const { handle, passphrase } = req.body ?? {};
    const account = OPS_ACCOUNTS.find(a => a.username === handle && a.passphrase === passphrase);
    if (!account) {
      res.status(401).send('Invalid credentials');
      return;
    }

    const sessionId = randomBytes(24).toString('hex');
    sessions.set(sessionId, account);

    res.cookie('ops_session', sessionId, {
      httpOnly: true,
      path: '/',
      sameSite: 'lax',
    });

    res.redirect(302, '/console');
  });

  app.get('/console', requireAuth, (req, res) => {
    const account = (req as Request & { account: OpsAccount }).account;
    const currentStatus = incidentStatuses.get('INC-9942') ?? 'Awaiting Triage';
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Enterprise Cloud Ops Console</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #030712; color: #f9fafb; margin: 0; display: flex; flex-direction: column; min-height: 100vh; }
    header { background: #111827; border-bottom: 1px solid #1f2937; padding: 1rem 1.5rem; display: flex; justify-content: space-between; align-items: center; }
    h1 { font-size: 1.15rem; margin: 0; color: #38bdf8; display: flex; align-items: center; gap: 0.5rem; }
    .badge { background: #1e293b; border: 1px solid #334155; padding: 0.25rem 0.6rem; border-radius: 9999px; font-size: 0.8rem; }
    nav { background: #0f172a; border-bottom: 1px solid #1e293b; padding: 0.5rem 1.5rem; display: flex; gap: 0.5rem; }
    .tab-btn { background: transparent; border: 1px solid transparent; color: #94a3b8; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-size: 0.9rem; }
    .tab-btn.active { background: #1e293b; color: #f8fafc; border-color: #38bdf8; font-weight: 600; }
    main { padding: 1.5rem; flex: 1; }
    .panel { display: none; }
    .panel.active { display: block; }
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
    th, td { text-align: left; padding: 0.75rem 1rem; border-bottom: 1px solid #1f2937; }
    th { color: #9ca3af; font-size: 0.85rem; text-transform: uppercase; }
    .action-btn { background: #0284c7; color: white; border: none; padding: 0.4rem 0.8rem; border-radius: 4px; cursor: pointer; }
    .action-btn:hover { background: #0369a1; }
    .modal-backdrop { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); justify-content: center; align-items: center; }
    .modal-backdrop.open { display: flex; }
    .modal-card { background: #111827; border: 1px solid #374151; border-radius: 8px; width: 480px; padding: 1.5rem; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
    .modal-actions { margin-top: 1.5rem; display: flex; justify-content: flex-end; gap: 0.5rem; }
    .btn-secondary { background: #374151; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; }
    .btn-primary { background: #e11d48; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; font-weight: 600; cursor: pointer; }
    .status-pill { font-weight: 600; color: #facc15; }
    .status-pill.escalated { color: #4ade80; }
  </style>
</head>
<body>
  <header>
    <h1>Enterprise Cloud Ops Console</h1>
    <div id="operator-info">
      <span class="badge">Operator: <strong id="operator-display">${account.username}</strong></span>
      <span class="badge">Role: <strong id="role-display">${account.role}</strong></span>
      <form action="/logout" method="POST" style="display:inline; margin-left: 0.5rem;">
        <button type="submit" id="btn-logout" class="btn-secondary" style="padding: 0.25rem 0.5rem;">Sign Out</button>
      </form>
    </div>
  </header>
  <nav id="tabs-navigation">
    <button type="button" id="tab-fleet" class="tab-btn active" onclick="showTab('fleet')">Infrastructure Fleet</button>
    <button type="button" id="tab-threats" class="tab-btn" onclick="showTab('threats')">Threats & Triage</button>
    <button type="button" id="tab-iam" class="tab-btn" onclick="showTab('iam')">Tenancy & IAM</button>
  </nav>
  <main>
    <section id="panel-fleet" class="panel active">
      <h2>Active Cluster Compute Fleet</h2>
      <p>All 14 node pools operating under nominal thermal parameters.</p>
    </section>

    <section id="panel-threats" class="panel">
      <h2>Active Threats & Triage Queue</h2>
      <table>
        <thead>
          <tr>
            <th>Incident ID</th>
            <th>Severity</th>
            <th>Description</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="incidents-body">
          <tr>
            <td><strong>INC-9942</strong></td>
            <td><span style="color: #f87171; font-weight: 600;">CRITICAL</span></td>
            <td>Abnormal Egress Spikes on Core DB Cluster</td>
            <td><span id="threat-table-status" class="status-pill">${currentStatus}</span></td>
            <td>
              <button type="button" id="btn-examine-inc-9942" class="action-btn" onclick="openIncidentModal('INC-9942')">Examine Incident INC-9942</button>
            </td>
          </tr>
        </tbody>
      </table>
    </section>

    <section id="panel-iam" class="panel">
      <h2>Tenancy Policies & IAM RBAC</h2>
      <p>Configured policies for organizational boundaries.</p>
    </section>
  </main>

  <div id="incident-modal" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <div class="modal-card">
      <h3 id="modal-title">Incident Triage: <span id="modal-inc-id">INC-9942</span></h3>
      <p id="modal-inc-desc">Egress volume exceeds baseline by 450%. Source namespace: production-vault-east.</p>
      <div style="margin: 1rem 0; padding: 0.75rem; background: #030712; border-radius: 4px;">
        State: <span id="incident-status" class="status-pill">${currentStatus}</span>
      </div>
      <div class="modal-actions">
        <button type="button" id="btn-close-modal" class="btn-secondary" onclick="closeIncidentModal()">Dismiss</button>
        <button type="button" id="btn-ack-incident" class="btn-primary" onclick="acknowledgeIncident('INC-9942')">Acknowledge & Escalate</button>
      </div>
    </div>
  </div>

  <script>
    function showTab(name) {
      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      const activeBtn = document.getElementById('tab-' + name);
      const activePanel = document.getElementById('panel-' + name);
      if (activeBtn) activeBtn.classList.add('active');
      if (activePanel) activePanel.classList.add('active');
    }

    function openIncidentModal(id) {
      document.getElementById('modal-inc-id').innerText = id;
      const modal = document.getElementById('incident-modal');
      modal.classList.add('open');
    }

    function closeIncidentModal() {
      const modal = document.getElementById('incident-modal');
      modal.classList.remove('open');
    }

    async function acknowledgeIncident(id) {
      try {
        const res = await fetch('/api/triage/' + id + '/acknowledge', { method: 'POST' });
        if (res.ok) {
          const data = await res.json();
          const badge = document.getElementById('incident-status');
          const tableBadge = document.getElementById('threat-table-status');
          if (badge) {
            badge.innerText = 'Escalated to Commander';
            badge.classList.add('escalated');
          }
          if (tableBadge) {
            tableBadge.innerText = 'Escalated to Commander';
            tableBadge.classList.add('escalated');
          }
        }
      } catch (e) {
        console.error('Failed to acknowledge', e);
      }
    }
  </script>
</body>
</html>`);
  });

  app.post('/api/triage/:id/acknowledge', requireAuth, (req, res) => {
    const account = (req as Request & { account: OpsAccount }).account;
    const incidentId = String(req.params.id);
    incidentStatuses.set(incidentId, 'Escalated to Commander');
    res.json({
      success: true,
      incidentId,
      status: 'Escalated to Commander',
      escalatedBy: account.username,
      escalatedAt: new Date().toISOString(),
    });
  });

  app.get('/api/session', requireAuth, (req, res) => {
    const account = (req as Request & { account: OpsAccount }).account;
    res.json({
      username: account.username,
      role: account.role,
      department: account.department,
    });
  });

  app.post('/logout', requireAuth, (req, res) => {
    const sessionId = req.cookies['ops_session'];
    if (sessionId) sessions.delete(sessionId);
    res.clearCookie('ops_session');
    res.redirect(302, '/sign-in');
  });

  return app;
}

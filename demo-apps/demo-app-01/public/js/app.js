// Client-side shared JavaScript for AgentO Demo App

let currentUser = null;
let currentSecurityMode = 'vulnerable';

async function initApp() {
  await fetchSecurityMode();
  await checkAuth();
  updateCookieStatus();
}

async function fetchSecurityMode() {
  try {
    const res = await fetch('/api/config/security-mode');
    const data = await res.json();
    currentSecurityMode = data.currentMode;
    renderSecurityBanner();
  } catch (e) {
    console.error('Failed to load security mode', e);
  }
}

async function checkAuth() {
  try {
    const res = await fetch('/api/auth/me');
    if (res.ok) {
      const data = await res.json();
      currentUser = data.user;
    } else {
      currentUser = null;
    }
  } catch (e) {
    currentUser = null;
  }
  renderAuthStatus();
}

function renderSecurityBanner() {
  const container = document.getElementById('security-banner-container');
  if (!container) return;

  const isVulnerable = currentSecurityMode === 'vulnerable';
  container.innerHTML = `
    <div class="security-banner">
      <div class="security-info">
        <strong>Security Mode:</strong>
        <span class="badge ${isVulnerable ? 'badge-vulnerable' : 'badge-fixed'}">
          ${isVulnerable ? '⚠️ VULNERABLE (7 CWEs Active)' : '🛡️ FIXED (Patched & Hardened)'}
        </span>
        <span style="font-size: 0.85rem; color: var(--text-secondary);">
          ${isVulnerable ? 'All target vulnerabilities are active for scanning/testing.' : 'Strict access control, parameterization, and secure flags enforced.'}
        </span>
      </div>
      <div>
        <button class="btn btn-sm ${isVulnerable ? 'btn-primary' : 'btn-danger'}" onclick="toggleSecurityMode()">
          Switch to ${isVulnerable ? 'FIXED Mode' : 'VULNERABLE Mode'}
        </button>
      </div>
    </div>
  `;
}

async function toggleSecurityMode() {
  const newMode = currentSecurityMode === 'vulnerable' ? 'fixed' : 'vulnerable';
  try {
    const res = await fetch('/api/config/security-mode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: newMode })
    });
    const data = await res.json();
    currentSecurityMode = data.currentMode;
    renderSecurityBanner();
    alert(`Switched to ${currentSecurityMode.toUpperCase()} mode!`);
    window.location.reload();
  } catch (e) {
    alert('Failed to toggle security mode');
  }
}

function renderAuthStatus() {
  const userStatusEl = document.getElementById('user-status-container');
  if (!userStatusEl) return;

  if (currentUser) {
    userStatusEl.innerHTML = `
      <div class="user-status">
        <span class="user-pill">
          👤 <strong>${currentUser.username}</strong> (${currentUser.role})
        </span>
        <button class="btn btn-sm" onclick="logout()">Logout</button>
      </div>
    `;
  } else {
    userStatusEl.innerHTML = `
      <div class="user-status">
        <a href="/login.html" class="btn btn-sm btn-primary">Login</a>
      </div>
    `;
  }
}

async function loginAs(username) {
  const passwords = {
    alice: 'alice123',
    bob: 'bob123',
    admin: 'admin123'
  };

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        password: passwords[username] || 'password'
      })
    });

    const data = await res.json();
    if (res.ok) {
      currentUser = data.user;
      renderAuthStatus();
      updateCookieStatus();
      alert(`Logged in as ${username.toUpperCase()} (${currentUser.role})`);
      window.location.reload();
    } else {
      alert(`Login failed: ${data.error}`);
    }
  } catch (e) {
    alert('Login error');
  }
}

async function logout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
    currentUser = null;
    renderAuthStatus();
    updateCookieStatus();
    window.location.href = '/';
  } catch (e) {
    console.error('Logout error', e);
  }
}

function updateCookieStatus() {
  const el = document.getElementById('cookie-status-display');
  if (!el) return;

  // CWE-1004 inspection: Can document.cookie read the auth_token?
  const cookies = document.cookie;
  const hasAuthCookieInJS = cookies.includes('auth_token');

  el.innerHTML = `
    <div style="font-size: 0.85rem; margin-top: 8px;">
      <strong>Browser JS document.cookie:</strong> <code>${cookies || '(empty / hidden by HttpOnly)'}</code><br>
      <small style="color: ${hasAuthCookieInJS ? 'var(--danger-color)' : 'var(--success-color)'};">
        ${hasAuthCookieInJS 
          ? '⚠️ CWE-1004 VULNERABLE: auth_token is visible to document.cookie! Accessible to malicious XSS scripts.' 
          : '🛡️ CWE-1004 FIXED: auth_token is protected by HttpOnly (inaccessible to JS).'}
      </small>
    </div>
  `;
}

document.addEventListener('DOMContentLoaded', initApp);

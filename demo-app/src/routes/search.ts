import { Router, Request, Response } from 'express';
import { db } from '../db/database.js';
import { isFixedMode } from '../config.js';

export const searchRouter = Router();

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * /api/search
 * Demonstrates CWE-89 (SQL Injection)
 */
searchRouter.get('/api/search', (req: Request, res: Response) => {
  const q = (req.query.q as string) || '';
  const fixed = isFixedMode(req);

  try {
    if (fixed) {
      // FIXED (CWE-89): Safe parameterized query using prepared statements
      const stmt = db.prepare(`
        SELECT id, name, description, category, price, in_stock
        FROM products
        WHERE name LIKE ? OR description LIKE ?
      `);
      const pattern = `%${q}%`;
      const results = stmt.all(pattern, pattern);

      return res.json({
        securityMode: 'fixed',
        cwe: 'CWE-89 Fixed (Parameterized Query)',
        query: escapeHtml(q),
        results
      });
    } else {
      // VULNERABLE (CWE-89): Raw SQL string concatenation
      // Example payload: ' UNION SELECT id, username, password, role, email, full_name FROM users --
      const queryStr = `
        SELECT id, name, description, category, price, in_stock
        FROM products
        WHERE name LIKE '%${q}%' OR description LIKE '%${q}%'
      `;
      const results = db.prepare(queryStr).all();

      return res.json({
        securityMode: 'vulnerable',
        cwe: 'CWE-89 Vulnerable (Raw SQL Concatenation)',
        query: q,
        rawExecutedQuery: queryStr,
        results
      });
    }
  } catch (err: any) {
    return res.status(500).json({
      error: 'Database query execution error',
      details: err.message,
      query: q
    });
  }
});

/**
 * /search
 * Demonstrates CWE-79 (Cross-site Scripting - XSS)
 * Returns a server-rendered HTML page with search results.
 */
searchRouter.get('/search', (req: Request, res: Response) => {
  const q = (req.query.q as string) || '';
  const fixed = isFixedMode(req);

  let searchDisplay = q;
  if (fixed) {
    // FIXED (CWE-79): Escapes all HTML characters before embedding in HTML
    searchDisplay = escapeHtml(q);
  } else {
    // VULNERABLE (CWE-79): User query directly reflected in HTML without escaping
    // Example payload: <script>alert('XSS')</script> or <img src=x onerror="alert('CWE-79')">
    searchDisplay = q;
  }

  // Fetch results safely for display
  let results: any[] = [];
  try {
    const stmt = db.prepare(`SELECT * FROM products WHERE name LIKE ?`);
    results = stmt.all(`%${q}%`);
  } catch (e) {
    results = [];
  }

  const resultItems = results.map(r => `
    <div class="product-card">
      <h3>${escapeHtml(r.name)}</h3>
      <p>${escapeHtml(r.description)}</p>
      <div class="product-price">$${r.price.toFixed(2)}</div>
    </div>
  `).join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AgentO Demo — Search Results</title>
  <link rel="stylesheet" href="/css/styles.css">
</head>
<body class="theme-dark">
  <div class="container">
    <header class="navbar">
      <div class="brand">
        <a href="/">🛡️ <strong>AgentO Store</strong></a>
      </div>
      <nav class="nav-links">
        <a href="/">Catalog</a>
        <a href="/orders.html">Orders</a>
        <a href="/profile.html">Profile</a>
        <a href="/admin.html">Admin</a>
      </nav>
      <div class="badge ${fixed ? 'badge-fixed' : 'badge-vulnerable'}">
        Mode: ${fixed ? 'FIXED' : 'VULNERABLE (CWE-79 active)'}
      </div>
    </header>

    <main class="content-box">
      <div class="search-header">
        <h2>Search Results for: <span id="search-query-target">${searchDisplay}</span></h2>
        <p class="subtext">Found ${results.length} item(s)</p>
      </div>

      <div class="results-grid">
        ${resultItems || '<p class="no-results">No products matched your search query.</p>'}
      </div>

      <div class="test-panel">
        <h4>CWE-79 (Cross-Site Scripting) Verification:</h4>
        <p>In vulnerable mode, unsanitized query parameters are reflected raw into the DOM above.</p>
        <code>/search?q=&lt;img src=x onerror=alert('CWE-79-Reflected-XSS')&gt;</code>
      </div>
    </main>
  </div>
</body>
</html>`;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.send(html);
});

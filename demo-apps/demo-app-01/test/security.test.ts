import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { initDatabase, db } from '../src/db/database.js';
import { setSecurityMode } from '../src/config.js';

const app = createApp();

beforeAll(() => {
  initDatabase();
});

beforeEach(() => {
  setSecurityMode('vulnerable');
});

describe('Phase 1 — Vulnerable Demo Application Verification', () => {

  describe('User Authentication & Personas', () => {
    it('Alice can log in with valid credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: 'alice', password: 'alice123' });

      expect(res.status).toBe(200);
      expect(res.body.user.username).toBe('alice');
      expect(res.body.user.role).toBe('customer');
    });

    it('Bob can log in with valid credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: 'bob', password: 'bob123' });

      expect(res.status).toBe(200);
      expect(res.body.user.username).toBe('bob');
      expect(res.body.user.role).toBe('customer');
    });

    it('Admin can log in with valid credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: 'admin', password: 'admin123' });

      expect(res.status).toBe(200);
      expect(res.body.user.username).toBe('admin');
      expect(res.body.user.role).toBe('admin');
    });

    it('Rejects invalid passwords', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: 'alice', password: 'wrongpassword' });

      expect(res.status).toBe(401);
    });
  });

  describe('CWE-639 — Authorization Bypass Through User-Controlled Key (IDOR)', () => {
    it('VULNERABLE: Bob can access Alice order #101', async () => {
      const agent = request.agent(app);
      await agent.post('/api/auth/login').send({ username: 'bob', password: 'bob123' });

      const res = await agent.get('/api/orders/101');
      expect(res.status).toBe(200);
      expect(res.body.order.id).toBe(101);
      expect(res.body.order.owner_username).toBe('alice');
      expect(res.body.securityMode).toBe('vulnerable');
    });

    it('FIXED: Bob is rejected (403 Forbidden) when accessing Alice order #101', async () => {
      setSecurityMode('fixed');
      const agent = request.agent(app);
      await agent.post('/api/auth/login').send({ username: 'bob', password: 'bob123' });

      const res = await agent.get('/api/orders/101');
      expect(res.status).toBe(403);
      expect(res.body.error).toBe('Forbidden');
    });

    it('FIXED: Alice CAN access her own order #101', async () => {
      setSecurityMode('fixed');
      const agent = request.agent(app);
      await agent.post('/api/auth/login').send({ username: 'alice', password: 'alice123' });

      const res = await agent.get('/api/orders/101');
      expect(res.status).toBe(200);
      expect(res.body.order.id).toBe(101);
    });
  });

  describe('CWE-862 — Missing Authorization', () => {
    it('VULNERABLE: Alice (customer) can access admin endpoints /api/admin/users', async () => {
      const agent = request.agent(app);
      await agent.post('/api/auth/login').send({ username: 'alice', password: 'alice123' });

      const res = await agent.get('/api/admin/users');
      expect(res.status).toBe(200);
      expect(res.body.securityMode).toBe('vulnerable');
      expect(Array.isArray(res.body.users)).toBe(true);
    });

    it('FIXED: Alice is denied (403 Forbidden) from accessing admin endpoints', async () => {
      setSecurityMode('fixed');
      const agent = request.agent(app);
      await agent.post('/api/auth/login').send({ username: 'alice', password: 'alice123' });

      const res = await agent.get('/api/admin/users');
      expect(res.status).toBe(403);
      expect(res.body.error).toBe('Forbidden');
    });

    it('FIXED: Admin CAN access admin endpoints', async () => {
      setSecurityMode('fixed');
      const agent = request.agent(app);
      await agent.post('/api/auth/login').send({ username: 'admin', password: 'admin123' });

      const res = await agent.get('/api/admin/users');
      expect(res.status).toBe(200);
      expect(res.body.securityMode).toBe('fixed');
    });
  });

  describe('CWE-942 — Permissive Cross-domain Policy (CORS)', () => {
    it('VULNERABLE: Reflects arbitrary untrusted origin with credentials', async () => {
      const res = await request(app)
        .get('/api/products')
        .set('Origin', 'https://attacker-controlled-site.com');

      expect(res.headers['access-control-allow-origin']).toBe('https://attacker-controlled-site.com');
      expect(res.headers['access-control-allow-credentials']).toBe('true');
    });

    it('FIXED: Rejects untrusted origin or does not reflect with credentials', async () => {
      setSecurityMode('fixed');
      const res = await request(app)
        .get('/api/products')
        .set('Origin', 'https://attacker-controlled-site.com');

      expect(res.headers['access-control-allow-origin']).toBe('null');
    });
  });

  describe('CWE-1004 & CWE-614 — Sensitive Cookie Security Flags', () => {
    it('VULNERABLE: Session auth_token cookie lacks HttpOnly (CWE-1004) and Secure (CWE-614)', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: 'alice', password: 'alice123' });

      const cookies = res.headers['set-cookie'];
      expect(cookies).toBeDefined();

      const authCookie = cookies.find((c: string) => c.startsWith('auth_token='));
      expect(authCookie).toBeDefined();
      expect(authCookie).not.toContain('HttpOnly');
      expect(authCookie).not.toContain('Secure');
    });

    it('FIXED: Session auth_token cookie includes HttpOnly and Secure', async () => {
      setSecurityMode('fixed');
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: 'alice', password: 'alice123' });

      const cookies = res.headers['set-cookie'];
      expect(cookies).toBeDefined();

      const authCookie = cookies.find((c: string) => c.startsWith('auth_token='));
      expect(authCookie).toBeDefined();
      expect(authCookie).toContain('HttpOnly');
      expect(authCookie).toContain('Secure');
    });
  });

  describe('CWE-79 — Cross-site Scripting (XSS)', () => {
    const payload = `<script>alert('XSS-TEST')</script>`;

    it('VULNERABLE: Reflects raw unsanitized script tags in /search HTML', async () => {
      const res = await request(app)
        .get(`/search?q=${encodeURIComponent(payload)}`);

      expect(res.status).toBe(200);
      expect(res.text).toContain(`<span id="search-query-target">${payload}</span>`);
    });

    it('FIXED: Safely escapes HTML entities in /search HTML', async () => {
      setSecurityMode('fixed');
      const res = await request(app)
        .get(`/search?q=${encodeURIComponent(payload)}`);

      expect(res.status).toBe(200);
      expect(res.text).not.toContain(`<script>alert('XSS-TEST')</script>`);
      expect(res.text).toContain(`&lt;script&gt;alert(&#39;XSS-TEST&#39;)&lt;/script&gt;`);
    });
  });

  describe('CWE-89 — SQL Injection', () => {
    const sqliPayload = "' UNION SELECT id, username, password, role, email, full_name FROM users --";

    it('VULNERABLE: Executes UNION SQL injection and extracts user records', async () => {
      const res = await request(app)
        .get(`/api/search?q=${encodeURIComponent(sqliPayload)}`);

      expect(res.status).toBe(200);
      expect(res.body.securityMode).toBe('vulnerable');
      // Results contain extracted user rows
      const usernames = res.body.results.map((r: any) => r.name);
      expect(usernames).toContain('admin');
      expect(usernames).toContain('alice');
    });

    it('FIXED: Parameterized query prevents SQL injection', async () => {
      setSecurityMode('fixed');
      const res = await request(app)
        .get(`/api/search?q=${encodeURIComponent(sqliPayload)}`);

      expect(res.status).toBe(200);
      expect(res.body.securityMode).toBe('fixed');
      // No products match this crazy literal string
      expect(res.body.results.length).toBe(0);
    });
  });
});

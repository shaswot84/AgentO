import { describe, expect, it } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';

describe('Demo App 03 — SSR Multi-Page Portal', () => {
  const app = createApp();

  it('renders login page with CSRF token', async () => {
    const res = await request(app).get('/login');
    expect(res.status).toBe(200);
    expect(res.text).toContain('name="_csrf"');
    expect(res.text).toContain('id="csrf-token"');
  });

  it('rejects login with missing CSRF token', async () => {
    const res = await request(app)
      .post('/login')
      .type('form')
      .send({ username: 'analyst', password: 'Analyst!123' });
    expect(res.status).toBe(403);
  });

  it('authenticates with valid credentials and redirects to /dashboard with session cookie', async () => {
    const loginPage = await request(app).get('/login');
    const csrfMatch = loginPage.text.match(/name="_csrf" id="csrf-token" value="([^"]+)"/);
    expect(csrfMatch).toBeTruthy();
    const csrfToken = csrfMatch![1];

    const loginRes = await request(app)
      .post('/login')
      .type('form')
      .send({ username: 'analyst', password: 'Analyst!123', _csrf: csrfToken });
    expect(loginRes.status).toBe(302);
    expect(loginRes.headers.location).toBe('/dashboard');

    const cookie = loginRes.headers['set-cookie'];
    expect(cookie).toBeDefined();

    const dashboardRes = await request(app)
      .get('/dashboard')
      .set('Cookie', cookie);
    expect(dashboardRes.status).toBe(200);
    expect(dashboardRes.text).toContain('<span id="user-display">analyst</span>');
    expect(dashboardRes.text).toContain('<span id="role-display">auditor</span>');
  });
});

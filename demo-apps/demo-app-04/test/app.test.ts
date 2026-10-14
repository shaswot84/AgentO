import { describe, expect, it } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';

describe('Demo App 04 — Modern Edge-Case SPA', () => {
  const app = createApp();

  it('validates identifier lookup for valid operator', async () => {
    const res = await request(app).get('/api/auth/lookup?identifier=operator');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ exists: true, handle: 'operator' });
  });

  it('rejects identifier lookup for unknown user', async () => {
    const res = await request(app).get('/api/auth/lookup?identifier=unknown');
    expect(res.status).toBe(404);
  });

  it('authenticates with valid identifier and password', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ identifier: 'operator', password: 'Operator!42' });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.user).toBe('operator');
    expect(res.body.role).toBe('operator');

    // Access protected workspace endpoint with Bearer token
    const workspaceRes = await request(app)
      .get('/api/workspace')
      .set('Authorization', `Bearer ${res.body.token}`);
    expect(workspaceRes.status).toBe(200);
    expect(workspaceRes.body.telemetryId).toBe('TEL-900');
  });

  it('rejects protected workspace endpoint without Bearer token', async () => {
    const res = await request(app).get('/api/workspace');
    expect(res.status).toBe(401);
  });
});

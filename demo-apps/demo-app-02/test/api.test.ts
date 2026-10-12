import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../src/app.js';

describe('Demo App 02 API Verification', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it('GET /api/health returns service health info', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/health',
    });
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body.status).toBe('pass');
    expect(body.service).toBe('demo-app-02');
    expect(body.framework).toBe('fastify');
  });

  it('POST /api/auth/token generates a JWT and sets auth cookie', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/auth/token',
      payload: { username: 'alice', role: 'operator' },
    });
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body.token).toBeDefined();
    expect(body.username).toBe('alice');
    expect(body.role).toBe('operator');
    expect(response.cookies.find(c => c.name === 'token')).toBeDefined();
  });

  it('GET /api/auth/verify verifies authenticated token', async () => {
    const tokenRes = await app.inject({
      method: 'POST',
      url: '/api/auth/token',
      payload: { username: 'bob', role: 'customer' },
    });
    const { token } = JSON.parse(tokenRes.payload);

    const verifyRes = await app.inject({
      method: 'GET',
      url: '/api/auth/verify',
      headers: {
        authorization: `Bearer ${token}`,
      },
    });
    expect(verifyRes.statusCode).toBe(200);
    const verifyBody = JSON.parse(verifyRes.payload);
    expect(verifyBody.authenticated).toBe(true);
    expect(verifyBody.user.sub).toBe('bob');
  });

  it('POST /api/payment/charge applies custom CORS header and creates charge', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/payment/charge',
      payload: { amount: 99.50, currency: 'USD' },
    });
    expect(response.statusCode).toBe(201);
    expect(response.headers['access-control-allow-origin']).toBe('*');
    const body = JSON.parse(response.payload);
    expect(body.status).toBe('succeeded');
    expect(body.amount).toBe(99.50);
  });
});

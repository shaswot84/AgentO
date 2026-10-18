import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';

describe('Demo App 05 — Enterprise Cloud Ops Console', () => {
  let server: Server;
  let origin: string;

  beforeAll(async () => {
    const app = createApp();
    server = createServer(app);
    await new Promise<void>((resolve, reject) => {
      server.listen(0, '127.0.0.1', () => {
        const address = server.address() as AddressInfo;
        origin = `http://127.0.0.1:${address.port}`;
        resolve();
      });
      server.on('error', reject);
    });
  });

  afterAll(async () => {
    await new Promise<void>(resolve => server.close(() => resolve()));
  });

  it('redirects unauthenticated root to /sign-in', async () => {
    const res = await fetch(`${origin}/`, { redirect: 'manual' });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/sign-in');
  });

  it('renders sign-in form', async () => {
    const res = await fetch(`${origin}/sign-in`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Cloud Ops Portal');
    expect(html).toContain('name="handle"');
    expect(html).toContain('name="passphrase"');
  });

  it('authenticates responder and allows console access with session cookie', async () => {
    const loginRes = await fetch(`${origin}/sign-in`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'handle=responder.alice&passphrase=Responder!42',
      redirect: 'manual',
    });

    expect(loginRes.status).toBe(302);
    expect(loginRes.headers.get('location')).toBe('/console');
    const cookieHeader = loginRes.headers.get('set-cookie');
    expect(cookieHeader).toBeDefined();
    const cookie = cookieHeader!.split(';')[0];
    expect(cookie).toContain('ops_session=');

    // Access console
    const consoleRes = await fetch(`${origin}/console`, {
      headers: { Cookie: cookie! },
    });
    expect(consoleRes.status).toBe(200);
    const html = await consoleRes.text();
    expect(html).toContain('Enterprise Cloud Ops Console');
    expect(html).toContain('responder.alice');
    expect(html).toContain('Threats & Triage');
    expect(html).toContain('INC-9942');

    // Acknowledge incident
    const ackRes = await fetch(`${origin}/api/triage/INC-9942/acknowledge`, {
      method: 'POST',
      headers: { Cookie: cookie! },
    });
    expect(ackRes.status).toBe(200);
    const body = await ackRes.json();
    expect(body).toHaveProperty('success', true);
    expect(body).toHaveProperty('status', 'Escalated to Commander');
  });
});


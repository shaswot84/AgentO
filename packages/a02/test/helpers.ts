import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DeterministicRequestExecutor, type HttpTransport, type TransportRequest } from '@agento/runtime';
import { HttpCookieAuthenticationManager, type A02ScanOptions } from '../src/index.js';

export function repository() {
  const directory = mkdtempSync(join(tmpdir(), 'agento-a02-test-'));
  writeFileSync(join(directory, 'package.json'), JSON.stringify({ name: 'a02-fixture', dependencies: { express: '*', cors: '*' } }));
  writeFileSync(join(directory, 'app.js'), `
import express from 'express';
import cors from 'cors';
const app = express();
app.use(cors({origin: true, credentials: true}));
app.get('/target', (req, res) => {
  res.cookie('auth_token', 'source-value', {httpOnly: false, secure: false});
  res.json({ok: true});
});
app.get('/other', (req, res) => {
  res.cookie('auth_token', 'source-value', {httpOnly: false, secure: false});
  res.json({ok: true});
});
`);
  return directory;
}
export function setup(repositoryPath: string, mode: 'vulnerable' | 'fixed' = 'vulnerable', baseUrl = 'https://target.invalid') {
  const calls: TransportRequest[] = [];
  const transport: HttpTransport = { send: async request => {
    calls.push(request);
    if (new URL(request.url).pathname === '/login') return { status: 200,
      headers: { 'set-cookie': [`auth_token=private-session-token; Path=/; SameSite=Lax${mode === 'fixed' ? '; HttpOnly; Secure' : ''}`] },
      body: Buffer.from('private-login-body'), truncated: false, firstByteMs: 1 };
    const origin = Object.entries(request.headers).find(([name]) => name.toLowerCase() === 'origin')?.[1];
    return { status: request.method === 'OPTIONS' ? 204 : request.headers.cookie ? 200 : 401,
      headers: mode === 'vulnerable' && origin ? { 'access-control-allow-origin': [origin], 'access-control-allow-credentials': ['true'] } : {},
      body: Buffer.from('private-response-body'), truncated: false, firstByteMs: 1 };
  } };
  const executor = new DeterministicRequestExecutor({ baseUrl, allowedOrigins: [baseUrl], transport });
  const authentication = new HttpCookieAuthenticationManager({ executor, login: async () => ({
    url: '/login', method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: 'private-password' }),
  }) });
  const options: A02ScanOptions = { project: { id: 'test', name: 'A02 test', mode: 'code-aware', repositoryPath, baseUrl,
    allowedOrigins: [baseUrl], languages: ['javascript'] }, paths: ['/target'],
    identities: [{ id: 'alice', label: 'Alice', roles: [], authentication: 'session-cookie' }],
    sensitiveCookieNames: ['auth_token'], untrustedOrigins: ['https://unapproved.invalid'], authentication, transport,
    policy: { allowedOrigins: [baseUrl], allowedMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
      tools: { 'a02-http': {}, 'a02-auth': {} }, approval: { risks: [], severities: [] } } };
  return { options, calls, authentication, executor };
}

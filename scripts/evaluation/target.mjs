import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { createServer as httpServer } from 'node:http';
import { createServer as httpsServer, request as httpsRequest } from 'node:https';

/** The only executable target is the repository's controlled demo, bound to loopback. */
export async function startTarget() {
  const directory = mkdtempSync(join(tmpdir(), 'agento-evaluation-'));
  const oldDatabase = process.env.DB_PATH;
  let http, https, database, requests = 0;
  async function close() {
    await Promise.all([http, https].filter(Boolean).map(server => new Promise(resolve => {
      server.closeAllConnections(); server.close(resolve);
    })));
    database?.close();
    rmSync(directory, { recursive: true, force: true });
    if (oldDatabase === undefined) delete process.env.DB_PATH; else process.env.DB_PATH = oldDatabase;
  }
  try {
    const key = join(directory, 'key.pem'), cert = join(directory, 'cert.pem');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', key,
      '-out', cert, '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
    const certificate = readFileSync(cert);
    process.env.DB_PATH = ':memory:';
    const { createApp } = await import('../../demo-apps/demo-app-01/src/app.ts');
    const db = await import('../../demo-apps/demo-app-01/src/db/database.ts');
    const { setSecurityMode } = await import('../../demo-apps/demo-app-01/src/config.ts');
    database = db.db; db.initDatabase();
    // Separate app/session instances prevent cookie sharing between HTTP and HTTPS.
    const counted = app => (request, response) => { requests++; app(request, response); };
    http = httpServer(counted(createApp()));
    https = httpsServer({ key: readFileSync(key), cert: certificate }, counted(createApp()));
    const listen = server => new Promise((resolve, reject) => {
      server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
    });
    await listen(http); await listen(https);
    return {
      http: `http://127.0.0.1:${http.address().port}`, https: `https://127.0.0.1:${https.address().port}`,
      setMode: setSecurityMode, count: () => requests, close,
      // Trust only this ephemeral certificate; TLS verification remains enabled.
      transport: { send: request => new Promise((resolve, reject) => {
        const started = performance.now();
        const outgoing = httpsRequest(request.url, { ca: certificate, method: request.method, headers: request.headers,
          signal: request.signal, agent: false }, incoming => {
          const firstByteMs = performance.now() - started;
          const chunks = [], headers = {};
          for (let i = 0; i < incoming.rawHeaders.length; i += 2)
            (headers[incoming.rawHeaders[i].toLowerCase()] ??= []).push(incoming.rawHeaders[i + 1]);
          let size = 0;
          incoming.on('data', chunk => {
            chunks.push(chunk.subarray(0, Math.max(0, request.maxBodyBytes - size))); size += chunk.length;
          });
          incoming.on('end', () => resolve({ status: incoming.statusCode, headers, body: Buffer.concat(chunks),
            truncated: size > request.maxBodyBytes, firstByteMs }));
          incoming.on('error', reject);
        });
        outgoing.on('error', reject); outgoing.end(request.body);
      }) },
    };
  } catch (error) { await close(); throw error; }
}

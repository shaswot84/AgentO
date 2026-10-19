import { createServer } from 'node:http';
import { chmod } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { DeterministicRequestExecutor } from '@agento/runtime';
import { DalfoxAdapter, NucleiAdapter, SqlmapAdapter, ZapAdapter } from '../src/index.js';
import { input, project } from './helpers.js';

const fixture = fileURLToPath(new URL('./fixtures/engine.mjs', import.meta.url));
const engines = [
  { name: 'Nuclei', Engine: NucleiAdapter, env: 'AGENTO_NUCLEI_EXECUTABLE', command: 'nuclei' },
  { name: 'ZAP', Engine: ZapAdapter, env: 'AGENTO_ZAP_EXECUTABLE', command: 'zap.sh' },
  { name: 'Dalfox', Engine: DalfoxAdapter, env: 'AGENTO_DALFOX_EXECUTABLE', command: 'dalfox' },
  { name: 'sqlmap', Engine: SqlmapAdapter, env: 'AGENTO_SQLMAP_EXECUTABLE', command: 'sqlmap' },
] as const;

async function localTarget<T>(run: (origin: string, requests: string[]) => Promise<T>) {
  const requests: string[] = [];
  const server = createServer((request, response) => {
    requests.push(`${request.method} ${request.url}`);
    response.writeHead(200, { 'content-type': 'text/html', 'set-cookie': 'sid=PRIVATE_SESSION; Path=/' });
    response.end('<html><body><p>Controlled scanner test</p></body></html>');
  });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('listener-unavailable');
  try { return await run(`http://127.0.0.1:${address.port}`, requests); }
  finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
}

describe('real process and loopback protocol integration', () => {
  it.each(engines)('$name sends traffic through the injected executor', async ({ Engine }) => {
    await chmod(fixture, 0o755);
    await localTarget(async (origin, requests) => {
      const executor = new DeterministicRequestExecutor({ baseUrl: origin, allowedOrigins: [origin] });
      const result = await new Engine({ executable: fixture }).run(input({ project: { ...project, baseUrl: origin, allowedOrigins: [origin] },
        request: { url: `${origin}/search?q=a` }, cweId: Engine === DalfoxAdapter ? 'CWE-79' : 'CWE-89',
        parameter: { name: 'q', location: 'query' }, executor }));
      expect(result.outcome).toBe('COMPLETED'); expect(requests).toEqual(['GET /search?q=a']);
      expect(JSON.stringify(result)).not.toMatch(/PRIVATE|127\.0\.0\.1/);
    });
  });
});

describe('optional installed scanner integration', () => {
  for (const { name, Engine, env, command } of engines) {
    it.skipIf(process.env.AGENTO_SCANNERS_INTEGRATION !== '1')(`${name} scans a controlled target`, async () => {
      await localTarget(async (origin, requests) => {
        const executor = new DeterministicRequestExecutor({ baseUrl: origin, allowedOrigins: [origin] });
        const result = await new Engine({ executable: process.env[env] ?? command, timeoutMs: 180_000 }).run(input({
          project: { ...project, baseUrl: origin, allowedOrigins: [origin] }, request: { url: `${origin}/search?q=a` },
          cweId: Engine === DalfoxAdapter ? 'CWE-79' : 'CWE-89', parameter: { name: 'q', location: 'query' }, executor, maxRequests: 512 }));
        expect(result, JSON.stringify(result)).toMatchObject({ outcome: 'COMPLETED' });
        expect(requests.length).toBeGreaterThan(0); expect(requests.every(value => value.startsWith('GET /search?'))).toBe(true);
      });
    }, 200_000);
  }
});

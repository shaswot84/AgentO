import { existsSync } from 'node:fs';
import { readdir } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, type Plugin } from 'vite';

function agentoDiscoveryDevPlugin(): Plugin {
  const rootDir = resolve(fileURLToPath(new URL('.', import.meta.url)), '../..');
  const demoAppsDir = join(rootDir, 'demo-apps');

  return {
    name: 'agento-discovery-dev-bridge',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (req.method === 'GET' && req.url === '/api/demo-apps') {
          try {
            const entries = await readdir(demoAppsDir, { withFileTypes: true });
            const list = entries
              .filter(e => e.isDirectory() && !e.name.startsWith('.'))
              .map(e => ({
                id: e.name,
                name: e.name,
                path: join(demoAppsDir, e.name),
                discoveryFile: join(demoAppsDir, e.name, 'discovery.json'),
              }));
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ ok: true, data: list }));
          } catch (err: unknown) {
            const message = err instanceof Error ? err.message : 'Failed to list demo apps';
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ ok: false, error: message, data: [] }));
          }
          return;
        }

        if (req.method === 'POST' && req.url === '/api/discover') {
          let body = '';
          req.on('data', chunk => {
            body += String(chunk);
          });
          req.on('end', async () => {
            try {
              const parsed = JSON.parse(body || '{}') as { repositoryPath?: string };
              const repositoryPath = parsed.repositoryPath;
              if (!repositoryPath) {
                res.statusCode = 400;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({ ok: false, error: 'repositoryPath is required' }));
                return;
              }
              let target = repositoryPath.startsWith('/')
                ? repositoryPath
                : resolve(rootDir, repositoryPath);
              if (!existsSync(target)) {
                if (repositoryPath === 'demo-app' && existsSync(join(demoAppsDir, 'demo-app-01'))) {
                  target = join(demoAppsDir, 'demo-app-01');
                } else if (existsSync(join(demoAppsDir, repositoryPath))) {
                  target = join(demoAppsDir, repositoryPath);
                }
              }

              // Dynamically import discovery engine built from packages/discovery and express framework adapter
              const { discoverProject } = await import('../../packages/discovery/dist/index.js');
              let adapters: any[] = [];
              try {
                const { ExpressFrameworkAdapter } = await import('../../plugins/frameworks/express/dist/index.js');
                adapters = [
                  {
                    framework: 'express',
                    languages: ['javascript', 'typescript'],
                    adapter: new ExpressFrameworkAdapter(),
                  },
                ];
              } catch {
                // If express plugin is not available, proceed without it
              }
              const result = await discoverProject(target, { adapters });
              const output = { ...result, repositoryPath };

              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify({ ok: true, data: output }));
            } catch (err: unknown) {
              const message = err instanceof Error ? err.message : 'Discovery execution failed';
              res.statusCode = 500;
              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify({ ok: false, error: message }));
            }
          });
          return;
        }

        next();
      });
    },
  };
}

export default defineConfig({
  server: { host: '127.0.0.1', port: 5173, strictPort: true },
  preview: { host: '127.0.0.1', port: 4173, strictPort: true },
  plugins: [agentoDiscoveryDevPlugin()],
});

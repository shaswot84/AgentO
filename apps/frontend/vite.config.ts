import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, type Plugin } from 'vite';
import { createLocalApi } from './server/api.ts';
import { localExecution } from './server/execution.ts';

function workspacePlugin(): Plugin {
  const frontend = fileURLToPath(new URL('.', import.meta.url));
  const root = resolve(frontend, '../..');
  const middleware = createLocalApi({ root,
    file: process.env.AGENTO_WORKSPACE_FILE ?? resolve(frontend, '.agento/workspace.json'),
    execution: localExecution(root),
  });
  return {
    name: 'agento-local-workspace',
    configureServer(server) {
      server.middlewares.use(middleware);
      server.httpServer?.once('close', () => { void middleware.close().catch(() => undefined); });
    },
    configurePreviewServer(server) {
      server.middlewares.use(middleware);
      server.httpServer.once('close', () => { void middleware.close().catch(() => undefined); });
    },
  };
}

export default defineConfig({
  server: { host: '127.0.0.1', port: 5173, strictPort: true },
  preview: { host: '127.0.0.1', port: 4173, strictPort: true },
  plugins: [workspacePlugin()],
});

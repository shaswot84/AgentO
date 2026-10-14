import { createServer } from 'node:http';
import { WebSocketServer } from 'ws';
import { createApp } from './app.js';

const port = Number(process.env.PORT) || 3400;
const app = createApp();
const server = createServer(app);

const wss = new WebSocketServer({ server, path: '/ws/live' });
wss.on('connection', ws => {
  ws.send(JSON.stringify({ type: 'telemetry_stream', status: 'online' }));
});

server.listen(port, () => {
  console.log(`Demo App 04 (Edge Telemetry SPA) listening on http://127.0.0.1:${port}`);
});

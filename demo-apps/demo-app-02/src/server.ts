import { buildApp } from './app.js';
import { config } from './config.js';

async function main() {
  const app = await buildApp();
  try {
    const address = await app.listen({ port: config.port, host: config.host });
    console.log(`demo-app-02 server listening at ${address}`);
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

if (process.env.NODE_ENV !== 'test') {
  main();
}

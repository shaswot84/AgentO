import { createServer } from 'node:https';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

const [directory, key, cert] = process.argv.slice(2);
process.env.DB_PATH = ':memory:';
const app = await import(pathToFileURL(join(directory, 'src/app.ts')).href);
const database = await import(pathToFileURL(join(directory, 'src/db/database.ts')).href);
const config = await import(pathToFileURL(join(directory, 'src/config.ts')).href);
database.initDatabase(); config.setSecurityMode('vulnerable');
const server = createServer({ key: readFileSync(key), cert: readFileSync(cert) }, app.createApp());
server.listen(0, '127.0.0.1', () => process.send({ baseUrl: `https://127.0.0.1:${server.address().port}` }));
process.on('SIGTERM', () => {
  server.closeAllConnections();
  server.close(() => { database.db.close(); process.exit(0); });
});

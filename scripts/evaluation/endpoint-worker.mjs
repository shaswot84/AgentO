// Keep the historical custom-extractor benchmark arm independent of the production default.
import { ExpressSourceAnalyzer } from '../../plugins/frameworks/express/dist/index.js';
const [repositoryPath, id] = process.argv.slice(2);
if (!repositoryPath || !id) throw new Error('invalid-worker-arguments');
const analysis = await new ExpressSourceAnalyzer().extract({ id, name: id, mode: 'code-aware', repositoryPath,
  languages: ['javascript', 'typescript'], baseUrl: 'http://127.0.0.1:1', allowedOrigins: ['http://127.0.0.1:1'] });
process.stdout.write(JSON.stringify(analysis));

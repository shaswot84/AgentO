import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { cp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scoreRoutes } from './endpoint-score.mjs';
const run = promisify(execFile);
const args = process.argv.slice(2);
if (args.length !== 4 || args[0] !== '--noir' || args[2] !== '--output') throw new Error('Usage: node scripts/evaluation/noir-controls.mjs --noir /path/to/noir --output /new/results');
const executable = resolve(args[1]), output = resolve(args[3]);
await mkdir(output, { recursive: false, mode: 0o700 });
await mkdir(join(output, 'source'));
const config = join(output, 'noir.yaml');
await writeFile(config, '{}\n');
const env = Object.fromEntries(['PATH', 'LANG', 'HOME', 'TMPDIR'].flatMap(key => process.env[key] ? [[key, process.env[key]]] : []));
env.XDG_CONFIG_HOME = join(output, 'config'); env.XDG_CACHE_HOME = join(output, 'cache');
const cases = JSON.parse(await readFile(new URL('./endpoint-controls.json', import.meta.url), 'utf8')).cases;
const results = { schemaVersion: 1, description: 'Source-only parser controls; no target dependencies installed and no target module executed.', cases: [] };
for (const entry of cases) {
  const source = join(output, 'source', entry.id);
  await cp(fileURLToPath(new URL(`./endpoint-controls/${entry.id}`, import.meta.url)), source, { recursive: true });
  const row = { ...entry, arms: {} };
  for (const arm of ['agento', 'noir']) {
    const command = arm === 'agento' ? process.execPath : executable;
    const argv = arm === 'agento' ? [fileURLToPath(new URL('./endpoint-worker.mjs', import.meta.url)), source, entry.id]
      : ['scan', source, '-f', 'json', '--no-log', '--no-color', '--no-spinner', '--strict', '--concurrency', '1', '--config-file', config, '--only-techs', 'js_express'];
    const { stdout } = await run(command, argv, { env, timeout: 15_000, maxBuffer: 8 * 1024 * 1024 });
    const raw = JSON.parse(stdout);
    const endpoints = raw.endpoints.map(endpoint => ({ method: endpoint.method, path: arm === 'agento' ? endpoint.path : endpoint.url }));
    const expected = scoreRoutes(endpoints, entry.expected), forbidden = scoreRoutes(endpoints, entry.forbidden);
    row.arms[arm] = { endpoints, expected, forbidden, allExpectedFound: expected.every(item => item.matched), noForbiddenFound: forbidden.every(item => !item.matched) };
    await writeFile(join(output, `${entry.id}-${arm}.json`), JSON.stringify(raw, null, 2) + '\n');
  }
  results.cases.push(row);
}
await writeFile(join(output, 'results.json'), JSON.stringify(results, null, 2) + '\n');
console.log(JSON.stringify(results, null, 2));

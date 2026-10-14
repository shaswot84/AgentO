import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { AnalysisContext } from '@agento/core';
import { TesterArmyE2EAdapter } from './adapter.js';
import { DEMO_IDENTITIES, demoBrowserOptions } from './demo.js';
import { FileSessionStore } from './sessions.js';

/** Standalone controlled-demo runner. Other applications configure the library API. */
export async function main(args = process.argv.slice(2)): Promise<number> {
  try {
    const values = new Map<string, string>();
    for (let index = 0; index < args.length; index += 2) {
      const key = args[index], value = args[index + 1];
      if (!key || !['--url', '--allow-origin', '--identity', '--goal', '--session-dir', '--output'].includes(key)
        || !value || value.startsWith('--') || values.has(key)) throw new Error();
      values.set(key, value);
    }
    const baseUrl = values.get('--url'), allowedOrigin = values.get('--allow-origin');
    const identityId = values.get('--identity') ?? 'alice';
    if (!baseUrl || !allowedOrigin || !DEMO_IDENTITIES.some(item => item.id === identityId)) throw new Error();
    // The executable example deliberately addresses only the local controlled storefront.
    if (!['localhost', '127.0.0.1', '[::1]'].includes(new URL(baseUrl).hostname)) throw new Error();
    const context: AnalysisContext = { project: { id: 'controlled-demo', name: 'Controlled demo', mode: 'black-box',
      baseUrl, allowedOrigins: [allowedOrigin], languages: [] }, components: [], endpoints: [],
      identities: DEMO_IDENTITIES, resources: [], signals: [], evidence: [] };
    const sessionDirectory = values.get('--session-dir');
    const adapter = new TesterArmyE2EAdapter({ ...demoBrowserOptions(),
      ...(sessionDirectory ? { sessionStore: new FileSessionStore(sessionDirectory) } : {}) });
    const result = await adapter.observe(context, { id: 'demo-orders', identityId,
      goal: values.get('--goal') ?? 'open newest order' });
    const formatted = `${JSON.stringify(result, null, 2)}\n`;
    const outputPath = values.get('--output');
    if (outputPath) {
      await writeFile(outputPath, formatted, 'utf8');
    }
    process.stdout.write(formatted);
    return result.outcome === 'COMPLETED' ? 0 : 1;
  } catch {
    process.stderr.write('Usage: npm run observe -- --url http://127.0.0.1:3000 --allow-origin http://127.0.0.1:3000 [--identity alice|bob|admin] [--goal "open newest order"] [--session-dir .agento-browser] [--output <path>]\n');
    return 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) process.exitCode = await main();

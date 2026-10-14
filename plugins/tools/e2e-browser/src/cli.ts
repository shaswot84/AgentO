import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { AnalysisContext } from '@agento/core';
import { TesterArmyE2EAdapter } from './adapter.js';
import { storefrontBrowserOptions } from './targets/storefront.js';
import { purchasesBrowserOptions } from './targets/purchases.js';
import { portalBrowserOptions } from './targets/portal.js';
import { edgeSpaBrowserOptions } from './targets/edge-spa.js';
import { FileSessionStore } from './sessions.js';

/** Standalone controlled-fixture runner. Other applications configure the library API. */
export async function main(args = process.argv.slice(2)): Promise<number> {
  try {
    const values = new Map<string, string>();
    for (let index = 0; index < args.length; index += 2) {
      const key = args[index], value = args[index + 1];
      if (!key || !['--url', '--allow-origin', '--target', '--identity', '--goal', '--session-dir', '--output'].includes(key)
        || !value || value.startsWith('--') || values.has(key)) throw new Error();
      values.set(key, value);
    }
    const baseUrl = values.get('--url'), allowedOrigin = values.get('--allow-origin');
    if (!baseUrl || !allowedOrigin) throw new Error();
    const targetName = values.get('--target') ?? 'storefront';
    if (!['storefront', 'purchases', 'portal', 'edge-spa'].includes(targetName)) throw new Error();
    const options = targetName === 'storefront' ? storefrontBrowserOptions([allowedOrigin])
      : targetName === 'purchases' ? purchasesBrowserOptions([allowedOrigin])
      : targetName === 'portal' ? portalBrowserOptions([allowedOrigin])
      : edgeSpaBrowserOptions([allowedOrigin]);
    const identities = options.target!.personas!;
    const identityId = values.get('--identity') ?? identities[0]!.id;
    if (!identities.some(item => item.id === identityId)) throw new Error();
    // Seeded credentials are only for local controlled demo targets.
    if (!['localhost', '127.0.0.1', '[::1]'].includes(new URL(baseUrl).hostname)) throw new Error();
    const context: AnalysisContext = { project: { id: `controlled-${targetName}`, name: 'Controlled fixture', mode: 'black-box',
      baseUrl, allowedOrigins: [allowedOrigin], languages: [] }, components: [], endpoints: [],
      identities, resources: [], signals: [], evidence: [] };
    const sessionDirectory = values.get('--session-dir');
    const adapter = new TesterArmyE2EAdapter({ ...options,
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
    process.stderr.write('Usage: npm run observe -- --url <loopback-url> --allow-origin <origin> [--target storefront|purchases|portal|edge-spa] [--identity <persona>] [--goal "open newest order"] [--session-dir .agento-browser] [--output <path>]\n');
    return 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) process.exitCode = await main();

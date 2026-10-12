#!/usr/bin/env node
import { readdir, writeFile, stat } from 'node:fs/promises';
import { basename, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { discoverProject } from '../packages/discovery/dist/index.js';
import { ExpressFrameworkAdapter } from '../plugins/frameworks/express/dist/index.js';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const rootDir = resolve(__dirname, '..');
const demoAppsDir = resolve(rootDir, 'demo-apps');

async function listDemoApps() {
  try {
    const entries = await readdir(demoAppsDir, { withFileTypes: true });
    return entries.filter(e => e.isDirectory() && !e.name.startsWith('.')).map(e => e.name);
  } catch {
    return [];
  }
}

async function hasDiscoverySnapshot(dir) {
  try {
    const s = await stat(join(dir, 'discovery.json'));
    return s.isFile();
  } catch {
    return false;
  }
}

async function syncDemoDiscoveryFixture(discoveryResult) {
  try {
    const fixturePath = resolve(rootDir, 'apps', 'frontend', 'src', 'data', 'demo-discovery.ts');
    const content = `import type { DiscoveryResult } from '@agento/discovery';\n\n// Saved output from discoverProject('demo-app'); no browser filesystem access.\nexport const demoDiscovery: DiscoveryResult = ${JSON.stringify(
      { ...discoveryResult, repositoryPath: 'demo-app' },
      null,
      2
    )};\n`;
    await writeFile(fixturePath, content, 'utf8');
    console.log(`  - Synced frontend demo fixture: apps/frontend/src/data/demo-discovery.ts`);
  } catch (err) {
    console.warn(`  - Warning: Failed to sync frontend fixture:`, err.message);
  }
}

async function discoverAndSave(targetPath, outputFile) {
  const expressAdapter = new ExpressFrameworkAdapter();
  const result = await discoverProject(targetPath, {
    adapters: [
      {
        framework: 'express',
        languages: ['javascript', 'typescript'],
        adapter: expressAdapter,
      },
    ],
  });

  const finalOutputFile = outputFile ? resolve(outputFile) : join(targetPath, 'discovery.json');
  await writeFile(finalOutputFile, JSON.stringify(result, null, 2), 'utf8');

  // If this target is demo-app-01, sync frontend fixture
  if (basename(targetPath) === 'demo-app-01') {
    await syncDemoDiscoveryFixture(result);
  }

  return { result, outputFile: finalOutputFile };
}

async function main() {
  const args = process.argv.slice(2);
  const isRescan = args.includes('--rescan') || args.includes('-r');
  const isAll = args.includes('--all') || args.includes('-a');
  const isHelp = args.includes('--help') || args.includes('-h');
  const targetArg = args.find(a => !a.startsWith('-'));

  if (isHelp || (!isRescan && !isAll && !targetArg)) {
    const demos = await listDemoApps();
    console.log('\nAgentO Project Discovery CLI');
    console.log('-----------------------------');
    console.log('Usage:');
    console.log('  node scripts/discover.mjs <project-name-or-path> [output-file]');
    console.log('  node scripts/discover.mjs --rescan (or -r)  # Re-scan all projects that have already been scanned');
    console.log('  node scripts/discover.mjs --all (or -a)     # Discover all demo applications in demo-apps/');
    console.log('\nAvailable demo apps in demo-apps/:');
    for (const demo of demos) {
      const scanned = await hasDiscoverySnapshot(join(demoAppsDir, demo));
      console.log(`  - ${demo.padEnd(16)} [${scanned ? 'already scanned' : 'not scanned'}]`);
    }
    console.log('\nExamples:');
    console.log('  node scripts/discover.mjs --rescan');
    console.log('  node scripts/discover.mjs demo-app-01');
    console.log('  node scripts/discover.mjs demo-app-02 /tmp/demo-02.json\n');
    process.exit(isHelp ? 0 : 1);
  }

  // Handle re-scanning all previously scanned projects
  if (isRescan) {
    const demos = await listDemoApps();
    const targets = [];
    for (const demo of demos) {
      const p = join(demoAppsDir, demo);
      if (await hasDiscoverySnapshot(p)) {
        targets.push({ name: demo, path: p });
      }
    }

    if (targets.length === 0) {
      console.log('\nNo previously scanned projects found with an existing discovery.json.');
      console.log('Run with a project name or --all to scan demo apps.\n');
      return;
    }

    console.log(`\nFound ${targets.length} already-scanned project(s) to re-scan:`);
    for (let i = 0; i < targets.length; i++) {
      const t = targets[i];
      console.log(`\n[${i + 1}/${targets.length}] Re-scanning: ${t.name}`);
      const { result, outputFile } = await discoverAndSave(t.path);
      console.log(`  - Languages:       ${result.languages.join(', ')}`);
      console.log(`  - Frameworks:      ${result.frameworks.join(', ') || 'none'}`);
      console.log(`  - Mode:            ${result.mode}`);
      console.log(`  - Adapters:        ${result.availableAdapterIds.join(', ') || 'none'}`);
      console.log(`  - Updated file:    ${outputFile}`);
    }
    console.log(`\n✓ Re-scan complete for ${targets.length} project(s).\n`);
    return;
  }

  // Handle scanning all demo projects
  if (isAll) {
    const demos = await listDemoApps();
    console.log(`\nScanning all ${demos.length} demo apps in demo-apps/:`);
    for (let i = 0; i < demos.length; i++) {
      const demo = demos[i];
      const p = join(demoAppsDir, demo);
      console.log(`\n[${i + 1}/${demos.length}] Scanning: ${demo}`);
      const { result, outputFile } = await discoverAndSave(p);
      console.log(`  - Languages:       ${result.languages.join(', ')}`);
      console.log(`  - Frameworks:      ${result.frameworks.join(', ') || 'none'}`);
      console.log(`  - Mode:            ${result.mode}`);
      console.log(`  - Adapters:        ${result.availableAdapterIds.join(', ') || 'none'}`);
      console.log(`  - Output:          ${outputFile}`);
    }
    console.log(`\n✓ Discovery complete for ${demos.length} project(s).\n`);
    return;
  }

  // Single target discovery
  let targetPath = resolve(targetArg);
  if (!targetArg.includes('/') && !targetArg.includes('\\')) {
    const potentialDemo = join(demoAppsDir, targetArg);
    targetPath = potentialDemo;
  }

  console.log(`Running Project Discovery on: ${targetPath}`);
  const { result, outputFile } = await discoverAndSave(targetPath, args[1] && !args[1].startsWith('-') ? args[1] : undefined);

  console.log(`\n Discovery completed successfully!`);
  console.log(`  - Project Name:    ${result.name}`);
  console.log(`  - Languages:       ${result.languages.join(', ')}`);
  console.log(`  - Frameworks:      ${result.frameworks.join(', ') || 'none'}`);
  console.log(`  - Mode:            ${result.mode}`);
  console.log(`  - Adapters:        ${result.availableAdapterIds.join(', ') || 'none'}`);
  console.log(`  - Output File:     ${outputFile}`);
  console.log(`\nYou can now attach ${basename(outputFile)} in the web GUI (http://localhost:5173).\n`);
}

main().catch(err => {
  console.error('Discovery error:', err);
  process.exit(1);
});

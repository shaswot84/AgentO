#!/usr/bin/env node
import { readdir, writeFile } from 'node:fs/promises';
import { basename, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { discoverProject } from '../packages/discovery/dist/index.js';

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

async function main() {
  const targetArg = process.argv[2];

  if (!targetArg) {
    const demos = await listDemoApps();
    console.log('\nUsage: node scripts/discover.mjs <project-name-or-path> [output-file]');
    console.log('\nAvailable demo apps in demo-apps/:');
    for (const demo of demos) {
      console.log(`  - ${demo} (run: node scripts/discover.mjs ${demo})`);
    }
    console.log('\nExample:');
    console.log('  node scripts/discover.mjs demo-app-02');
    console.log('  node scripts/discover.mjs demo-apps/demo-app-01 my-custom-output.json\n');
    process.exit(1);
  }

  // Resolve target directory
  let targetPath = resolve(targetArg);
  if (!targetArg.includes('/') && !targetArg.includes('\\')) {
    const potentialDemo = join(demoAppsDir, targetArg);
    targetPath = potentialDemo;
  }

  console.log(`Running Project Discovery on: ${targetPath}`);
  const result = await discoverProject(targetPath);

  // Determine output file: place directly inside the project directory
  let outputFile = process.argv[3];
  if (!outputFile) {
    outputFile = join(targetPath, 'discovery.json');
  } else {
    outputFile = resolve(outputFile);
  }

  await writeFile(outputFile, JSON.stringify(result, null, 2), 'utf8');
  console.log(`\n Discovery completed successfully!`);
  console.log(`  - Project Name:    ${result.name}`);
  console.log(`  - Languages:       ${result.languages.join(', ')}`);
  console.log(`  - Frameworks:      ${result.frameworks.join(', ') || 'none'}`);
  console.log(`  - Mode:            ${result.mode}`);
  console.log(`  - Output File:     ${outputFile}`);
  console.log(`\nYou can now attach ${basename(outputFile)} in the web GUI (http://localhost:5173).\n`);
}

main().catch(err => {
  console.error('Discovery error:', err);
  process.exit(1);
});

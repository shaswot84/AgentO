import { discoverProject } from './discovery.js';

const args = process.argv.slice(2);
if (args.length !== 1 || args[0] === '--help' || args[0] === '-h') {
  const help = 'Usage: npm run discover -- <repository-path>\nReads repository metadata and prints JSON. No target code or network requests run.\n';
  if (args[0] === '--help' || args[0] === '-h') process.stdout.write(help);
  else { process.stderr.write(help); process.exitCode = 1; }
} else {
  try {
    const result = await discoverProject(args[0]!);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (result.diagnostics.length > 0) process.exitCode = 1;
  } catch {
    process.stderr.write('Project discovery failed.\n');
    process.exitCode = 1;
  }
}

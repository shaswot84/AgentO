import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ExpressFrameworkAdapter } from './index.js';

const help = 'Usage: npm run extract -- <repository-path>\nPrints normalized Express source observations as JSON. No target code or requests run.\n';
export async function runCli(args: readonly string[], writeOut: (text: string) => void,
  writeError: (text: string) => void): Promise<number> {
  if (args.length !== 1 || args[0] === '--help' || args[0] === '-h') {
    if (args[0] === '--help' || args[0] === '-h') { writeOut(help); return 0; }
    writeError(help); return 1;
  }
  try {
    const repositoryPath = resolve(args[0]!);
    const analysis = await new ExpressFrameworkAdapter().extract({
      id: 'express-source', name: 'Express source', mode: 'code-aware', repositoryPath,
      baseUrl: 'http://localhost', allowedOrigins: [], languages: ['javascript', 'typescript'],
    });
    writeOut(`${JSON.stringify(analysis, null, 2)}\n`);
    return analysis.diagnostics.length ? 1 : 0;
  } catch {
    writeError('Express extraction failed.\n'); return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runCli(process.argv.slice(2), text => { process.stdout.write(text); },
    text => { process.stderr.write(text); });
}

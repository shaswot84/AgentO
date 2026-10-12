import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SemgrepAdapter } from './index.js';

const help = 'Usage: npm run analyze -- <repository-path> [--executable <semgrep-path>]\nPrints normalized static candidates as JSON; runtime verification is required.\n';
export async function runCli(args: readonly string[], writeOut: (text: string) => void,
  writeError: (text: string) => void): Promise<number> {
  if (args[0] === '--help' || args[0] === '-h') { writeOut(help); return 0; }
  if ((args.length !== 1 && args.length !== 3) || args[0]?.startsWith('-')
    || (args.length === 3 && (args[1] !== '--executable' || !args[2]))) { writeError(help); return 1; }
  try {
    const repositoryPath = resolve(args[0]!);
    const analysis = await new SemgrepAdapter(args[2] ? { executable: args[2] } : {}).analyze({
      id: 'static-source', name: 'Static source', mode: 'code-aware', repositoryPath,
      baseUrl: 'http://localhost', allowedOrigins: [], languages: ['javascript', 'typescript'],
    });
    writeOut(`${JSON.stringify(analysis, null, 2)}\n`);
    return analysis.status === 'completed' ? 0 : 1;
  } catch { writeError('Static analysis failed.\n'); return 1; }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runCli(process.argv.slice(2), text => { process.stdout.write(text); }, text => { process.stderr.write(text); });
}

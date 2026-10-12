import { constants } from 'node:fs';
import { lstat, open, readdir } from 'node:fs/promises';
import { extname, join, resolve } from 'node:path';
import ts from 'typescript-parser';
import type { ExpressDiagnostic } from './types.js';

const ignored = new Set(['node_modules', 'dist', 'build', 'coverage', 'vendor', 'out', 'target']);
const extensions = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts']);
const isTest = (file: string) => /(^|\/)(tests?|__tests__|fixtures?)(\/|$)|\.(test|spec)\.[^.]+$/.test(file);

export interface Repository {
  readonly root: string;
  readonly files: ReadonlyMap<string, ts.SourceFile>;
  readonly diagnostics: ExpressDiagnostic[];
}

/** No target modules, scripts, tsconfig plugins, or external imports are loaded. */
export async function readRepository(repositoryPath: string): Promise<Repository> {
  const root = resolve(repositoryPath);
  const files = new Map<string, ts.SourceFile>();
  const diagnostics: ExpressDiagnostic[] = [];
  let entriesRead = 0;
  let bytesRead = 0;
  let limited = false;
  const report = (code: ExpressDiagnostic['code'], file: string, message: string) => {
    diagnostics.push({ code, message, source: { file, startLine: 1 } });
  };
  async function walk(directory: string, depth: number): Promise<void> {
    if (depth > 40) { report('limit-reached', directory, 'Repository depth limit reached.'); return; }
    let entries;
    try { entries = await readdir(join(root, directory), { withFileTypes: true }); }
    catch { report('read-failed', directory || '.', 'Directory could not be read.'); return; }
    entries.sort((a, b) => a.name.localeCompare(b.name, 'en'));
    for (const entry of entries) {
      if (entry.name.startsWith('.') || entry.isSymbolicLink() || ignored.has(entry.name)) continue;
      if (++entriesRead > 20_000) {
        if (!limited) report('limit-reached', '.', 'Repository entry limit reached.');
        limited = true; return;
      }
      const file = directory ? `${directory}/${entry.name}` : entry.name;
      if (isTest(file)) continue;
      if (entry.isDirectory()) await walk(file, depth + 1);
      else if (entry.isFile() && extensions.has(extname(file))) {
        let handle;
        try {
          handle = await open(join(root, file), constants.O_RDONLY | constants.O_NOFOLLOW);
          if (!(await handle.stat()).isFile()) continue;
          const buffer = Buffer.alloc(1_048_577);
          let length = 0;
          while (length < buffer.length) {
            const result = await handle.read(buffer, length, buffer.length - length, null);
            if (result.bytesRead === 0) break;
            length += result.bytesRead;
          }
          if (length > 1_048_576 || bytesRead + length > 16_777_216) {
            report('limit-reached', file, 'Source size limit reached.'); continue;
          }
          bytesRead += length;
          const source = ts.createSourceFile(join(root, file), buffer.subarray(0, length).toString('utf8'), ts.ScriptTarget.Latest, true);
          const errors = (source as ts.SourceFile & { parseDiagnostics: readonly ts.Diagnostic[] }).parseDiagnostics;
          if (errors.length) { report('parse-failed', file, 'Source could not be parsed.'); continue; }
          files.set(source.fileName, source);
        } catch { report('read-failed', file, 'Source could not be read.'); }
        finally { await handle?.close().catch(() => undefined); }
      }
      if (limited) return;
    }
  }
  try {
    if (!(await lstat(root)).isDirectory()) throw new Error();
    await walk('', 0);
  } catch { report('repository-unavailable', '.', 'Repository must be an existing directory, not a symlink.'); }
  return { root, files, diagnostics };
}

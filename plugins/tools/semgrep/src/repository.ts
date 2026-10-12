import { constants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { extname, join, relative, resolve, sep } from 'node:path';
import ts from 'typescript-parser';
import type { SemgrepDiagnostic } from './types.js';

const ignored = new Set(['node_modules', 'dist', 'build', 'coverage', 'vendor', 'out', 'target']);
const extensions = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts']);
const excluded = (file: string) => /(^|\/)(tests?|__tests__|fixtures?)(\/|$)|\.(test|spec|d)\.[^.]+$/.test(file);
export interface Inventory {
  readonly files: ReadonlyMap<string, ts.SourceFile>;
  readonly diagnostics: SemgrepDiagnostic[];
}

/** Only source bytes are read; target manifests, modules, plugins, and scripts are never loaded. */
export async function readSources(repositoryPath: string): Promise<Inventory> {
  const root = resolve(repositoryPath);
  const files = new Map<string, ts.SourceFile>();
  const diagnostics: SemgrepDiagnostic[] = [];
  let entriesRead = 0, bytesRead = 0, stopped = false;
  const report = (code: SemgrepDiagnostic['code'], file: string, message: string) => {
    diagnostics.push({ code, message, source: { file, startLine: 1 } });
  };
  async function contained(path: string): Promise<boolean> {
    const local = relative(root, await realpath(path));
    return local !== '..' && !local.startsWith(`..${sep}`) && !resolve(path).includes('\0');
  }
  async function walk(directory: string, depth: number): Promise<void> {
    if (depth > 40) { report('limit-reached', directory, 'Source traversal depth limit reached.'); return; }
    let entries;
    try {
      const path = join(root, directory);
      if ((await lstat(path)).isSymbolicLink() || !await contained(path)) throw new Error();
      entries = await readdir(path, { withFileTypes: true });
    } catch { report('read-failed', directory || '.', 'Source directory could not be read.'); return; }
    entries.sort((a, b) => a.name.localeCompare(b.name, 'en'));
    for (const entry of entries) {
      if (stopped) return;
      if (++entriesRead > 20_000) { stopped = true; report('limit-reached', '.', 'Source entry limit reached.'); return; }
      if (entry.name.startsWith('.') || entry.isSymbolicLink() || ignored.has(entry.name)) continue;
      const file = directory ? `${directory}/${entry.name}` : entry.name;
      if (excluded(file)) continue;
      if (entry.isDirectory()) await walk(file, depth + 1);
      else if (entry.isFile() && extensions.has(extname(file))) {
        if (files.size >= 1_000) { stopped = true; report('limit-reached', '.', 'Source file limit reached.'); return; }
        let handle;
        try {
          const path = join(root, file);
          if (!await contained(path)) throw new Error();
          handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
          if (!(await handle.stat()).isFile()) throw new Error();
          const buffer = Buffer.alloc(1_048_577);
          let size = 0;
          while (size < buffer.length) {
            const chunk = await handle.read(buffer, size, buffer.length - size, null);
            if (!chunk.bytesRead) break;
            size += chunk.bytesRead;
          }
          if (size > 1_048_576 || bytesRead + size > 16_777_216) {
            report('limit-reached', file, 'Source byte limit reached.'); continue;
          }
          bytesRead += size;
          const source = ts.createSourceFile(file, buffer.subarray(0, size).toString('utf8'), ts.ScriptTarget.Latest, true);
          const errors = (source as ts.SourceFile & { parseDiagnostics: readonly ts.Diagnostic[] }).parseDiagnostics;
          if (errors.length) { report('parse-failed', file, 'Source could not be parsed.'); continue; }
          files.set(file, source);
        } catch { report('read-failed', file, 'Source file could not be read.'); }
        finally { await handle?.close().catch(() => undefined); }
      }
    }
  }
  try {
    if (!(await lstat(root)).isDirectory() || await realpath(root) !== root) throw new Error();
    await walk('', 0);
  } catch { report('repository-unavailable', '.', 'Repository must be a readable directory without symlink ancestors.'); }
  return { files, diagnostics };
}

import { randomUUID } from 'node:crypto';
import { mkdir, open, readFile, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';

/** Prevent dev/preview processes from overwriting the same workspace. */
export async function claimWorkspace(file: string): Promise<() => Promise<void>> {
  await mkdir(dirname(file), { recursive: true, mode: 0o700 });
  if (basename(dirname(file)) === '.agento') {
    try { await writeFile(join(dirname(file), '.gitignore'), '*\n', { flag: 'wx', mode: 0o600 }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
  }
  const lock = `${file}.lock`;
  const owner = JSON.stringify({ pid: process.pid, token: randomUUID() });
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await writeFile(lock, owner, { flag: 'wx', mode: 0o600 });
      return async () => {
        try { if (await readFile(lock, 'utf8') === owner) await rm(lock); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      // Serialize stale-owner recovery so competing starters cannot remove a new lock.
      const recoveryPath = `${lock}.recovery`;
      const recovery = await open(recoveryPath, 'wx', 0o600);
      let stale = false;
      try {
        const previous = JSON.parse(await readFile(lock, 'utf8')) as { pid: number };
        if (!Number.isSafeInteger(previous.pid) || previous.pid <= 0) throw new Error('Invalid workspace lock');
        try { process.kill(previous.pid, 0); }
        catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error;
          stale = true;
          await rm(lock);
        }
      } finally {
        await recovery.close();
        await rm(recoveryPath);
      }
      if (stale) continue;
      throw new Error('Another local service owns this workspace');
    }
  }
  throw new Error('Could not acquire workspace');
}

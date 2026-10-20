import { createHash } from 'node:crypto';
import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const version = '1.4.0';
const digest = '620e774f240be91b975ca0b2f04a5df568f0612ef1f74d182a43a25daf402001';
const destination = fileURLToPath(new URL('../node_modules/.bin/noir', import.meta.url));
const args = process.argv.slice(2);
if (process.platform !== 'linux' || process.arch !== 'x64') {
  throw new Error('This installer supports Linux x64. Install Noir 1.4.0 for your host and set AGENTO_NOIR_EXECUTABLE.');
}
if (args.length && (args.length !== 2 || args[0] !== '--from')) throw new Error('Usage: npm run setup:noir -- [--from /path/to/download]');
let bytes;
if (args.length) bytes = await readFile(args[1]);
else {
  const response = await fetch(`https://github.com/owasp-noir/noir/releases/download/v${version}/noir-v${version}-linux-x86_64`,
    { signal: AbortSignal.timeout(120_000) });
  if (!response.ok) throw new Error('Noir download failed.');
  bytes = Buffer.from(await response.arrayBuffer());
}
if (createHash('sha256').update(bytes).digest('hex') !== digest) throw new Error('Noir checksum did not match the pinned release.');
await mkdir(dirname(destination), { recursive: true });
const temporary = `${destination}.${process.pid}.tmp`;
try {
  await writeFile(temporary, bytes, { mode: 0o700, flag: 'wx' });
  await chmod(temporary, 0o700);
  await rename(temporary, destination);
} finally { await rm(temporary, { force: true }); }
console.log(`Installed Noir ${version} with a verified checksum in the adapter's local tool directory.`);

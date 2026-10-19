import { readFile, readdir } from 'node:fs/promises';
import { expect, it } from 'vitest';

it('keeps vendor implementations, network clients and vulnerability judgments out of policy', async () => {
  const directory = new URL('../src/', import.meta.url);
  for (const file of (await readdir(directory)).filter(file => file.endsWith('.ts'))) {
    const source = await readFile(new URL(file, directory), 'utf8');
    expect(source, file).not.toMatch(/from ['"](?:@agento\/tool-|node:(?:http|https|net|tls|child_process))|\bfetch\s*\(/);
    expect(source, file).not.toMatch(/\b(?:dalfox|sqlmap|nuclei|zap|playwright|puppeteer)\b/i);
    expect(source, file).not.toMatch(/CWE-\d+|evaluateEvidence|CONFIRMED|NOT_REPRODUCED/);
  }
});

import { readFile, readdir } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

describe('rule dependency boundary', () => {
  it('keeps execution, browser vendors, cookie parsing and transport imports out of rule source', async () => {
    const directory = new URL('../src/', import.meta.url);
    for (const file of (await readdir(directory)).filter(file => file.endsWith('.ts'))) {
      const source = await readFile(new URL(file, directory), 'utf8');
      expect(source, file).not.toMatch(/\bfetch\s*\(|from ['"]node:(?:http|https|net|tls|child_process)['"]/);
      expect(source, file).not.toMatch(/from ['"](?:playwright|puppeteer|e2e|@e2e|@agento\/(?:tool-|framework-))/);
      expect(source, file).not.toMatch(/\.execute\s*\(|\.perform\s*\(|\.establishSession\s*\(|\.analyze\s*\(/);
      expect(source, file).not.toMatch(/import\s*\{[^}]+\}\s*from ['"]@agento\/runtime['"]/);
    }
  });
});

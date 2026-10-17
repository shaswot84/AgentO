import { readFile, readdir } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

describe('runtime dependency boundary', () => {
  it('keeps rule semantics, scanner integrations and browser vendors out of runtime source', async () => {
    const directory = new URL('../src/', import.meta.url);
    const files = (await readdir(directory)).filter(file => file.endsWith('.ts'));
    for (const file of files) {
      const source = await readFile(new URL(file, directory), 'utf8');
      expect(source, file).not.toMatch(/CWE-\d+|\bOWASP\b|\bSecurityProbe\b|\bFinding\b/);
      expect(source, file).not.toMatch(/from ['"](?:playwright|puppeteer|e2e|@e2e|@agento\/tool-)/);
    }
  });
});

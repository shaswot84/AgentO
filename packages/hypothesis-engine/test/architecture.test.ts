import { readFile, readdir } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

describe('reasoning dependency boundary', () => {
  it('contains no transport, vendor SDK, probe execution, verdict, or test-planning dependencies', async () => {
    const directory = new URL('../src/', import.meta.url);
    for (const file of (await readdir(directory)).filter(file => file.endsWith('.ts'))) {
      const source = await readFile(new URL(file, directory), 'utf8');
      expect(source, file).not.toMatch(/\bfetch\s*\(|from ['"]node:(?:http|https|net|tls|child_process)['"]/);
      expect(source, file).not.toMatch(/from ['"](?:playwright|puppeteer|openai|@agento\/(?:runtime|cwe|tool-|framework-))/);
      expect(source, file).not.toMatch(/\.execute\s*\(|\.generateTests\s*\(|\.evaluateEvidence\s*\(/);
    }
  });
});

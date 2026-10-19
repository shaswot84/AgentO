import { readFile, readdir } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

describe('tool-independent selection boundaries', () => {
  it('keeps vendor branches out of planning, probes, core and selection', async () => {
    for (const path of ['../src/', '../../runtime/src/probes/', '../../test-planner/src/', '../../core/src/']) {
      const directory = new URL(path, import.meta.url);
      for (const file of (await readdir(directory)).filter(file => file.endsWith('.ts'))) {
        const source = await readFile(new URL(file, directory), 'utf8');
        expect(source, `${path}${file}`).not.toMatch(/\b(?:dalfox|sqlmap|nuclei|zap|playwright|puppeteer)\b/i);
        expect(source, `${path}${file}`).not.toMatch(/from ['"]@agento\/tool-/);
      }
    }
  });

  it('keeps execution, network traffic and shell commands out of selection', async () => {
    const directory = new URL('../src/', import.meta.url);
    for (const file of (await readdir(directory)).filter(file => file.endsWith('.ts'))) {
      const source = await readFile(new URL(file, directory), 'utf8');
      expect(source, file).not.toMatch(/from ['"]node:(?:http|https|net|tls|child_process)['"]|\bfetch\s*\(/);
      expect(source, file).not.toMatch(/\.(?:execute|scan|perform|establishSession|evaluateEvidence|runWorkflow)\s*\(/);
    }
  });
});

import { readFile, readdir } from 'node:fs/promises';
import { expect, it } from 'vitest';

it('keeps tool execution and vendor dependencies outside the evidence store', async () => {
  const directory = new URL('../src/', import.meta.url);
  for (const file of (await readdir(directory)).filter(file => file.endsWith('.ts'))) {
    const source = await readFile(new URL(file, directory), 'utf8');
    expect(source, file).not.toMatch(/from ['"](?:@agento\/(?:runtime|cwe|tool-)|node:(?:http|https|net|tls|child_process))|\bfetch\s*\(/);
    expect(source, file).not.toMatch(/evaluateEvidence|executePlan|detectCandidates/);
  }
  const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  expect(Object.keys(manifest.dependencies)).toEqual(['@agento/core']);
});

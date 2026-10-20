import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { verifyComparison } from './noir-verify.mjs';
const recorded = fileURLToPath(new URL('../../docs/evaluation/noir', import.meta.url));
test('replays all recorded inventories, source references, repetitions and evidence hashes offline', async () => {
  assert.deepEqual(await verifyComparison(recorded), { projects: 7, timedRuns: 63 });
});
for (const mutation of ['changed-count', 'invented-prefix-hit', 'missing-case', 'damaged-artifact']) {
  test(`rejects ${mutation}`, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agento-noir-proof-test-'));
    try {
      await cp(recorded, directory, { recursive: true });
      const path = join(directory, 'results.json');
      const data = JSON.parse(await readFile(path, 'utf8'));
      const row = data.cases.find(item => item.id === 'realworld-express');
      if (mutation === 'changed-count') row.arms['noir-framework'].endpointCount++;
      if (mutation === 'invented-prefix-hit') row.arms['noir-framework'].routeReferences.find(item => !item.matched).matched = true;
      if (mutation === 'missing-case') data.cases.pop();
      if (mutation === 'damaged-artifact') await writeFile(join(directory, row.arms['noir-framework'].inventoryArtifact.path), 'invalid');
      await writeFile(path, JSON.stringify(data));
      await assert.rejects(verifyComparison(directory));
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
}

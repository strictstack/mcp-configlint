import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
async function snapshot(directory, prefix = '') {
  const result = {};
  for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) Object.assign(result, await snapshot(join(directory, entry.name), relative));
    else result[relative] = createHash('sha256').update(await readFile(join(directory, entry.name))).digest('hex');
  }
  return result;
}

test('ronda 4: duas regenerações independentes reproduzem todos os bytes das fixtures', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-configlint-fixture-regeneration-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const generated = [];
  for (const name of ['first', 'second']) {
    const output = join(directory, name);
    const execution = spawnSync(process.execPath, ['scripts/generate-fixtures.mjs', '--output-dir', output],
      { cwd: root, encoding: 'utf8', timeout: 30000 });
    assert.equal(execution.error, undefined);
    assert.equal(execution.status, 0, 'generator must complete without evaluating fixture data');
    assert.equal(execution.stderr, '');
    assert.match(execution.stdout, /^Generated \d+ original, \d+ round-3 and \d+ round-4 deterministic fixtures\.\n$/);
    generated.push(await snapshot(output));
  }
  const current = await snapshot(resolve(root, 'fixtures'));
  assert.deepEqual(generated[0], generated[1], 'independent generations must be byte-identical');
  assert.deepEqual(generated[0], current, 'checked-in corpus must match the generator exactly');
  t.diagnostic(`Fixture regeneration: ${JSON.stringify({ files: Object.keys(current).length,
    identicalGenerations: true, matchesStoredFixtures: true,
    sha256: createHash('sha256').update(JSON.stringify(current)).digest('hex') })};`);
});

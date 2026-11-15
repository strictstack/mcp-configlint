import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { lintConfig, RULES } from '../src/engine.mjs';

const sets = [
  { name: 'original', root: new URL('../fixtures/', import.meta.url), manifest: 'manifest.json' },
  { name: 'round3', root: new URL('../fixtures/corpus/', import.meta.url), manifest: 'manifest.json' },
  { name: 'round4', root: new URL('../fixtures/corpus/', import.meta.url), manifest: 'manifest-round4.json' },
];
const empty = () => ({ fixtures: 0, parsedConfigurations: 0, rejectedConfigurations: 0, servers: 0,
  truePositives: 0, falsePositives: 0, falseNegatives: 0, trueNegatives: 0 });
const ratio = (numerator, denominator) => denominator === 0 ? null : numerator / denominator;
const metrics = (dataset, counts, categories) => ({ dataset, ...counts, totalRules: RULES.length,
  totalPairs: counts.servers * RULES.length,
  precision: ratio(counts.truePositives, counts.truePositives + counts.falsePositives),
  recall: ratio(counts.truePositives, counts.truePositives + counts.falseNegatives), categories });

test('ronda 4: matriz por servidor e matriz combinada derivam dos rótulos de cada fixture', async t => {
  const combined = empty();
  const combinedCategories = {};
  const rounds = {};
  const mismatches = [];
  const manifestIds = new Set();
  for (const set of sets) {
    const manifest = JSON.parse(await readFile(new URL(set.manifest, set.root), 'utf8'));
    assert.equal(manifest.synthetic, true, set.name);
    assert.equal(manifest.fixtureCount, manifest.cases.length, set.name);
    const totals = empty();
    const categories = {};
    for (const entry of manifest.cases) {
      assert.equal(manifestIds.has(entry.id), false, `duplicate fixture: ${entry.id}`);
      manifestIds.add(entry.id);
      const result = lintConfig(await readFile(new URL(entry.filename, set.root), 'utf8'));
      totals.fixtures++;
      if (!result.valid) {
        totals.rejectedConfigurations++;
        const actual = [...new Set(result.findings.map(finding => finding.ruleId))].sort();
        if (JSON.stringify(actual) !== JSON.stringify([...entry.expectedRuleIds].sort())) {
          mismatches.push({ fixture: entry.id, actual, expected: entry.expectedRuleIds });
        }
        continue; // Rejected configurations have no parsed server/rule pairs.
      }
      totals.parsedConfigurations++;
      assert.equal(result.ai_generated, false, entry.id);
      if (entry.expectedServerRuleIds) assert.equal(result.serverCount, entry.expectedServerRuleIds.length, entry.id);
      for (let index = 0; index < result.serverCount; index++) {
        const actual = new Set(result.findings.filter(finding => ['configuration', `server#${index + 1}`]
          .includes(finding.location.server)).map(finding => finding.ruleId));
        const expected = new Set(entry.expectedServerRuleIds?.[index] ?? entry.expectedRuleIds);
        const category = categories[entry.category] ??= { servers: 0, truePositives: 0,
          falsePositives: 0, falseNegatives: 0, trueNegatives: 0 };
        for (const rule of RULES) {
          const key = actual.has(rule.id) ? expected.has(rule.id) ? 'truePositives' : 'falsePositives'
            : expected.has(rule.id) ? 'falseNegatives' : 'trueNegatives';
          totals[key]++; category[key]++;
        }
        totals.servers++; category.servers++;
        if (JSON.stringify([...actual].sort()) !== JSON.stringify([...expected].sort())) {
          mismatches.push({ fixture: entry.id, server: index + 1, actual: [...actual].sort(), expected: [...expected].sort() });
        }
      }
    }
    assert.equal(totals.parsedConfigurations + totals.rejectedConfigurations, totals.fixtures, set.name);
    assert.equal(totals.truePositives + totals.falsePositives + totals.falseNegatives + totals.trueNegatives,
      totals.servers * RULES.length, set.name);
    rounds[set.name] = metrics(`synthetic-${set.name}-per-server`, totals, categories);
    for (const key of Object.keys(combined)) combined[key] += totals[key];
    for (const [name, counts] of Object.entries(categories)) {
      const target = combinedCategories[name] ??= Object.fromEntries(Object.keys(counts).map(key => [key, 0]));
      for (const [key, count] of Object.entries(counts)) target[key] += count;
    }
  }
  // Keep the explicitly requested counterexamples in the labelled corpus.
  for (const wrapper of ['doas', 'xargs', 'flock', 'time', 'unshare', 'command', 'exec', 'su', 'script']) {
    for (const suffix of ['', '-inline', '-mixed', '-quoted-data', '-no-eval']) {
      assert.ok(manifestIds.has(`round4-wrapper-${wrapper}${suffix}`));
    }
  }
  for (const variant of ['irm-pipeline', 'webclient-pipeline', 'iwr-content', 'webrequest-content']) {
    for (const suffix of ['', '-inline', '-mixed', '-quoted-data', '-comment']) {
      assert.ok(manifestIds.has(`round4-powershell-${variant}${suffix}`));
    }
  }
  assert.ok(rounds.round4.categories.valid.servers >= 20);
  assert.ok(rounds.round4.categories['warning-only'].servers >= 20);
  assert.ok(rounds.round4.categories.dangerous.servers >= 40);
  t.diagnostic(JSON.stringify(rounds.round4));
  t.diagnostic(JSON.stringify({ ...metrics('synthetic-combined-per-server', combined, combinedCategories),
    constituentDatasets: Object.fromEntries(Object.entries(rounds).map(([name, round]) => [name,
      Object.fromEntries(Object.keys(empty()).map(key => [key, round[key]]))])) }));
  assert.deepEqual(mismatches, [], 'fixture/server labels must match exactly; summaries never hide a missed case');
  assert.equal(combined.falsePositives, 0);
  assert.equal(combined.falseNegatives, 0);
});

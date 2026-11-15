// Synthetic reports exercise persistence without rerunning the enclosing suite.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { latestReportPath, publishReport } from '../scripts/run-tests.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
function fixture(t) {
  // Everything lives under the system temporary directory, never inside the repository.
  const base = mkdtempSync(resolve(tmpdir(), 'mcp-configlint-report-test-'));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const directory = resolve(base, 'repo');
  mkdirSync(directory);
  const report = {
    schema: 'mib.test-report.v1', comando: 'synthetic fixture',
    total: 1, passou: 1, falhou: 0, ignorados: 0,
    duracao_s: 0.125, ambiente: { node: 'fixture-a' }, gerado_em: '2026-01-01T00:00:00Z',
    ficheiros: ['fixture.test.mjs'], metricas_corpus: { fixtures: 1, precision: 1 },
    contadores_offline: { connections: 0, processes: 0 },
  };
  return { base, directory, report, snapshot: resolve(directory, 'TEST_REPORT.json'),
    latest: resolve(base, 'measurement/TEST_REPORT.latest.json') };
}

test('first execution writes the identical snapshot and latest measurement', t => {
  const { directory, report, snapshot, latest } = fixture(t);
  assert.equal(publishReport(directory, report, latest), true);
  assert.deepEqual(readFileSync(snapshot), readFileSync(latest));
});

test('fresh duration, environment and date preserve snapshot bytes and timestamp', t => {
  const { directory, report, snapshot, latest } = fixture(t);
  publishReport(directory, report, latest);
  const original = readFileSync(snapshot);
  utimesSync(snapshot, 1_000_000_000, 1_000_000_000);
  const originalMtime = statSync(snapshot).mtimeMs;
  const fresh = { ...report, duracao_s: 1.75, ambiente: { node: 'fixture-b' }, gerado_em: '2026-01-02T00:00:00Z' };
  assert.equal(publishReport(directory, fresh, latest), false);
  assert.deepEqual(readFileSync(snapshot), original);
  assert.equal(statSync(snapshot).mtimeMs, originalMtime);
  assert.deepEqual(JSON.parse(readFileSync(latest, 'utf8')), fresh);
});

test('new failure replaces the snapshot with the complete fresh measurement', t => {
  const { directory, report, snapshot, latest } = fixture(t);
  publishReport(directory, report, latest);
  const failure = { ...report, passou: 0, falhou: 1, duracao_s: 0.375, gerado_em: '2026-01-03T00:00:00Z' };
  assert.equal(publishReport(directory, failure, latest), true);
  assert.deepEqual(JSON.parse(readFileSync(snapshot, 'utf8')), failure);
});

test('corpus metrics, offline counters, file list and new fields are invariants', t => {
  const { directory, report, latest } = fixture(t);
  publishReport(directory, report, latest);
  report.metricas_corpus.precision = 0.5;
  assert.equal(publishReport(directory, report, latest), true);
  report.contadores_offline.connections = 1;
  assert.equal(publishReport(directory, report, latest), true);
  report.ficheiros = ['replacement.test.mjs'];
  assert.equal(publishReport(directory, report, latest), true);
  report.newInvariant = { value: 2 };
  assert.equal(publishReport(directory, report, latest), true);
  assert.equal(publishReport(directory, report, latest), false);
});

test('invalid snapshot is replaced by the complete execution', t => {
  const { directory, report, snapshot, latest } = fixture(t);
  writeFileSync(snapshot, '{invalid');
  assert.equal(publishReport(directory, report, latest), true);
  assert.deepEqual(JSON.parse(readFileSync(snapshot, 'utf8')), report);
});


test('runner reexecutes on repeat and records a later real failure', t => {
  const { directory, snapshot, latest } = fixture(t);
  mkdirSync(resolve(directory, 'scripts'));
  mkdirSync(resolve(directory, 'tests'));
  copyFileSync(resolve(root, 'scripts/run-tests.mjs'), resolve(directory, 'scripts/run-tests.mjs'));
  const fixtureTest = resolve(directory, 'tests/fixture.test.mjs');
  const fixtureCode = `import test from 'node:test';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
test('real execution', () => {
  const count = existsSync('executions') ? Number(readFileSync('executions', 'utf8')) : 0;
  writeFileSync('executions', String(count + 1));
  if (count === 2) throw new Error('intentional fixture failure');
});
`;
  writeFileSync(fixtureTest, fixtureCode);
  // A fresh CLI process must not inherit node:test's nested-run sentinel.
  const environment = { ...process.env, MIB_TEST_REPORT_LATEST: latest };
  delete environment.NODE_TEST_CONTEXT;
  const run = () => spawnSync(process.execPath, ['scripts/run-tests.mjs'],
    { cwd: directory, env: environment, encoding: 'utf8', timeout: 30_000 });
  const first = run();
  assert.equal(first.status, 0, first.stderr);
  const original = readFileSync(snapshot);
  const second = run();
  assert.equal(second.status, 0, second.stderr);
  assert.equal(readFileSync(resolve(directory, 'executions'), 'utf8'), '2');
  assert.deepEqual(readFileSync(snapshot), original);
  const fresh = JSON.parse(readFileSync(latest, 'utf8'));
  assert.notEqual(fresh.gerado_em, JSON.parse(original).gerado_em);
  assert.deepEqual([fresh.total, fresh.passou, fresh.falhou], [1, 1, 0]);
  const failed = run();
  assert.equal(failed.status, 1);
  const failure = JSON.parse(readFileSync(snapshot, 'utf8'));
  assert.deepEqual([failure.total, failure.passou, failure.falhou], [1, 0, 1]);
  assert.equal(readFileSync(resolve(directory, 'executions'), 'utf8'), '3');
});

function runnerFixture(t) {
  const { base, directory } = fixture(t);
  mkdirSync(resolve(directory, 'scripts'));
  mkdirSync(resolve(directory, 'tests'));
  copyFileSync(resolve(root, 'scripts/run-tests.mjs'), resolve(directory, 'scripts/run-tests.mjs'));
  writeFileSync(resolve(directory, 'tests/fixture.test.mjs'), "import test from 'node:test';\ntest('ok', () => {});\n");
  const environment = { ...process.env };
  delete environment.NODE_TEST_CONTEXT;
  delete environment.MIB_TEST_REPORT_LATEST;
  return { base, directory, environment };
}

test('regression: runner without MIB_TEST_REPORT_LATEST writes the measurement outside the repository', t => {
  const { directory, environment } = runnerFixture(t);
  const scratch = mkdtempSync(resolve(tmpdir(), 'mcp-configlint-runner-tmp-'));
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  const run = spawnSync(process.execPath, ['scripts/run-tests.mjs'],
    { cwd: directory, env: { ...environment, TMPDIR: scratch }, encoding: 'utf8', timeout: 30_000 });
  assert.equal(run.status, 0, run.stderr);
  const printed = run.stderr.match(/^Medição desta execução: (\/[^;\n]+); TEST_REPORT\.json atualizado\.$/m);
  assert.ok(printed, run.stderr);
  const latest = printed[1];
  assert.ok(relative(directory, latest).startsWith('..'), 'measurement must be outside the repository');
  assert.ok(latest.startsWith(`${scratch}/mcp-configlint-test-report-`), latest);
  assert.deepEqual(JSON.parse(readFileSync(latest, 'utf8')), JSON.parse(readFileSync(resolve(directory, 'TEST_REPORT.json'), 'utf8')));
  // Only the versioned snapshot is (re)generated in the tree; no .work/ or any other residue.
  assert.deepEqual(readdirSync(directory).sort(), ['TEST_REPORT.json', 'scripts', 'tests']);
  assert.equal(existsSync(resolve(directory, '.work')), false);
});

test('regression: MIB_TEST_REPORT_LATEST inside the repository is refused with exit 2 and nothing written', t => {
  const { directory, environment } = runnerFixture(t);
  const run = spawnSync(process.execPath, ['scripts/run-tests.mjs'], { cwd: directory,
    env: { ...environment, MIB_TEST_REPORT_LATEST: resolve(directory, '.work/TEST_REPORT.latest.json') }, encoding: 'utf8', timeout: 30_000 });
  assert.equal(run.status, 2);
  assert.match(run.stderr, /MIB_TEST_REPORT_LATEST aponta para dentro do repositório/);
  assert.deepEqual(readdirSync(directory).sort(), ['scripts', 'tests']);
  assert.throws(() => latestReportPath(directory, { MIB_TEST_REPORT_LATEST: resolve(directory, 'x.json') }), RangeError);
  assert.throws(() => latestReportPath(directory, { MIB_TEST_REPORT_LATEST: resolve(directory, '..x.json') }), RangeError);
  assert.equal(latestReportPath(directory, { MIB_TEST_REPORT_LATEST: resolve(directory, '../outside.json') }), resolve(directory, '../outside.json'));
});

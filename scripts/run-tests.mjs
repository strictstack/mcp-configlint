// Relatório derivado do TAP real. A medição de cada execução fica FORA do repositório:
// no caminho de MIB_TEST_REPORT_LATEST ou num diretório temporário novo (caminho impresso).
// TEST_REPORT.json (versionado) só é regenerado quando os resultados invariantes mudam.
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { hostname, platform, release, tmpdir } from 'node:os';
import { resolve, dirname, isAbsolute, join, relative, sep } from 'node:path';
import { isDeepStrictEqual } from 'node:util';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const volatileFields = new Set(['duracao_s', 'ambiente', 'gerado_em']);

export function latestReportPath(directory, environment = process.env) {
  const configured = environment.MIB_TEST_REPORT_LATEST;
  if (!configured) return join(mkdtempSync(join(tmpdir(), 'mcp-configlint-test-report-')), 'TEST_REPORT.latest.json');
  const latest = resolve(configured);
  const inside = relative(resolve(directory), latest);
  const outside = inside === '..' || inside.startsWith(`..${sep}`) || isAbsolute(inside);
  if (!outside) {
    throw new RangeError('MIB_TEST_REPORT_LATEST aponta para dentro do repositório; indique um caminho fora da árvore.');
  }
  return latest;
}

export function publishReport(directory, report, latest) {
  if (!latest) throw new TypeError('publishReport: caminho da medição em falta.');
  const encoded = `${JSON.stringify(report, null, 2)}\n`;
  mkdirSync(dirname(latest), { recursive: true });
  writeFileSync(latest, encoded);
  const snapshot = resolve(directory, 'TEST_REPORT.json');
  let previous;
  try {
    previous = JSON.parse(readFileSync(snapshot, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error;
  }
  const invariant = value => Object.fromEntries(Object.entries(value).filter(([key]) => !volatileFields.has(key)));
  if (previous && !Array.isArray(previous) && typeof previous === 'object'
      && isDeepStrictEqual(invariant(previous), invariant(report))) return false;
  writeFileSync(snapshot, encoded);
  return true;
}

export function main() {
  let latest;
  try {
    latest = latestReportPath(root);
  } catch (error) {
    if (!(error instanceof RangeError)) throw error;
    process.stderr.write(`${error.message}\n`);
    return 2;
  }
  const files = readdirSync(resolve(root, 'tests')).filter(x => x.endsWith('.test.mjs')).sort();
  const started = performance.now();
  const run = spawnSync(process.execPath, ['--experimental-vm-modules', '--test', '--test-reporter=tap',
    ...files.map(x => `tests/${x}`)], { cwd: root, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
  process.stdout.write(run.stdout ?? '');
  process.stderr.write(run.stderr ?? '');
  const metric = name => Number((run.stdout ?? '').match(new RegExp(`^# ${name} (\\d+)$`, 'm'))?.[1] ?? 0);
  const report = {
    schema: 'mib.test-report.v1', comando: 'npm test', total: metric('tests'), passou: metric('pass'),
    falhou: metric('fail') || (run.status !== 0 ? 1 : 0), ignorados: metric('skipped') + metric('todo'),
    duracao_s: Number(((performance.now() - started) / 1000).toFixed(6)),
    ambiente: { no: hostname(), os: `${platform()} ${release()}`, node: process.version },
    suites: [{ nome: 'node:test', total: metric('tests'), passou: metric('pass'), falhou: metric('fail') }],
    modo_medicao: 'harness', gerado_em: new Date().toISOString(), ficheiros: files,
  };
  const corpusLines = (run.stdout ?? '').split('\n').filter(line => line.startsWith('# {"dataset":'));
  const corpus = corpusLines.map(line => JSON.parse(line.slice(2)));
  const configMetrics = corpus.find(value => value.dataset === 'synthetic-fixtures-only');
  const serverMetrics = corpus.find(value => value.dataset === 'synthetic-fixtures-per-server');
  const round3Metrics = corpus.find(value => value.dataset === 'synthetic-round3-per-server');
  const round4Metrics = corpus.find(value => value.dataset === 'synthetic-round4-per-server');
  const combinedMetrics = corpus.find(value => value.dataset === 'synthetic-combined-per-server');
  const offlineLine = (run.stdout ?? '').match(/^# Offline counters: (\{[^\n]+?\});/m);
  const round4OfflineLine = (run.stdout ?? '').match(/^# Round4 offline counters: (\{[^\n]+?\});/m);
  const fixtureRegenerationLine = (run.stdout ?? '').match(/^# Fixture regeneration: (\{[^\n]+?\});/m);
  if (configMetrics) report.metricas_corpus = configMetrics;
  if (serverMetrics) report.metricas_servidores = serverMetrics;
  if (round3Metrics) report.metricas_round3 = round3Metrics;
  if (round4Metrics) report.metricas_round4 = round4Metrics;
  if (combinedMetrics) report.metricas_combinadas = combinedMetrics;
  if (offlineLine) report.contadores_offline = JSON.parse(offlineLine[1]);
  if (round4OfflineLine) report.contadores_offline_round4 = JSON.parse(round4OfflineLine[1]);
  if (fixtureRegenerationLine) report.reproducibilidade_fixtures = JSON.parse(fixtureRegenerationLine[1]);
  const updated = publishReport(root, report, latest);
  process.stderr.write(`Medição desta execução: ${latest}; TEST_REPORT.json `
    + (updated ? 'atualizado.\n' : 'conservado (resultados invariantes iguais).\n'));
  return run.status === 0 && report.total > 0 ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exit(main());

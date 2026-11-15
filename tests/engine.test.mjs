import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { lint_config, check_version_pins, compare_config, explain_rule, parseConfig, containsSecret, sanitize, RULES, MAX_INPUT_BYTES } from '../src/engine.mjs';

const config = server => ({ mcpServers: { example: server } });
const ids = result => [...new Set(result.findings.map(finding => finding.ruleId))].sort();
const fixtureRoot = new URL('../fixtures/', import.meta.url);
const manifest = JSON.parse(await readFile(new URL('manifest.json', fixtureRoot), 'utf8'));

test('deterministic fixture matrix: ten dangerous, ten valid, complete rule coverage', async t => {
  assert.equal(manifest.cases.length, 20);
  assert.equal(manifest.cases.filter(entry => entry.category === 'dangerous').length, 10);
  assert.equal(manifest.cases.filter(entry => entry.category === 'valid').length, 10);
  let truePositives = 0, falsePositives = 0, falseNegatives = 0, trueNegatives = 0;
  const covered = new Set();
  for (const entry of manifest.cases) {
    const source = await readFile(new URL(entry.filename, fixtureRoot), 'utf8');
    const result = lint_config(source);
    const actual = new Set(ids(result));
    const expected = new Set(entry.expectedRuleIds);
    for (const rule of RULES) {
      if (actual.has(rule.id) && expected.has(rule.id)) { truePositives++; covered.add(rule.id); }
      else if (actual.has(rule.id)) falsePositives++;
      else if (expected.has(rule.id)) falseNegatives++;
      else trueNegatives++;
    }
    assert.deepEqual([...actual].sort(), [...expected].sort(), entry.id);
    assert.equal(result.ai_generated, false);
    assert.equal(result.summary.total, result.findings.length);
    assert.equal(result.summary.total, result.summary.error + result.summary.warning + result.summary.info);
  }
  const precision = truePositives / (truePositives + falsePositives);
  const recall = truePositives / (truePositives + falseNegatives);
  const ruleCoverage = covered.size / RULES.length;
  assert.equal(precision, 1);
  assert.equal(recall, 1);
  assert.equal(ruleCoverage, 1);
  assert.equal(falsePositives, 0);
  assert.equal(falseNegatives, 0);
  t.diagnostic(JSON.stringify({ dataset: 'synthetic-fixtures-only', fixtures: 20, truePositives, falsePositives, falseNegatives, trueNegatives, precision, recall, ruleCoverage, coveredRules: covered.size, totalRules: RULES.length }));
});

test('JSONC comments and trailing commas preserve strings and URL delimiters', () => {
  const source = '{/* comment */"mcpServers":{"one":{"url":"https://service.example/path//a/*literal*/?x=,]}","headers":{"Authorization":"Bearer ${env:MCP_TOKEN}"},},},}';
  const result = lint_config(source);
  assert.equal(result.valid, true);
  assert.deepEqual(ids(result), []);
});

test('raw JSON detects duplicate names including escaped equivalence', () => {
  const result = lint_config('{"mcpServers":{"one":{"command":"local"},"o\\u006ee":{"command":"local"}}}');
  assert.deepEqual(ids(result), ['MCL-002']);
});

test('byte limit includes Unicode and accepts exactly the boundary', () => {
  const base = JSON.stringify(config({ command: 'local-mcp' }));
  assert.equal(lint_config(base.padEnd(MAX_INPUT_BYTES, ' ')).valid, true);
  assert.equal(lint_config(base.padEnd(MAX_INPUT_BYTES + 1, ' ')).inputError, 'size');
  assert.equal(lint_config(`/*${'é'.repeat(MAX_INPUT_BYTES / 2)}*/${base}`).inputError, 'size');
});

test('bounded parser rejects incomplete syntax, unsafe object shapes and nonfinite numbers', () => {
  for (const input of ['{"mcpServers":', '{"mcpServers":{},"x":1e999}', '{"mcpServers":{}} trailing', '{"mcpServers":{}} /* unclosed', '{"mcpServers":{},"x":01}', '{}', null, [], { mcpServers: { one: 42 } }]) {
    assert.equal(lint_config(input).valid, false);
    assert.ok(ids(lint_config(input)).includes('MCL-001'));
  }
  assert.equal(lint_config({ mcpServers: {}, ignored: new Array(MAX_INPUT_BYTES) }).inputError, 'size');
});

test('credential formats, contextual literals and entropy are independent detectors', () => {
  const formatted = 'sk-teste-NAO-USAR-Ab7Cd8Ef9Gh0Jk1Lm2Np3Qr4';
  const opaque = 'teste_NAO-USAR_9aB4cD7eF2gH8jK3mN6pQ1rS5tU0';
  assert.equal(containsSecret(formatted), true);
  assert.equal(containsSecret(opaque), true);
  assert.equal(containsSecret('teste-NAO-USAR', 'password'), true);
  for (const placeholder of ['${env:TOKEN}', '$TOKEN', '%TOKEN%', '{{TOKEN}}', 'Bearer ${env:TOKEN}']) assert.equal(containsSecret(placeholder, 'TOKEN'), false);
  assert.equal(containsSecret('0123456789abcdef'.repeat(4), 'SHA256'), false);
  assert.equal(containsSecret('example-mcp@1.2.3-alpha.20261113'), false);
});

test('all API outputs omit literal values, hostile names, paths and unknown properties', () => {
  const secret = 'sk-teste-NAO-USAR-a1B2c3D4e5F6g7H8j9K0';
  const path = '/workspace/teste-NAO-USAR-sensitive-path';
  const input = { mcpServers: { [secret]: { command: 'local-mcp', args: ['--token', secret, path], env: { [secret]: secret }, [secret]: { [path]: secret } } } };
  const outputs = [lint_config(input), check_version_pins(input), compare_config(input, config({ command: 'local-mcp' })), explain_rule(secret), parseConfig(JSON.stringify(input)), lint_config(`{"${secret}": broken`), sanitize(input)];
  for (const output of outputs) {
    const serialized = JSON.stringify(output);
    assert.equal(serialized.includes(secret), false, 'A synthetic credential was reflected.');
    assert.equal(serialized.includes(path), false, 'An input path was reflected.');
    assert.equal(serialized.includes('process.env'), false);
  }
  assert.equal(sanitize(secret), 'sk-t[REDIGIDO]');
});

test('package launchers distinguish exact pins, floating refs, options and multiple installs', () => {
  const entries = [
    [{ command: 'npx', args: ['example-mcp@1.2.3'] }, ['MCL-013']],
    [{ command: 'npx', args: ['--package', 'example-mcp@1.2.3', 'example-command'] }, ['MCL-013']],
    [{ command: 'uvx', args: ['--from', 'example-mcp==1.2', 'example-command'] }, ['MCL-013']],
    [{ command: 'pip', args: ['install', 'first==1.2.3', 'second>=2.0'] }, ['MCL-011', 'MCL-013']],
    [{ command: 'npm', args: ['install', 'first@1.2.3', 'second@latest'] }, ['MCL-010', 'MCL-013']],
    [{ command: 'npx', args: ['@example/mcp'] }, ['MCL-012', 'MCL-013']],
    [{ command: 'docker', args: ['run', '--name', 'example', 'image:latest'] }, ['MCL-010']],
    [{ command: 'docker', args: ['run', 'image:1.2.3'] }, ['MCL-011']],
  ];
  for (const [server, expected] of entries) assert.deepEqual(ids(check_version_pins(config(server))), expected);
});

test('loopback handling includes normalized numeric and IPv4 mapped IPv6 addresses', () => {
  for (const url of ['http://127.0.0.2/mcp', 'http://[::1]/mcp', 'http://[::ffff:127.0.0.1]/mcp', 'http://localhost/mcp', 'http://0x7f000001/mcp']) assert.deepEqual(ids(lint_config(config({ url }))), []);
  assert.deepEqual(ids(lint_config(config({ url: 'http://localhost.example/mcp' }))), ['MCL-014', 'MCL-024']);
  assert.deepEqual(ids(lint_config(config({ url: 'https://[::ffff:10.0.0.1]/mcp', auth: { type: 'oauth' } }))), ['MCL-015', 'MCL-016']);
  assert.deepEqual(ids(lint_config(config({ url: 'https://fdocs.example/mcp', auth: { type: 'oauth' } }))), []);
  assert.deepEqual(ids(lint_config(config({ url: 'http://localhost./mcp' }))), []);
});

test('shell operators respect quoted literals and direct argument arrays', () => {
  assert.deepEqual(ids(lint_config(config({ command: 'local-mcp', args: ['a; b && c | d'] }))), []);
  assert.deepEqual(ids(lint_config(config({ command: 'sh', args: ['-c', "echo 'a; b && c | d'"] }))), ['MCL-009']);
  assert.deepEqual(ids(lint_config(config({ command: 'sh', args: ['-c', 'curl https://download.example/file | jq .'] }))), ['MCL-007', 'MCL-009']);
});

test('container mount syntax covers named source, shorthand and Windows drive roots', () => {
  for (const mountArgs of [['-v', '/:/host'], ['-v/etc:/config:ro'], ['--mount=type=bind,source=/,target=/host'], ['--volume', 'C:\\:/host']]) {
    const result = lint_config(config({ command: 'docker', args: ['run', ...mountArgs, `image@sha256:${'a'.repeat(64)}`] }));
    assert.ok(ids(result).includes('MCL-021'));
  }
  assert.ok(ids(lint_config(config({ command: 'local-mcp', mounts: [{ type: 'bind', source: '/', target: '/data' }] }))).includes('MCL-021'));
  assert.ok(ids(lint_config(config({ command: 'local-filesystem-mcp', args: ['--path=/'] }))).includes('MCL-017'));
});

test('comparison reports finding changes without configuration values', () => {
  const before = config({ command: 'local-mcp', autoApprove: true });
  const after = config({ command: 'local-mcp', allowedTools: ['*'] });
  const result = compare_config(before, after);
  assert.deepEqual(result.added.map(finding => finding.ruleId), ['MCL-028']);
  assert.deepEqual(result.resolved.map(finding => finding.ruleId), ['MCL-022']);
  assert.equal(result.unchanged, 0);
  assert.equal(result.valid, true);
});

test('each rule provides version, explanation, remediation and an example', () => {
  assert.ok(RULES.length >= 20);
  assert.equal(new Set(RULES.map(rule => rule.id)).size, RULES.length);
  for (const rule of RULES) {
    assert.match(rule.id, /^MCL-\d{3}$/);
    const explained = explain_rule(rule.id);
    for (const key of ['version', 'title', 'explanation', 'remediation', 'example', 'disclaimer']) assert.ok(typeof explained[key] === 'string' && explained[key].length > 0);
    assert.equal(explained.ai_generated, false);
  }
  assert.deepEqual(explain_rule('__proto__'), { ai_generated: false, error: 'Unknown rule identifier.' });
});

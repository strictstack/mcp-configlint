import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PassThrough } from 'node:stream';
import { exportSarif } from '../src/index.mjs';
import { createServer, serveStdio, PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION, MAX_FRAME_BYTES } from '../src/server.mjs';

const cli = fileURLToPath(new URL('../bin/cli.mjs', import.meta.url));
const mcp = fileURLToPath(new URL('../bin/mcp.mjs', import.meta.url));
const config = { mcpServers: { example: { command: 'npx', args: ['-y', 'example-mcp@1.2.3'] } } };
const request = (id, method, params = {}) => ({ jsonrpc: '2.0', id, method, params });
const meta = {
  'io.modelcontextprotocol/protocolVersion': PROTOCOL_VERSION,
  'io.modelcontextprotocol/clientCapabilities': {},
};
const initialize = (server) => {
  const result = server.handleRequest(request(1, 'initialize', {
    protocolVersion: LEGACY_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'test', version: '1.0.0' },
  }));
  assert.equal(result.result.protocolVersion, LEGACY_PROTOCOL_VERSION);
  assert.equal(server.handleRequest({ jsonrpc: '2.0', method: 'notifications/initialized' }), null);
};

test('MCP legacy lifecycle, all five tools, and safe errors', () => {
  const server = createServer();
  assert.equal(server.handleRequest(request(0, 'tools/list')).error.code, -32002);
  assert.deepEqual(server.handleRequest(request(0, 'ping')).result, {});
  assert.equal(server.handleRequest(request(0, 'initialize', {})).error.code, -32602);
  initialize(server);
  const tools = server.handleRequest(request('list-1', 'tools/list')).result.tools;
  assert.deepEqual(tools.map((entry) => entry.name), ['lint_config', 'check_version_pins', 'compare_config', 'explain_rule', 'export_sarif']);
  for (const name of ['lint_config', 'check_version_pins', 'export_sarif']) {
    const result = server.handleRequest(request(2, 'tools/call', { name, arguments: { config } }));
    assert.equal(result.result.isError, false, name);
    assert.equal(result.result.content[0].type, 'text');
    assert.deepEqual(JSON.parse(result.result.content[0].text), result.result.structuredContent);
  }
  const comparison = server.handleRequest(request(3, 'tools/call', { name: 'compare_config', arguments: { before: config, after: config } }));
  assert.equal(comparison.result.isError, false);
  assert.deepEqual(comparison.result.structuredContent.added, []);
  const explanation = server.handleRequest(request(4, 'tools/call', { name: 'explain_rule', arguments: { rule_id: 'MCL-001' } }));
  assert.equal(explanation.result.isError, false);
  assert.equal(explanation.result.structuredContent.ai_generated, false);
  const missingExplanation = server.handleRequest(request(4, 'tools/call', { name: 'explain_rule', arguments: { rule_id: 'unknown' } }));
  assert.equal(missingExplanation.result.isError, true);
  assert.equal(server.handleRequest(request(5, 'tools/call', { name: 'unknown', arguments: {} })).error.code, -32602);
  assert.equal(server.handleRequest(request(5, 'tools/call', { name: 'lint_config', arguments: { config, unexpected: 'ignored?' } })).error.code, -32602);
  assert.equal(server.handleRequest(request(5, 'unknown')).error.code, -32601);
  assert.equal(server.handleRequest(request(5, 'initialize')).error.code, -32600);
  const malformed = server.handleRequest(request(6, 'tools/call', { name: 'lint_config', arguments: { config: '{invalid' } }));
  assert.equal(malformed.result.isError, true);
  assert.equal(JSON.stringify(malformed).includes('{invalid'), false);
});

test('MCP initialization cannot be skipped during the legacy handshake', () => {
  const server = createServer();
  server.handleRequest(request(1, 'initialize', { protocolVersion: LEGACY_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'test', version: '1' } }));
  assert.equal(server.handleRequest(request(2, 'tools/list')).error.code, -32002);
  server.handleRequest({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.ok(server.handleRequest(request(3, 'tools/list')).result);
});

test('MCP current per-request negotiation, discovery, calls and invalid versions', () => {
  const server = createServer();
  const discovery = server.handleRequest(request(1, 'server/discover', { _meta: meta })).result;
  assert.equal(discovery.resultType, 'complete');
  assert.deepEqual(discovery.supportedVersions, [PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION]);
  assert.equal(discovery.cacheScope, 'public');
  assert.equal(discovery.ttlMs, 0);
  assert.equal(discovery._meta['io.modelcontextprotocol/serverInfo'].name, 'mcp-configlint');
  const list = server.handleRequest(request(2, 'tools/list', { _meta: meta })).result;
  assert.equal(list.resultType, 'complete');
  assert.equal(list.tools.length, 5);
  const call = server.handleRequest(request(3, 'tools/call', { _meta: meta, name: 'lint_config', arguments: { config } })).result;
  assert.equal(call.resultType, 'complete');
  assert.equal(call.isError, false);
  const unsupported = server.handleRequest(request(4, 'tools/list', { _meta: { ...meta, 'io.modelcontextprotocol/protocolVersion': '2030-01-01' } }));
  assert.equal(unsupported.error.code, -32022);
  assert.equal(unsupported.error.data.requested, '2030-01-01');
  const malformed = server.handleRequest(request(4, 'tools/list', { _meta: { 'io.modelcontextprotocol/protocolVersion': PROTOCOL_VERSION } }));
  assert.equal(malformed.error.code, -32602);
  assert.equal(server.handleRequest(request(5, 'tools/list')).error.code, -32002, 'modern capability metadata must not carry over');
});

test('MCP identifiers and protocol errors do not reflect credentials or paths', () => {
  const server = createServer();
  const secret = 'sk-SENTINEL_DO_NOT_DISCLOSE_1234567890';
  const response = server.handleRequest(request(secret, 'tools/list'));
  assert.equal(Object.hasOwn(response, 'id'), false);
  assert.equal(JSON.stringify(response).includes(secret), false);
  const version = server.handleRequest(request(1, 'tools/list', { _meta: { ...meta, 'io.modelcontextprotocol/protocolVersion': secret } }));
  assert.equal(JSON.stringify(version).includes(secret), false);
  assert.equal(Object.hasOwn(server.handleRequest(request('/private/configuration.json', 'ping')), 'id'), false);
  assert.equal(server.handleRequest(request('request-42', 'ping')).id, 'request-42');
});

test('both MCP eras omit unreadable IDs and retain valid IDs in error responses', () => {
  for (const modern of [false, true]) {
    const server = createServer();
    if (!modern) initialize(server);
    const params = modern ? { _meta: meta } : {};
    for (const invalid of [null, [], { jsonrpc: '2.0' }, request('sk-SENTINEL_private', 'ping', params)]) {
      const response = server.handleRequest(invalid);
      assert.equal(response.jsonrpc, '2.0');
      assert.equal(response.error.code, -32600);
      assert.equal(Object.hasOwn(response, 'id'), false);
    }
    const missingMethod = server.handleRequest(request('request-7', 'unknown', params));
    assert.equal(missingMethod.error.code, -32601);
    assert.equal(missingMethod.id, 'request-7');
    assert.equal(server.handleRequest({ jsonrpc: '2.0', method: 'notifications/example', params }), null);
  }
  const unsupported = createServer().handleRequest(request(8, 'tools/list', {
    _meta: { ...meta, 'io.modelcontextprotocol/protocolVersion': '2030-01-01' },
  }));
  assert.equal(unsupported.id, 8);
  assert.equal(unsupported.error.code, -32022);
});

test('stdio framing handles parse errors, size limits, notifications and recovery', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  let text = '';
  output.on('data', (chunk) => { text += chunk; });
  const done = serveStdio(input, output);
  input.write('{not json}\n');
  input.write('x'.repeat(MAX_FRAME_BYTES + 1));
  input.write('\n');
  input.write(`${JSON.stringify(request(1, 'ping'))}\n`);
  input.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
  input.end('{truncated');
  await done;
  const responses = text.trim().split('\n').map(JSON.parse);
  assert.deepEqual(responses.map((entry) => entry.error?.code ?? 'ok'), [-32700, -32600, 'ok', -32700]);
  assert.ok(responses.filter((entry) => entry.error).every((entry) => !Object.hasOwn(entry, 'id')));
  assert.equal(text.includes('not json'), false);
  assert.equal(text.includes('truncated'), false);
});

test('SARIF 2.1.0 structure and anonymous logical locations', () => {
  const secret = 'sk-SENTINEL_DO_NOT_DISCLOSE_1234567890';
  const sarif = exportSarif({ mcpServers: { [secret]: { command: 'npx', args: ['example-mcp@latest'], env: { PRIVATE_TOKEN: secret } } } });
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs.length, 1);
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, 'mcp-configlint');
  assert.equal(run.properties.ai_generated, false);
  assert.match(run.properties.disclaimer, /malicious|malicioso/i);
  assert.ok(run.results.length > 0);
  for (const result of run.results) {
    assert.equal(run.tool.driver.rules[result.ruleIndex].id, result.ruleId);
    assert.ok(['error', 'warning', 'note'].includes(result.level));
    assert.equal(typeof result.message.text, 'string');
    assert.match(result.locations[0].logicalLocations[0].name, /^(server#\d+|configuration)$/);
    assert.equal(result.properties.ai_generated, false);
  }
  const text = JSON.stringify(sarif);
  assert.equal(text.includes(secret), false);
  assert.equal(text.includes('PRIVATE_TOKEN'), false);
  assert.equal(text.includes('example-mcp'), false);
});

test('CLI explicit stdin/file, JSON/text/SARIF, limits and safe read errors', () => {
  const input = JSON.stringify(config);
  for (const format of ['json', 'text', 'sarif']) {
    const result = spawnSync(process.execPath, [cli, '--format', format], { input, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
    if (format === 'sarif') assert.equal(JSON.parse(result.stdout).version, '2.1.0');
    else if (format === 'json') assert.equal(JSON.parse(result.stdout).ai_generated, false);
    else assert.match(result.stdout, /ai_generated: false/);
  }
  const directory = mkdtempSync(join(tmpdir(), 'configlint-adapter-'));
  try {
    const file = join(directory, 'explicit.jsonc');
    writeFileSync(file, `// comment\n${input}`);
    assert.equal(spawnSync(process.execPath, [cli, file], { encoding: 'utf8' }).status, 0);
    const missing = spawnSync(process.execPath, [cli, join(directory, 'SENTINEL-private-missing.json')], { encoding: 'utf8' });
    assert.equal(missing.status, 2);
    assert.equal(missing.stderr.includes('SENTINEL'), false);
    assert.equal(missing.stderr.includes(directory), false);
  } finally { rmSync(directory, { recursive: true, force: true }); }
  const tooLarge = spawnSync(process.execPath, [cli], { input: ' '.repeat(65537), encoding: 'utf8' });
  assert.equal(tooLarge.status, 2);
  assert.match(tooLarge.stderr, /64 KiB/);
  const invalid = spawnSync(process.execPath, [cli, '--format', 'SENTINEL-private'], { input, encoding: 'utf8' });
  assert.equal(invalid.status, 2);
  assert.equal(invalid.stderr.includes('SENTINEL'), false);
});

test('installed MCP entry points process a complete legacy stdio session', () => {
  const frames = [
    request(1, 'initialize', { protocolVersion: LEGACY_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'test', version: '1' } }),
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    request(2, 'tools/list'),
    request(3, 'tools/call', { name: 'lint_config', arguments: { config } }),
  ].map((entry) => JSON.stringify(entry)).join('\n') + '\n';
  for (const args of [[mcp], [cli, '--mcp']]) {
    const result = spawnSync(process.execPath, args, { input: frames, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
    const responses = result.stdout.trim().split('\n').map(JSON.parse);
    assert.equal(responses.length, 3);
    assert.equal(responses[0].result.protocolVersion, LEGACY_PROTOCOL_VERSION);
    assert.equal(responses[1].result.tools.length, 5);
    assert.equal(responses[2].result.isError, false);
  }
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough, Readable } from 'node:stream';
import { lintConfig, checkVersionPins, compareConfig, explainRule, parseConfig, MAX_INPUT_BYTES } from '../src/engine.mjs';
import { exportSarif } from '../src/sarif.mjs';
import { createServer, serveStdio, PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION, MAX_FRAME_BYTES } from '../src/server.mjs';

const rules = (result) => result.findings.map((finding) => finding.ruleId);
const configuration = (server) => ({ mcpServers: { 'teste-NAO-USAR': server } });
const clean = configuration({ command: 'local-mcp', args: [] });
const metadata = () => ({
  'io.modelcontextprotocol/protocolVersion': PROTOCOL_VERSION,
  'io.modelcontextprotocol/clientCapabilities': {},
});
const request = (method, params = {}, id = 1) => ({ jsonrpc: '2.0', id, method, params });
const initialize = () => request('initialize', {
  protocolVersion: LEGACY_PROTOCOL_VERSION, capabilities: {},
  clientInfo: { name: 'teste-NAO-USAR', version: '0.0.0' },
});

test('JSONC deteta membros duplicados depois da descodificação Unicode', () => {
  const input = String.raw`{"mcpServers":{"teste":{"command":"node","args":[]},"\u0074este":{"command":"node","args":[]}}}`;
  const result = lintConfig(input);
  assert.ok(rules(result).includes('MCL-002'));
  assert.ok(!JSON.stringify(result).includes('"teste"'));
});

test('JSONC deteta duplicados profundamente aninhados e nomes de servidores em lista', () => {
  const input = '{"mcpServers":{"teste":{"command":"node","env":{"API_TOKEN":"teste-NAO-USAR","API_TOKEN":"${API_TOKEN}"}}}}';
  assert.ok(rules(lintConfig(input)).includes('MCL-002'));
  const result = lintConfig({ servers: [{ name: 'teste-NAO-USAR', command: 'node' }, { name: 'teste-NAO-USAR', command: 'node' }] });
  assert.ok(rules(result).includes('MCL-002'));
});

test('comentários e vírgulas finais não reescrevem delimitadores dentro de strings', () => {
  const input = '{/* teste */"mcpServers":{"teste":{"url":"https://example.invalid/teste/*literal*/?x=//literal",},},}';
  assert.equal(lintConfig(input).valid, true);
  const malformed = '{"mcpServers":{}} /* teste-NAO-USAR';
  const result = lintConfig(malformed);
  assert.equal(result.valid, false);
  assert.ok(!JSON.stringify(result).includes('NAO-USAR'));
});

test('propriedades especiais não modificam protótipos nem expõem nomes', () => {
  const result = lintConfig('{"mcpServers":{"__proto__":{"command":"node","env":{"constructor":"teste-NAO-USAR"}},"constructor":{"command":"node"}}}');
  assert.equal(result.valid, true);
  assert.equal(Object.prototype.polluted, undefined);
  assert.ok(!JSON.stringify(result).includes('__proto__'));
  assert.equal(result.serverCount, 2);
});

test('objetos com getters são recusados sem invocação', () => {
  let calls = 0;
  const server = { args: [] };
  Object.defineProperty(server, 'command', { enumerable: true, get() { calls++; return 'teste-NAO-USAR'; } });
  assert.equal(lintConfig(configuration(server)).valid, false);
  assert.equal(calls, 0);
});

test('ciclos, profundidade e limite UTF-8 falham de forma limitada', () => {
  const cyclic = {}; cyclic.mcpServers = cyclic;
  assert.equal(lintConfig(cyclic).valid, false);
  let nested = {};
  for (let index = 0; index < 70; index++) nested = { teste: nested };
  assert.equal(lintConfig(nested).valid, false);
  const wide = JSON.stringify(configuration({ command: 'node', args: ['á'.repeat(MAX_INPUT_BYTES / 2)] }));
  assert.ok(wide.length < MAX_INPUT_BYTES);
  assert.equal(lintConfig(wide).valid, false);
});

test('nenhuma saída API, comparação, parser ou SARIF devolve segredos ou namespaces recebidos', () => {
  const marker = 'teste-NAO-USAR-CANARIO-PRIVADO';
  const input = { mcpServers: { [marker]: {
    command: '/teste/' + marker, args: ['--token', marker],
    env: { API_TOKEN: marker }, headers: { Authorization: 'Bearer ' + marker },
    url: 'https://example.invalid/' + marker + '?token=' + marker,
  } } };
  for (const result of [lintConfig(input), checkVersionPins(input), compareConfig(clean, input), parseConfig(input), exportSarif(input)]) {
    assert.ok(!JSON.stringify(result).includes(marker));
  }
  assert.ok(!JSON.stringify(explainRule(marker)).includes(marker));
  assert.ok(!JSON.stringify(explainRule('__proto__')).includes('__proto__'));
});

test('instalação de vários pacotes inspeciona referências posteriores', () => {
  const npm = checkVersionPins(configuration({ command: 'npm', args: ['install', 'teste-safe@1.2.3', 'teste-unsafe@latest'] }));
  assert.ok(rules(npm).includes('MCL-010'));
  const pip = checkVersionPins(configuration({ command: 'pip', args: ['install', 'teste-safe==1.2.3', 'teste-unsafe>=1.0.0'] }));
  assert.ok(rules(pip).includes('MCL-011'));
});

test('escapes equivalentes não ocultam segredos nem alteram a classificação', () => {
  const input = String.raw`{"mcpServers":{"teste":{"command":"node","env":{"API_\u0054OKEN":"teste-NAO-USAR"}}}}`;
  assert.ok(rules(lintConfig(input)).includes('MCL-003'));
});

test('protocolo legado exige a notificação de conclusão e recusa reinicialização', () => {
  const server = createServer();
  assert.ok(server.handleRequest(request('tools/list')).error);
  assert.ok(server.handleRequest(initialize()).result);
  assert.ok(server.handleRequest(request('tools/list')).error);
  assert.equal(server.handleRequest({ jsonrpc: '2.0', method: 'notifications/initialized' }), null);
  assert.ok(server.handleRequest(request('tools/list')).result);
  assert.ok(server.handleRequest(initialize()).error);
});

test('sessões novas não herdam estado de inicialização', () => {
  const initialized = createServer();
  initialized.handleRequest(initialize());
  initialized.handleRequest({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.ok(initialized.handleRequest(request('tools/list')).result);
  assert.ok(createServer().handleRequest(request('tools/list')).error);
});

test('protocolo atual é independente da sessão e valida capabilities', () => {
  const server = createServer();
  const good = server.handleRequest(request('tools/list', { _meta: metadata() }));
  assert.equal(good.result.resultType, 'complete');
  const bad = server.handleRequest(request('tools/list', { _meta: { 'io.modelcontextprotocol/protocolVersion': PROTOCOL_VERSION } }));
  assert.ok(bad.error);
});

test('versões inválidas e identificadores secretos nunca são refletidos', () => {
  const marker = 'teste-NAO-USAR-secret-canario';
  const server = createServer();
  const version = server.handleRequest(request('tools/list', { _meta: { ...metadata(), 'io.modelcontextprotocol/protocolVersion': marker } }));
  const identity = server.handleRequest(request('tools/list', { _meta: metadata() }, marker));
  assert.ok(version.error);
  assert.ok(identity.error);
  assert.ok(!Object.hasOwn(identity, 'id'));
  assert.ok(!JSON.stringify([version, identity]).includes(marker));
});

test('notificações não produzem respostas nem executam ferramentas', () => {
  const server = createServer();
  assert.equal(server.handleRequest({ jsonrpc: '2.0', method: 'tools/call', params: {
    _meta: metadata(), name: 'lint_config', arguments: { config: clean },
  } }), null);
});

test('argumentos inesperados e nomes de ferramentas não atravessam namespaces', () => {
  const server = createServer();
  for (const params of [
    { name: '__proto__', arguments: {} },
    { name: 'lint_config', arguments: { config: clean, path: '/teste/NAO-USAR' } },
    { name: 'lint_config', arguments: { config: clean, tenant: 'teste-NAO-USAR' } },
  ]) {
    assert.ok(server.handleRequest(request('tools/call', { ...params, _meta: metadata() })).error);
  }
});

test('framing rejeita excesso, recupera na linha seguinte e não ecoa o corpo', async () => {
  const output = new PassThrough();
  let text = '';
  output.on('data', (chunk) => { text += chunk.toString(); });
  const next = JSON.stringify(request('tools/list', { _meta: metadata() }, 2));
  const first = 'teste-NAO-USAR-' + 'x'.repeat(MAX_FRAME_BYTES);
  await serveStdio(Readable.from([first + '\n' + next + '\n']), output);
  const messages = text.trim().split('\n').map(JSON.parse);
  assert.equal(messages.length, 2);
  assert.ok(messages[0].error);
  assert.ok(!Object.hasOwn(messages[0], 'id'));
  assert.equal(messages[1].id, 2);
  assert.ok(messages[1].result);
  assert.ok(!text.includes('teste-NAO-USAR'));
});

test('framing UTF-8 repartido entre chunks preserva pedido válido', async () => {
  const output = new PassThrough();
  let text = '';
  output.on('data', (chunk) => { text += chunk.toString(); });
  const payload = Buffer.from(JSON.stringify(request('tools/call', {
    _meta: metadata(), name: 'lint_config', arguments: { config: configuration({ command: 'node', args: ['teste-á-NAO-USAR'] }) },
  })) + '\n');
  const split = payload.indexOf(Buffer.from('á')) + 1;
  await serveStdio(Readable.from([payload.subarray(0, split), payload.subarray(split)]), output);
  const response = JSON.parse(text);
  assert.ok(response.result);
  assert.equal(response.result.isError, false);
});

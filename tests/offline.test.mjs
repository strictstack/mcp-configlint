import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { PassThrough } from 'node:stream';

test('deny-all precedes I/O; network/process traps and outgoing MCP requests stay at zero', async (t) => {
  const counts = { connections: 0, processes: 0, outboundInitialize: 0, outboundToolsCall: 0 };
  const restored = [];
  const trap = (object, key, category) => {
    const original = object[key];
    if (typeof original !== 'function') return;
    object[key] = function () { counts[category] += 1; throw new Error('Offline trap: unexpected operation.'); };
    restored.push(() => { object[key] = original; });
  };
  for (const api of [http, https]) for (const method of ['request', 'get']) trap(api, method, 'connections');
  for (const method of ['connect', 'createConnection']) trap(net, method, 'connections');
  trap(net.Socket.prototype, 'connect', 'connections');
  trap(tls, 'connect', 'connections');
  for (const method of ['lookup', 'lookupService', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveCname', 'resolveMx', 'resolveNs', 'resolvePtr', 'resolveSoa', 'resolveSrv', 'resolveTxt', 'reverse']) {
    trap(dns, method, 'connections');
    trap(dns.promises, method, 'connections');
    trap(dns.Resolver.prototype, method, 'connections');
    trap(dns.promises.Resolver.prototype, method, 'connections');
  }
  for (const method of ['exec', 'execFile', 'execSync', 'execFileSync', 'spawn', 'spawnSync', 'fork']) trap(childProcess, method, 'processes');
  for (const key of ['fetch', 'WebSocket']) {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, key);
    Object.defineProperty(globalThis, key, { configurable: true, writable: true, value: function () { counts.connections += 1; throw new Error('Offline trap: unexpected global I/O.'); } });
    restored.push(() => descriptor ? Object.defineProperty(globalThis, key, descriptor) : delete globalThis[key]);
  }
  syncBuiltinESMExports();
  try {
    // Import after installing traps so captured imports cannot bypass instrumentation.
    const api = await import('../src/index.mjs');
    const { serveStdio, LEGACY_PROTOCOL_VERSION } = await import('../src/server.mjs');
    assert.deepEqual(api.NETWORK_POLICY, { allow: [], policy: null });
    for (const host of ['api.openai.com', 'api.anthropic.com', 'generativelanguage.googleapis.com']) {
      for (const method of ['initialize', 'tools/call']) {
        const guardedOutbound = () => {
          api.guardEgress(`https://${host}`, method);
          // These counters represent outgoing MCP requests, not server responses.
          if (method === 'initialize') counts.outboundInitialize += 1;
          else counts.outboundToolsCall += 1;
          fetch(`https://${host}`, { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method }) });
        };
        assert.throws(guardedOutbound, { code: 'ERR_OFFLINE_POLICY' });
      }
    }
    const config = { mcpServers: { fixture: { command: 'npx', args: ['example-mcp@1.2.3'] } } };
    assert.equal(api.lintConfig(config).valid, true);
    assert.equal(api.exportSarif(config).version, '2.1.0');
    const input = new PassThrough();
    const output = new PassThrough();
    const responses = [];
    output.on('data', (chunk) => responses.push(...chunk.toString().trim().split('\n').filter(Boolean).map(JSON.parse)));
    const done = serveStdio(input, output);
    const requests = [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: LEGACY_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'offline-test', version: '1' } } },
      { jsonrpc: '2.0', method: 'notifications/initialized' },
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
      ...['lint_config', 'check_version_pins', 'export_sarif'].map((name, i) => ({ jsonrpc: '2.0', id: i + 3, method: 'tools/call', params: { name, arguments: { config } } })),
      { jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'compare_config', arguments: { before: config, after: config } } },
      { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'explain_rule', arguments: { rule_id: 'MCL-001' } } },
    ];
    input.end(requests.map((request) => JSON.stringify(request)).join('\n') + '\n');
    await done;
    assert.equal(responses.length, 7);
    assert.ok(responses.every((response) => !response.error && !response.result.isError));
    assert.equal(responses.filter((response) => Object.hasOwn(response, 'method')).length, 0, 'server must never initiate peer calls');
    assert.deepEqual(counts, { connections: 0, processes: 0, outboundInitialize: 0, outboundToolsCall: 0 });
    t.diagnostic(`Offline counters: ${JSON.stringify(counts)}; local server responses: ${responses.length}`);
  } finally {
    for (const restore of restored.reverse()) restore();
    syncBuiltinESMExports();
  }
});

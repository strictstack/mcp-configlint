import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createContext, SourceTextModule } from 'node:vm';

test('browser ESM loads and executes without Node globals or Node imports', async () => {
  let outboundAttempts = 0;
  const deny = () => { outboundAttempts += 1; throw new Error('Unexpected outbound operation.'); };
  const context = createContext({ TextEncoder, TextDecoder, URL, fetch: deny, WebSocket: deny });
  const modules = new Map();
  const load = (url) => {
    if (modules.has(url.href)) return modules.get(url.href);
    const pending = readFile(url, 'utf8').then((source) => new SourceTextModule(source, { context, identifier: url.href }));
    modules.set(url.href, pending);
    return pending;
  };
  const entry = await load(new URL('../src/index.mjs', import.meta.url));
  await entry.link(async (specifier, parent) => {
    assert.equal(specifier.startsWith('.'), true, 'browser engine must import only local ESM');
    return load(new URL(specifier, parent.identifier));
  });
  await entry.evaluate();
  const config = JSON.stringify({ mcpServers: { sample: { command: 'npx', args: ['example-mcp@1.2.3'] } } });
  const result = entry.namespace.lintConfig(config);
  assert.equal(result.valid, true);
  assert.equal(result.ai_generated, false);
  assert.equal(entry.namespace.checkVersionPins(config).valid, true);
  assert.equal(entry.namespace.compareConfig(config, config).added.length, 0);
  assert.equal(entry.namespace.exportSarif(config).version, '2.1.0');
  assert.throws(() => entry.namespace.guardEgress('https://offline.invalid'), { code: 'ERR_OFFLINE_POLICY' });
  assert.equal(outboundAttempts, 0);
  assert.ok(modules.size >= 3, 'the transitive module graph was loaded');
});

import { lintConfig, checkVersionPins, compareConfig, explainRule, containsSecret } from './engine.mjs';
import { exportSarif } from './sarif.mjs';

export const PROTOCOL_VERSION = '2026-07-28';
export const LEGACY_PROTOCOL_VERSION = '2025-11-25';
export const SUPPORTED_PROTOCOL_VERSIONS = Object.freeze([PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION]);
export const MAX_FRAME_BYTES = 1024 * 1024;
const VERSION_KEY = 'io.modelcontextprotocol/protocolVersion';
const CAPABILITIES_KEY = 'io.modelcontextprotocol/clientCapabilities';
const INFO_KEY = 'io.modelcontextprotocol/serverInfo';
const SERVER_INFO = Object.freeze({ name: 'mcp-configlint', version: '0.1.0' });
const DISCLAIMER = 'Static configuration linting cannot prove absence of malicious behavior and is not a penetration test or security certification.';
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const configurationSchema = {
  description: 'An explicitly supplied configuration object or JSONC string, at most 64 KiB. No files are discovered or opened by tools.',
  oneOf: [{ type: 'string' }, { type: 'object' }],
};
const tool = (name, description, properties) => ({
  name,
  description,
  inputSchema: { type: 'object', properties, required: Object.keys(properties), additionalProperties: false },
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
});
export const TOOLS = Object.freeze([
  tool('lint_config', 'Statically lint an explicitly supplied MCP configuration offline. Linting is not a security certification.', { config: configurationSchema }),
  tool('check_version_pins', 'Check exact version references without resolving or installing packages.', { config: configurationSchema }),
  tool('compare_config', 'Compare anonymous static findings from two explicitly supplied configurations.', { before: configurationSchema, after: configurationSchema }),
  tool('explain_rule', 'Explain a built-in rule using static metadata.', { rule_id: { type: 'string' } }),
  tool('export_sarif', 'Lint an explicitly supplied configuration and return redacted SARIF 2.1.0.', { config: configurationSchema }),
]);

const errorResponse = (id, code, message, data) => ({
  // MCP's error envelope permits an omitted ID, but not JSON-RPC's null ID.
  jsonrpc: '2.0', ...(id === null ? {} : { id }),
  error: { code, message, ...(data === undefined ? {} : { data }) },
});

// Protocol identifiers are metadata, not a channel for configuration or credentials.
function safeId(value) {
  if (typeof value === 'number') return Number.isSafeInteger(value);
  if (typeof value !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(value)) return false;
  return !containsSecret(value) && !/(?:secret|token|password|credential|sentinel)/i.test(value);
}

function validArguments(name, args) {
  if (!isObject(args)) return false;
  const definition = TOOLS.find((entry) => entry.name === name);
  const expected = definition.inputSchema.required;
  if (Object.keys(args).length !== expected.length || !expected.every((key) => Object.hasOwn(args, key))) return false;
  if (name === 'explain_rule') return typeof args.rule_id === 'string';
  return expected.every((key) => typeof args[key] === 'string' || isObject(args[key]));
}

export function createServer() {
  let legacyState = 'new';

  function handleRequest(request) {
    if (!isObject(request) || request.jsonrpc !== '2.0' || typeof request.method !== 'string') {
      return errorResponse(null, -32600, 'Invalid request.');
    }
    const notification = !Object.hasOwn(request, 'id');
    if (!notification && !safeId(request.id)) return errorResponse(null, -32600, 'Invalid request identifier.');
    const id = notification ? null : request.id;
    if (notification) {
      if (request.method === 'notifications/initialized' && legacyState === 'initializing') legacyState = 'ready';
      return null;
    }
    if (request.params !== undefined && !isObject(request.params)) return errorResponse(id, -32602, 'Invalid parameters.');
    const params = request.params ?? {};
    const meta = params._meta;
    const modern = isObject(meta) && Object.hasOwn(meta, VERSION_KEY);
    if (modern) {
      if (meta[VERSION_KEY] !== PROTOCOL_VERSION) {
        const requested = typeof meta[VERSION_KEY] === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(meta[VERSION_KEY])
          ? meta[VERSION_KEY] : '[REDIGIDO]';
        return errorResponse(id, -32022, 'Unsupported protocol version.', { requested, supported: [...SUPPORTED_PROTOCOL_VERSIONS] });
      }
      if (!isObject(meta[CAPABILITIES_KEY])) return errorResponse(id, -32602, 'Invalid protocol metadata.');
    }
    const success = (result) => ({ jsonrpc: '2.0', id, result: modern
      ? { ...result, resultType: 'complete', _meta: { [INFO_KEY]: SERVER_INFO } }
      : result });

    if (request.method === 'initialize' && !modern) {
      if (legacyState !== 'new') return errorResponse(id, -32600, 'Initialization has already started.');
      if (typeof params.protocolVersion !== 'string' || !isObject(params.capabilities) || !isObject(params.clientInfo)
        || typeof params.clientInfo.name !== 'string' || typeof params.clientInfo.version !== 'string') {
        return errorResponse(id, -32602, 'Invalid initialization parameters.');
      }
      legacyState = 'initializing';
      return success({ protocolVersion: LEGACY_PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: SERVER_INFO, instructions: DISCLAIMER });
    }
    if (request.method === 'ping') return success({});
    if (!modern && legacyState !== 'ready') return errorResponse(id, -32002, 'Initialization is required.');
    if (request.method === 'server/discover' && modern) {
      return success({ supportedVersions: [...SUPPORTED_PROTOCOL_VERSIONS], capabilities: { tools: {} }, ttlMs: 0, cacheScope: 'public', instructions: DISCLAIMER });
    }
    if (request.method === 'tools/list') return success({ tools: TOOLS, ...(modern ? { ttlMs: 0, cacheScope: 'public' } : {}) });
    if (request.method !== 'tools/call') return errorResponse(id, -32601, 'Method not found.');
    if (typeof params.name !== 'string' || !TOOLS.some((entry) => entry.name === params.name)) return errorResponse(id, -32602, 'Unknown tool.');
    if (!validArguments(params.name, params.arguments)) return errorResponse(id, -32602, 'Invalid tool arguments.');
    try {
      const args = params.arguments;
      const operations = {
        lint_config: () => lintConfig(args.config),
        check_version_pins: () => checkVersionPins(args.config),
        compare_config: () => compareConfig(args.before, args.after),
        explain_rule: () => explainRule(args.rule_id),
        export_sarif: () => exportSarif(args.config),
      };
      const result = operations[params.name]();
      const isError = Boolean(result.error) || result.valid === false;
      return success({ content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result, isError });
    } catch {
      return success({ content: [{ type: 'text', text: 'Tool execution failed safely.' }], isError: true });
    }
  }
  return Object.freeze({ handleRequest });
}

/** Injected streams allow the identical stdio transport to run under offline traps. */
export function serveStdio(input, output, server = createServer()) {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  let pending = '';
  let pendingBytes = 0;
  let dropping = false;
  const send = (response) => { if (response !== null) output.write(`${JSON.stringify(response)}\n`); };
  const consume = (text) => {
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i += 1) {
      const segment = lines[i];
      const complete = i < lines.length - 1;
      if (!dropping) {
        pendingBytes += encoder.encode(segment).byteLength;
        if (pendingBytes > MAX_FRAME_BYTES) {
          pending = '';
          dropping = true;
          send(errorResponse(null, -32600, 'Request exceeds the transport limit.'));
        } else pending += segment;
      }
      if (complete) {
        if (!dropping && pending.trim() !== '') {
          try { send(server.handleRequest(JSON.parse(pending))); }
          catch { send(errorResponse(null, -32700, 'Invalid JSON request.')); }
        }
        pending = '';
        pendingBytes = 0;
        dropping = false;
      }
    }
  };
  return new Promise((resolve, reject) => {
    input.on('data', (chunk) => consume(typeof chunk === 'string' ? chunk : decoder.decode(chunk, { stream: true })));
    input.once('end', () => {
      consume(decoder.decode());
      if (!dropping && pending.trim() !== '') send(errorResponse(null, -32700, 'Incomplete JSON request.'));
      resolve();
    });
    input.once('error', () => reject(new Error('Input stream failed.')));
    output.once('error', () => reject(new Error('Output stream failed.')));
  });
}

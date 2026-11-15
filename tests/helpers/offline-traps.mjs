import http from 'node:http';
import https from 'node:https';
import http2 from 'node:http2';
import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import dns from 'node:dns';
import fs from 'node:fs';
import childProcess from 'node:child_process';
import cluster from 'node:cluster';
import workerThreads from 'node:worker_threads';
import { syncBuiltinESMExports } from 'node:module';

// Inspect data descriptors only: observing a payload must never run its getters.
// Records contain API labels and MCP method names, never supplied private data.
export function mcpMethods(value, seen = new Set(), depth = 0) {
  if (depth > 12 || value == null) return [];
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) value = Buffer.from(value).toString('utf8');
  if (typeof value === 'string') {
    return value.split('\n').filter(Boolean).flatMap(line => {
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

const mutators = [
  'writeFile', 'appendFile', 'createWriteStream', 'write', 'writev',
  'copyFile', 'cp', 'rename', 'unlink', 'rm', 'rmdir', 'mkdir', 'mkdtemp',
  'mkdtempDisposable', 'link', 'symlink', 'truncate', 'ftruncate',
  'chmod', 'fchmod', 'lchmod', 'chown', 'fchown', 'lchown',
  'utimes', 'futimes', 'lutimes', 'fsync', 'fdatasync',
];

function opensForWriting(flags) {
  if (typeof flags === 'number') {
    const bits = fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT
      | fs.constants.O_TRUNC | fs.constants.O_APPEND;
    return Boolean(flags & bits);
  }
  return typeof flags === 'string' && /[wa+]/.test(flags);
}

export async function installOfflineTraps() {
  // Discover FileHandle's otherwise unexported prototype through a read-only
  // handle to this test helper. Calibration below never reaches real I/O.
  const handle = await fs.promises.open(new URL(import.meta.url), 'r');
  const fileHandlePrototype = Object.getPrototypeOf(handle);
  await handle.close();

  const attempts = [];
  const installed = [];
  const restorers = [];
  let phase = 'calibration';
  const trap = (object, key, category, prefix, allows = () => false, argsFor = body => ['round4-never-created', { body }]) => {
    if (typeof object[key] !== 'function') return;
    const original = object[key];
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    const label = `${prefix}.${key}`;
    Object.defineProperty(object, key, {
      configurable: true, writable: true, value: function (...args) {
        if (allows(args)) return Reflect.apply(original, this, args);
        // Record first: production catching this exception cannot erase an
        // attempted connection, process creation, DNS query, or write.
        attempts.push({ phase, category, label, methods: mcpMethods(args) });
        throw Object.assign(new Error(`Round4 offline trap blocked ${label}`), { code: 'ERR_ROUND4_OFFLINE_TRAP' });
      },
    });
    installed.push({ object, key, category, label, argsFor });
    restorers.push(() => descriptor
      ? Object.defineProperty(object, key, descriptor) : delete object[key]);
  };
  const restore = () => {
    for (const undo of restorers.reverse()) undo();
    syncBuiltinESMExports();
  };
  try {
    for (const [api, prefix] of [[http, 'http'], [https, 'https']]) {
      for (const method of ['request', 'get']) trap(api, method, 'connections', prefix);
      trap(api.Agent.prototype, 'createConnection', 'connections', `${prefix}.Agent`);
    }
    trap(http2, 'connect', 'connections', 'http2');
    for (const method of ['connect', 'createConnection']) trap(net, method, 'connections', 'net');
    trap(net.Socket.prototype, 'connect', 'connections', 'net.Socket');
    trap(net.Server.prototype, 'listen', 'connections', 'net.Server');
    trap(tls, 'connect', 'connections', 'tls');
    trap(dgram, 'createSocket', 'connections', 'dgram');
    for (const method of ['connect', 'send', 'bind']) trap(dgram.Socket.prototype, method, 'connections', 'dgram.Socket');
    for (const [resolver, prefix] of [
      [dns, 'dns'], [dns.promises, 'dns.promises'],
      [dns.Resolver.prototype, 'dns.Resolver'], [dns.promises.Resolver.prototype, 'dns.promises.Resolver'],
    ]) {
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
    trap(cluster, 'fork', 'processes', 'cluster');
    trap(workerThreads, 'Worker', 'processes', 'worker_threads');
    for (const method of ['fetch', 'WebSocket', 'EventSource', 'WebTransport']) {
      trap(globalThis, method, 'connections', 'globalThis');
    }
    for (const method of mutators) {
      for (const key of [method, `${method}Sync`]) {
        // The test runner's stdout/stderr are not persistent file writes.
        const allows = /^(?:write|writev)(?:Sync)?$/.test(key)
          ? args => args[0] === 1 || args[0] === 2 : () => false;
        trap(fs, key, 'filesystemWrites', 'fs', allows);
      }
      trap(fs.promises, method, 'filesystemWrites', 'fs.promises');
    }
    for (const method of ['writeFile', 'appendFile', 'write', 'writev', 'createWriteStream',
      'truncate', 'chmod', 'chown', 'utimes', 'sync', 'datasync']) {
      trap(fileHandlePrototype, method, 'filesystemWrites', 'FileHandle');
    }
    trap(fs, 'WriteStream', 'filesystemWrites', 'fs');
    for (const [api, prefix, key] of [[fs, 'fs', 'open'], [fs, 'fs', 'openSync'], [fs.promises, 'fs.promises', 'open']]) {
      trap(api, key, 'filesystemWrites', prefix,
        args => !opensForWriting(args[1]), body => ['round4-never-created', 'w', { body }]);
    }
    syncBuiltinESMExports();
    return {
      attempts, installed,
      beginExercise() { phase = 'application'; },
      restore,
    };
  } catch (error) {
    restore();
    throw error;
  }
}

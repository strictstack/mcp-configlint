#!/usr/bin/env node
import { createReadStream } from 'node:fs';
import { lintConfig, exportSarif } from '../src/index.mjs';

const MAX_BYTES = 64 * 1024;
function usage() {
  return 'Usage: mcp-configlint [--format json|text|sarif] [FILE|-]\n       mcp-configlint --mcp\nReads only an explicitly named file or standard input.\n';
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--mcp') {
    const { serveStdio } = await import('../src/server.mjs');
    await serveStdio(process.stdin, process.stdout);
    return;
  }
  let format = 'json';
  let path;
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === '--help' || args[i] === '-h') { process.stdout.write(usage()); return; }
    if (args[i] === '--format' && i + 1 < args.length) {
      format = args[++i];
    } else if (args[i].startsWith('-') && args[i] !== '-') {
      process.stderr.write('Invalid command-line arguments.\n');
      process.exitCode = 2;
      return;
    } else if (path === undefined) path = args[i];
    else { process.stderr.write('Specify at most one input.\n'); process.exitCode = 2; return; }
  }
  if (!['json', 'text', 'sarif'].includes(format)) {
    process.stderr.write('Unsupported output format.\n');
    process.exitCode = 2;
    return;
  }
  const stream = path === undefined || path === '-' ? process.stdin : createReadStream(path);
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.byteLength;
    if (size > MAX_BYTES) {
      process.stderr.write('Configuration exceeds the 64 KiB limit.\n');
      process.exitCode = 2;
      return;
    }
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  const result = lintConfig(text);
  if (format === 'text') {
    process.stdout.write(`${result.disclaimer}\n`);
    for (const finding of result.findings) {
      process.stdout.write(`${finding.severity.toUpperCase()} ${finding.ruleId} ${finding.location.server}: ${finding.message}\n`);
    }
    process.stdout.write(`${result.summary.total} findings; ai_generated: false\n`);
  } else {
    process.stdout.write(`${JSON.stringify(format === 'sarif' ? exportSarif(text) : result, null, 2)}\n`);
  }
  process.exitCode = result.valid === false ? 2 : result.summary.error > 0 ? 1 : 0;
}

main().catch(() => { process.stderr.write('Unable to read or process the supplied input.\n'); process.exitCode = 2; });

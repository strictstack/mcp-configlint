#!/usr/bin/env node
import { serveStdio } from '../src/server.mjs';

serveStdio(process.stdin, process.stdout).catch(() => {
  process.stderr.write('MCP transport failed safely.\n');
  process.exitCode = 1;
});

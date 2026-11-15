import { RULES, RULE_BY_ID, RULESET_VERSION, DISCLAIMER } from './rules.mjs';

export { RULES, RULESET_VERSION, DISCLAIMER };
export const MAX_INPUT_BYTES = 64 * 1024;
const MAX_DEPTH = 64;
const encoder = new TextEncoder();
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const objectLike = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const strings = value => Array.isArray(value) ? value.filter(item => typeof item === 'string') : [];
const credentialKey = /(?:token|secret|password|passwd|(?:^|[_-])pwd(?:$|[_-])|api[_-]?key|authorization|credential|private[_-]?key|bearer)/i;
const publicKey = /(?:checksum|sha\d*|integrity|digest|fingerprint|public[_-]?key|(?:^|[_-])hash)$/i;
const truthy = value => value === true || value === 1 || value === 'true';

/** Never echo arbitrary caller-owned keys or arbitrary object structure. */
export function sanitize(value) {
  if (typeof value === 'string') return `${Array.from(value).slice(0, 4).join('')}[REDIGIDO]`;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean' || value === null) return value;
  return '[REDIGIDO]';
}

function placeholder(value) {
  const stripped = value.trim().replace(/^(?:Bearer|Basic|Token)\s+/i, '');
  return /^(?:\$\{[^{}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|\{\{[^{}]+\}\}|<[A-Z_][A-Z0-9_ -]*>)$/.test(stripped);
}

function entropy(value) {
  const counts = new Map();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let result = 0;
  for (const count of counts.values()) { const p = count / value.length; result -= p * Math.log2(p); }
  return result;
}

/** Heuristic only: literal credential context, recognizable formats, then entropy. */
export function containsSecret(value, key = '') {
  if (typeof value !== 'string' || !value.trim() || placeholder(value)) return false;
  const text = value.trim();
  if (/(?:sk-(?:proj-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{16,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{30,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/.test(text)) return true;
  if (publicKey.test(key)) return false;
  if (credentialKey.test(key)) return !/^(?:none|null|false|disabled)$/i.test(text);
  const candidate = text.replace(/^(?:Bearer|Basic|Token)\s+/i, '');
  if (/^[a-f0-9]{32,128}$/i.test(candidate)) return false; // Ambiguous hashes need credential-key context.
  if (/(?:^|@)sha(?:256|384|512):[a-f0-9]{64,128}$/i.test(candidate)) return false;
  if (/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+@v?\d+\.\d+\.\d+(?:[-+][a-z0-9.+-]+)?$/i.test(candidate)) return false;
  return candidate.length >= 24 && candidate.length <= 4096 && !/\s/.test(candidate)
    && !/^(?:https?|wss?|file):\/\//i.test(candidate) && !/^[./~]|^[A-Za-z]:[\\/]/.test(candidate)
    && /[a-z]/i.test(candidate) && /[0-9]/.test(candidate) && entropy(candidate) >= 4.2;
}
export const isSecret = containsSecret;

class InputError extends Error {
  constructor(code = 'syntax', offset = 0) { super('Configuration input was rejected.'); this.code = code; this.offset = offset; }
}

/** A bounded JSONC parser: comments and trailing commas, without textual rewriting. */
function readJsonc(source) {
  let offset = source.charCodeAt(0) === 0xfeff ? 1 : 0;
  let duplicates = 0;
  function skip() {
    while (offset < source.length) {
      if (/[ \t\r\n]/.test(source[offset])) { offset++; continue; }
      if (source[offset] === '/' && source[offset + 1] === '/') {
        offset += 2; while (offset < source.length && !/[\r\n]/.test(source[offset])) offset++; continue;
      }
      if (source[offset] === '/' && source[offset + 1] === '*') {
        const end = source.indexOf('*/', offset + 2);
        if (end === -1) throw new InputError('syntax', offset);
        offset = end + 2; continue;
      }
      break;
    }
  }
  function readString() {
    const start = offset++;
    while (offset < source.length) {
      const char = source[offset++];
      if (char === '"') {
        try { return JSON.parse(source.slice(start, offset)); } catch { throw new InputError('syntax', start); }
      }
      if (char === '\\') { offset++; continue; }
      if (char.charCodeAt(0) < 32) throw new InputError('syntax', offset - 1);
    }
    throw new InputError('syntax', start);
  }
  function readValue(depth) {
    if (depth > MAX_DEPTH) throw new InputError('depth', offset);
    skip();
    const char = source[offset];
    if (char === '"') return readString();
    if (char === '{' || char === '[') {
      const array = char === '[';
      const result = array ? [] : Object.create(null);
      const end = array ? ']' : '}';
      offset++; skip();
      if (source[offset] === end) { offset++; return result; }
      while (offset < source.length) {
        let key;
        if (!array) {
          if (source[offset] !== '"') throw new InputError('syntax', offset);
          key = readString(); skip();
          if (source[offset++] !== ':') throw new InputError('syntax', offset - 1);
        }
        const value = readValue(depth + 1);
        if (array) result.push(value);
        else { if (own(result, key)) duplicates++; result[key] = value; }
        skip();
        if (source[offset] === end) { offset++; return result; }
        if (source[offset++] !== ',') throw new InputError('syntax', offset - 1);
        skip();
        if (source[offset] === end) { offset++; return result; }
      }
      throw new InputError('syntax', offset);
    }
    for (const [literal, value] of [['true', true], ['false', false], ['null', null]]) {
      if (source.startsWith(literal, offset)) { offset += literal.length; return value; }
    }
    const number = source.slice(offset).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (number) {
      offset += number[0].length;
      const result = Number(number[0]);
      if (!Number.isFinite(result)) throw new InputError('number', offset);
      return result;
    }
    throw new InputError('syntax', offset);
  }
  const value = readValue(0); skip();
  if (offset !== source.length) throw new InputError('syntax', offset);
  return { value, duplicates };
}

function cloneData(input) {
  const seen = new Set();
  let budget = 0;
  function clone(value, depth) {
    if (depth > MAX_DEPTH) throw new InputError('depth');
    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'string') {
      budget += encoder.encode(value).byteLength;
      if (budget > MAX_INPUT_BYTES) throw new InputError('size');
      return value;
    }
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value !== 'object' || seen.has(value)) throw new InputError('shape');
    const prototype = Object.getPrototypeOf(value);
    if (!Array.isArray(value) && prototype !== Object.prototype && prototype !== null) throw new InputError('shape');
    if (Array.isArray(value) && value.length > MAX_INPUT_BYTES / 2) throw new InputError('size');
    seen.add(value);
    const result = Array.isArray(value) ? [] : Object.create(null);
    for (const key of Object.keys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !own(descriptor, 'value')) throw new InputError('shape');
      budget += encoder.encode(key).byteLength + 4;
      if (budget > MAX_INPUT_BYTES) throw new InputError('size');
      result[key] = clone(descriptor.value, depth + 1);
    }
    seen.delete(value);
    return result;
  }
  const value = clone(input, 0);
  const byteLength = encoder.encode(JSON.stringify(value)).byteLength;
  if (byteLength > MAX_INPUT_BYTES) throw new InputError('size');
  return { value, duplicates: 0, byteLength };
}

function parseInput(input) {
  if (typeof input !== 'string') return cloneData(input);
  if (input.length > MAX_INPUT_BYTES) throw new InputError('size');
  const byteLength = encoder.encode(input).byteLength;
  if (byteLength > MAX_INPUT_BYTES) throw new InputError('size');
  return { ...readJsonc(input), byteLength };
}

function createResult() {
  return {
    schemaVersion: '1.0.0', rulesetVersion: RULESET_VERSION, ai_generated: false,
    disclaimer: DISCLAIMER, valid: true, findings: [],
    summary: { error: 0, warning: 0, info: 0, total: 0 },
  };
}
function addFinding(result, id, server = 'configuration', field = 'configuration') {
  if (result.findings.some(finding => finding.ruleId === id && finding.location.server === server && finding.location.field === field)) return;
  const rule = RULE_BY_ID[id];
  result.findings.push({ ruleId: id, severity: rule.severity, message: rule.title,
    location: { server, field }, evidence: rule.explanation, remediation: rule.remediation });
}
function finish(result) {
  result.findings.sort((a, b) => a.location.server.localeCompare(b.location.server, 'en') || a.ruleId.localeCompare(b.ruleId, 'en') || a.location.field.localeCompare(b.location.field, 'en'));
  result.summary = { error: 0, warning: 0, info: 0, total: result.findings.length };
  for (const finding of result.findings) result.summary[finding.severity]++;
  return result;
}
function invalid(result, error) {
  result.valid = false;
  addFinding(result, 'MCL-001');
  result.inputError = ['size', 'depth', 'shape', 'number'].includes(error?.code) ? error.code : 'syntax';
  return finish(result);
}

function getServers(value) {
  if (!objectLike(value)) throw new InputError('shape');
  const keys = ['mcpServers', 'servers'].filter(key => own(value, key));
  if (keys.length !== 1) throw new InputError('shape');
  const collection = value[keys[0]];
  if (!objectLike(collection) && !Array.isArray(collection)) throw new InputError('shape');
  const entries = Array.isArray(collection) ? collection : Object.values(collection);
  if (entries.some(server => !objectLike(server))) throw new InputError('shape');
  return entries;
}

function traverse(value, callback, depth = 0) {
  if (depth > MAX_DEPTH || value === null || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    callback(key, child);
    if (child !== null && typeof child === 'object') traverse(child, callback, depth + 1);
  }
}

function sectionSecret(value) {
  let found = false;
  if (typeof value === 'string') return containsSecret(value);
  traverse(value, (key, child) => { if (containsSecret(child, key) || containsSecret(key)) found = true; });
  return found;
}

function argumentSecret(args) {
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    const split = argument.match(/^--?([^=]+)=(.*)$/s) ?? argument.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s);
    if (split && containsSecret(split[2], split[1])) return true;
    if (/^--?[A-Za-z][\w-]*$/.test(argument) && credentialKey.test(argument) && containsSecret(args[index + 1], argument)) return true;
    if (/^(?:Authorization|Proxy-Authorization|X-Api-Key)\s*:/i.test(argument)) {
      const [key, ...parts] = argument.split(':');
      if (containsSecret(parts.join(':').trim(), key)) return true;
    }
    if (containsSecret(argument)) return true;
  }
  return false;
}

function basename(command) { return command.replace(/\\/g, '/').split('/').pop()?.toLowerCase().replace(/\.(?:exe|cmd|bat|com)$/, '') ?? ''; }
const wrapperName = /^(?:env|sudo|doas|nohup|busybox|timeout|nice|setsid|stdbuf|ionice|taskset|chrt|xargs|flock|time|unshare|command|exec)$/;

/** Only command text is tokenized. Items in an args array remain literal argv items. */
function commandWords(source) {
  const words = [];
  let word = '', quote = null, started = false;
  for (let index = 0; index < source.length; index++) {
    const char = source[index];
    if (char === quote) { quote = null; started = true; continue; }
    if (!quote && (char === '"' || char === "'")) { quote = char; started = true; continue; }
    const windowsPath = /^(?:[A-Za-z]:[\\/]|\\\\)/.test(word);
    if (char === '\\' && quote !== "'" && !windowsPath && /[\s\\"'$`;&|]/.test(source[index + 1] ?? '')) {
      word += source[++index]; started = true; continue;
    }
    if (!quote && /\s/.test(char)) {
      if (started) words.push(word);
      word = ''; started = false; continue;
    }
    word += char; started = true;
  }
  if (started) words.push(word);
  return words;
}

function commandInvocation(raw, args) {
  const text = raw.trim();
  const tokenized = commandWords(text);
  // A Windows executable path may contain spaces and shell-looking characters.
  // A recognizable POSIX interpreter path can also contain spaces in directories.
  const path = text.match(/^(?:[A-Za-z]:[\\/]|\\\\)[^"\r\n]*?\.(?:exe|cmd|bat|com)(?=\s|$)/i)
    ?? (!wrapperName.test(basename(tokenized[0] ?? '')) && text.match(/^(?:\/|\.{1,2}\/)[^"'\r\n]*?\/(?:node(?:js)?|python(?:w|\d+(?:\.\d+)*)?|(?:(?:ba|da|z|fi|k|a)?sh|[t]?csh|mksh)|pwsh|perl|ruby|npx)(?=\s|$)/i));
  const words = path ? [path[0], ...commandWords(text.slice(path[0].length))] : tokenized;
  const inlineArgs = words.slice(1);
  return { command: words[0] ?? '', args: [...inlineArgs, ...args], inlineCount: inlineArgs.length,
    inlineCode: path ? text.slice(path[0].length) : text };
}

/** Walk known argv wrappers only; never execute or resolve an executable. */
function unwrapInvocation(invocation) {
  const tokens = [{ value: invocation.command, field: 'command' }, ...invocation.args.map((value, index) => ({
    value, field: index < invocation.inlineCount ? 'command' : 'args',
  }))];
  let cursor = 0, splits = 0;
  while (cursor < tokens.length) {
    const name = basename(tokens[cursor].value);
    if (!wrapperName.test(name)) break;
    let index = cursor + 1, endOptions = false;
    while (index < tokens.length) {
      const argument = tokens[index].value;
      if (!endOptions && argument === '--') { endOptions = true; index++; continue; }
      if (/^(?:env|sudo)$/.test(name) && /^[A-Za-z_][A-Za-z0-9_]*=/.test(argument)) { index++; continue; }
      if (endOptions || !argument.startsWith('-') || argument === '-' && name !== 'env') break;
      if (name === 'env' && /^(?:-S|--split-string(?:=|$))/.test(argument)) {
        // env explicitly splits this one argument; ordinary argv stays literal.
        const attached = argument.startsWith('--split-string=') || argument.startsWith('-S') && argument.length > 2;
        const source = attached ? argument.startsWith('-S') ? argument.slice(2) : argument.slice(argument.indexOf('=') + 1) : tokens[index + 1]?.value;
        if (source === undefined || ++splits > MAX_DEPTH) return null;
        const field = tokens[index].field;
        tokens.splice(index, attached ? 1 : 2, ...commandWords(source).map(value => ({ value, field })));
        continue;
      }
      if (/^(?:--help|--version)$/.test(argument)) return null;
      if (name === 'busybox') return null; // --install/--list do not run the following applet.
      const takesValue = name === 'env' ? /^(?:-u|--unset|-C|--chdir|--argv0)$/
        : name === 'sudo' ? /^(?:-[ugphCDRT]|--user|--group|--prompt|--host|--close-from|--chdir|--chroot|--role|--type|--command-timeout)$/
          : name === 'doas' ? /^(?:-u|-a)$/
          : name === 'timeout' ? /^(?:-k|--kill-after|-s|--signal)$/
            : name === 'nice' ? /^(?:-n|--adjustment)$/
              : name === 'stdbuf' ? /^(?:-[ioe]|--input|--output|--error)$/
                : name === 'ionice' ? /^(?:-[cn]|--class|--classdata)$/
                  : name === 'taskset' ? /^(?:-c|--cpu-list)$/
                    : name === 'xargs' ? /^(?:-[adEILnPs]|--arg-file|--delimiter|--eof|--replace|--max-lines|--max-args|--max-procs|--max-chars)$/
                      : name === 'flock' ? /^(?:-[wE]|--wait|--timeout|--conflict-exit-code)$/
                        : name === 'time' ? /^(?:-[fo]|--format|--output)$/
                          : name === 'unshare' ? /^(?:-[SGRw]|--setuid|--setgid|--root|--wd|--map-user|--map-group|--map-users|--map-groups)$/
                            : name === 'exec' ? /^-a$/ : /^$/;
      if (name === 'sudo' && /^(?:-[elvVK]|--edit|--list|--validate|--remove-timestamp)$/.test(argument)
        || name === 'doas' && /^-C/.test(argument)
        || name === 'command' && /^-[vV]+$/.test(argument)
        || /^(?:ionice|taskset|chrt)$/.test(name) && /^(?:-[pPuU]|--pid|--pgid|--uid)$/.test(argument)) return null;
      if (takesValue.test(argument)) { if (!tokens[index + 1]) return null; index += 2; }
      else index++;
    }
    if (name === 'timeout') {
      if (!/^\d+(?:\.\d+)?[smhd]?$/.test(tokens[index]?.value ?? '')) return null;
      index++;
    } else if (name === 'taskset' && !tokens.slice(cursor + 1, index).some(token => /^(?:-c|--cpu-list)$/.test(token.value))) {
      if (!/^(?:0x)?[a-f0-9]+$/i.test(tokens[index]?.value ?? '')) return null;
      index++;
    } else if (name === 'chrt') {
      if (!/^\d+$/.test(tokens[index]?.value ?? '')) return null;
      index++;
    } else if (name === 'flock') {
      // The first operand is a lock file/directory/fd, not the executable.
      index++;
      const option = tokens[index]?.value ?? '';
      if (/^(?:-c|--command)(?:=|$)/.test(option)) {
        const attached = option.startsWith('--command=');
        const code = attached ? option.slice(option.indexOf('=') + 1) : tokens[index + 1]?.value;
        const field = tokens[index].field;
        return { command: 'sh', args: ['-c', ...(code === undefined ? [] : [code])], fields: [field, field] };
      }
    }
    if (index >= tokens.length) return null;
    cursor = index;
  }
  return { command: tokens[cursor]?.value ?? '', args: tokens.slice(cursor + 1).map(token => token.value),
    fields: tokens.slice(cursor + 1).map(token => token.field) };
}

function evaluation(command, args) {
  const name = basename(command);
  const commandStringWrapper = /^(?:su|script)$/.test(name);
  const kind = /^(?:(?:ba|da|z|fi|k|a)?sh|[t]?csh|mksh)$/.test(name) || commandStringWrapper ? 'shell'
    : /^(?:cmd|powershell|pwsh)$/.test(name) ? name === 'cmd' ? 'cmd' : 'powershell'
      : /^python(?:w|\d+(?:\.\d+)*)?$/.test(name) ? 'python'
        : /^(?:node|nodejs)$/.test(name) ? 'node'
          : /^(?:perl|ruby|npx)$/.test(name) ? name : null;
  if (!kind) return null;
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === '--') break;
    if (!(kind === 'cmd' ? /^\// : kind === 'shell' ? /^[-+]/ : /^-/).test(argument)) {
      if (commandStringWrapper) continue; // su's user and script's log file may precede -c.
      break;
    }
    if (/^(?:--help|--version)$/.test(argument)) break;
    if (kind === 'python' && argument === '-m' || kind === 'powershell' && /^-file$/i.test(argument)
      || kind === 'ruby' && argument === '-S') break;
    const separate = commandStringWrapper ? /^(?:-[qelfm]*c|--command|--session-command)$/.test(argument)
      : kind === 'shell' ? /^-[a-z]*c[a-z]*$/i.test(argument)
      : kind === 'cmd' ? /^\/[ck]$/i.test(argument)
        : kind === 'powershell' ? /^-(?:c|command|e|ec|enc|encodedcommand)$/i.test(argument)
          : kind === 'python' ? /^-[bBEiIOqRsSuvVWxX]*c$/.test(argument)
            : kind === 'perl' ? /^-[anlpwW]*[eE]$/.test(argument)
              : kind === 'ruby' ? /^-[anlpw]*e$/.test(argument)
              : kind === 'npx' ? /^(?:-c|--call)$/.test(argument)
                : /^(?:-e|--eval|-p|--print)$/.test(argument);
    const attached = commandStringWrapper ? argument.match(/^(?:--(?:session-)?command=|-c)(.+)$/s)
      : kind === 'node' ? argument.match(/^(?:--(?:eval|print)=|-[ep])(.+)$/s)
      : kind === 'python' ? argument.match(/^-c(.+)$/s)
        : kind === 'perl' ? argument.match(/^-[anlpwW]*[eE](.+)$/s)
          : kind === 'ruby' ? argument.match(/^-[anlpw]*e(.+)$/s)
          : kind === 'npx' ? argument.match(/^(?:--call=|-c)(.+)$/s) : null;
    if (separate || attached) {
      const encoded = kind === 'powershell' && /^-(?:e|ec|enc|encodedcommand)$/i.test(argument);
      const code = attached?.[1] ?? (kind === 'cmd' || kind === 'powershell' ? args.slice(index + 1).join(' ') : args[index + 1]);
      return { kind, index, nextIndex: index + (attached ? 1 : 2), code: encoded ? null : code ?? null };
    }
    const takesValue = name === 'su' ? /^(?:-[sgG]|--shell|--group|--supp-group|--whitelist-environment)$/
      : name === 'script' ? /^(?:-[BIOoT]|--log-in|--log-out|--log-io|--log-timing|--output-limit)$/
      : kind === 'node' ? /^(?:-r|--require|--import|--loader|--experimental-loader|--input-type)$/
      : kind === 'python' ? /^-[WX]$/ : kind === 'shell' ? /^(?:[-+][oO]|--rcfile|--init-file)$/
        : kind === 'perl' ? /^-[IMmF]$/ : kind === 'ruby' ? /^-[CIrE]$/
          : kind === 'npx' ? /^(?:-p|--package|--cache|--registry|--userconfig|--prefix)$/
            : /^-(?:ep|ex|executionpolicy|w|windowstyle|workingdirectory|inputformat|outputformat)$/i;
    if (takesValue.test(argument)) index++;
  }
  return null;
}

function evaluations(command, args) {
  const found = [];
  let offset = 0;
  while (offset < args.length) {
    const evaluated = evaluation(command, args.slice(offset));
    if (!evaluated) break;
    found.push({ ...evaluated, index: evaluated.index + offset });
    if (evaluated.kind !== 'perl' && evaluated.kind !== 'ruby') break;
    // Perl and Ruby accept several -e source arguments before the script/argv boundary.
    offset += evaluated.nextIndex;
  }
  return found;
}

function invocationEvaluations(invocation) {
  if (!invocation) return [];
  const tokens = [invocation.command, ...invocation.args];
  for (let index = 0; index < tokens.length; index++) {
    if (!/^(?:(?:(?:ba|da|z|fi|k|a)?sh|[t]?csh|mksh)|cmd|powershell|pwsh|python(?:w|\d+(?:\.\d+)*)?|node(?:js)?|perl|ruby|npx|su|script)$/.test(basename(tokens[index]))) continue;
    // An unknown wrapper cannot hide a recognizable interpreter in literal argv.
    // This conservative fallback may warn for data resembling an invocation.
    // Only the effective command owns an authoritative script/--/-m boundary.
    // Later names may be wrapper option values (e.g. docker --name node), so a
    // candidate without evaluation must not hide subsequent interpreter argv.
    const found = evaluations(tokens[index], tokens.slice(index + 1)).map(evaluated => ({
      ...evaluated, field: invocation.fields[index + evaluated.index],
    }));
    if (index === 0 && basename(tokens[index]) === 'npx' && found.length === 0) {
      const separator = tokens.indexOf('--', 1);
      if (separator >= 1) { index = separator; continue; }
    }
    if (index === 0 || found.length) return found;
  }
  return [];
}
function shellOperators(code) {
  let quote = null;
  let chain = false;
  let substitution = false;
  let redirection = false;
  for (let index = 0; index < code.length; index++) {
    const char = code[index];
    if (char === '\\' && quote !== "'") { index++; continue; }
    if (char === quote) { quote = null; continue; }
    if (!quote && (char === "'" || char === '"')) { quote = char; continue; }
    if (quote !== "'" && (char === '`' || (char === '$' && code[index + 1] === '('))) substitution = true;
    if (!quote && /[;&|\n\r]/.test(char)) chain = true;
    if (!quote && /[<>]/.test(char)) redirection = true;
  }
  return { chain, substitution, redirection };
}

/** Decode only a quoted literal, without evaluating Python, JavaScript or a shell. */
function codeLiteral(source, offset) {
  while (/\s/.test(source[offset] ?? '') && offset < source.length) offset++;
  if (/^[rub]{1,2}["']/i.test(source.slice(offset, offset + 3))) offset += source.slice(offset).match(/^[rub]{1,2}/i)[0].length;
  const quote = source[offset++];
  if (quote !== '"' && quote !== "'") return null;
  let value = '';
  for (; offset < source.length; offset++) {
    const char = source[offset];
    if (char === quote) return { value, end: offset + 1 };
    if (char === '\\') {
      const next = source[++offset];
      value += ({ n: '\n', r: '\r', t: '\t' })[next] ?? next ?? '';
    } else value += char;
  }
  return null;
}

function embeddedShells(code, kind) {
  const texts = [];
  // Deliberately bounded literal analysis, without imports, execution or dataflow.
  const calls = kind === 'python'
    ? /\b(os\s*\.\s*(?:system|popen)|subprocess\s*\.\s*(?:run|call|Popen|check_call|check_output))\s*\(/g
    : kind === 'node' ? /\b(exec|execSync)\s*\(/g : /\b(system|exec|readpipe)\b/g;
  if (kind === 'node' && !/['"](?:node:)?child_process['"]/.test(code)) return texts;
  // Keep source offsets, but exclude calls mentioned only in comments or strings.
  const visible = code.replace(kind !== 'node'
    ? /#[^\r\n]*|'''[\s\S]*?'''|"""[\s\S]*?"""|'(?:\\[\s\S]|[^'\\])*'|"(?:\\[\s\S]|[^"\\])*"/g
    : /\/\/[^\r\n]*|\/\*[\s\S]*?\*\/|'(?:\\[\s\S]|[^'\\])*'|"(?:\\[\s\S]|[^"\\])*"|`(?:\\[\s\S]|[^`\\])*`/g, match => ' '.repeat(match.length));
  for (const match of visible.matchAll(calls)) {
    let offset = match.index + match[0].length;
    if (kind === 'perl' || kind === 'ruby') {
      while (/\s/.test(code[offset] ?? '') && offset < code.length) offset++;
      if (code[offset] === '(') offset++;
    }
    const literal = codeLiteral(code, offset);
    if (!literal) continue;
    if (kind === 'python' && match[1].startsWith('subprocess') && !/^\s*,[^)\n]*\bshell\s*=\s*True\b/.test(code.slice(literal.end))) continue;
    if ((kind === 'perl' || kind === 'ruby') && /^\s*,/.test(code.slice(literal.end))) continue; // list argv is not shell text
    texts.push(literal.value);
  }
  return texts;
}

function inspectPowerShell(add, code, field) {
  // Mask comments and quoted data before matching the download-to-evaluation call.
  const dataOrComment = /<#[\s\S]*?#>|#[^\r\n]*|'(?:''|[^'])*'|"(?:`[\s\S]|[^"`])*"/g;
  const visible = code.replace(dataOrComment, match => ' '.repeat(match.length));
  const source = /(?:^|[(&|])\s*(?:irm|iwr|invoke-restmethod|invoke-webrequest)\b|\.\s*download(?:string|data)\s*\(/i;
  const sink = /(?:^|[(&|])\s*(?:iex|invoke-expression)(?=\s|\(|$)/i;
  // Keep statement and pipe boundaries: unrelated download/evaluation statements
  // are not a flow. Quoted strings/comments cannot supply either endpoint.
  for (const statement of visible.split(/[;\r\n]/)) {
    const stages = statement.split('|');
    for (let index = 0; index < stages.length; index++) {
      const stage = stages[index];
      const evaluated = stage.match(sink);
      const argument = evaluated ? stage.slice(evaluated.index + evaluated[0].length) : '';
      if (evaluated && source.test(argument) || source.test(stage) && sink.test(stages[index + 1] ?? '')) add('MCL-008', field);
    }
  }
  const uncommented = code.replace(dataOrComment, match => /^(?:#|<#)/.test(match) ? ' '.repeat(match.length) : match).trim();
  // Expression sinks use the statement-aware check above. Native shell pipelines
  // in the same source still receive the ordinary download-to-execution check.
  inspectShell(add, uncommented, field, false);
}

function inspectShell(add, code, field, expressionSinks = true) {
  const operators = shellOperators(code);
  if (operators.chain) add('MCL-007', field);
  const visible = code.replace(/'(?:[^']*)'|"(?:\\[\s\S]|[^"\\])*"/g, match => /\$\(|`/.test(match) && match[0] === '"' ? match : ' '.repeat(match.length));
  const nativeExecution = /(?:[|;&]\s*(?:[^\s|;&]*[\\/])?(?:(?:(?:ba|da|z|fi|k|a)?sh|[t]?csh|mksh)|python\d*|node|perl|ruby|cmd|powershell|pwsh)\b|\bchmod\s+\+x\b|\$\(|`|[;&]\s*\.\/)/i.test(visible);
  const expressionExecution = expressionSinks && /[|;&]\s*(?:[^\s|;&]*[\\/])?(?:iex|invoke-expression)\b/i.test(visible);
  if (/\b(?:curl|wget|fetch|invoke-webrequest|iwr)\b/i.test(visible) && (operators.chain || operators.substitution)
    && (nativeExecution || expressionExecution)) add('MCL-008', field);
}

function packageReferences(command, args) {
  const name = basename(command);
  let kind = 'npm';
  let start = -1;
  let installer = false;
  let multiple = false;
  if (/^(?:npx|bunx)$/.test(name)) { start = 0; installer = true; }
  else if (/^(?:npm|pnpm|yarn|bun)$/.test(name) && /^(?:exec|dlx|x|install|add)$/.test(args[0] ?? '')) { start = 1; installer = true; }
  else if (/^(?:uvx|pip|pip3)$/.test(name)) { kind = 'python'; start = name === 'uvx' ? 0 : args[0] === 'install' ? 1 : -1; installer = start >= 0; }
  else if (/^python(?:3(?:\.\d+)?)?$/.test(name) && args[0] === '-m' && args[1] === 'pip' && args[2] === 'install') { kind = 'python'; start = 3; installer = true; }
  else if (name === 'uv' && ((args[0] === 'tool' && args[1] === 'run') || (args[0] === 'pip' && args[1] === 'install'))) { kind = 'python'; start = 2; installer = true; }
  else if (/^(?:docker|podman)$/.test(name) && /^(?:run|create)$/.test(args[0] ?? '')) { kind = 'container'; start = 1; }
  const refs = [];
  if (start < 0) return { refs, installer };
  multiple = /^(?:install|add)$/.test(args[start - 1] ?? '');
  const takesValue = /^(?:--package|-p|--from|--registry|--cache|--prefix|--user|-u|--volume|-v|--mount|--network|--name|--env|-e|--env-file|--workdir|-w|--entrypoint|--platform|--index-url|-i|--extra-index-url|--python|--directory|--cwd)$/;
  for (let index = start; index < args.length; index++) {
    const argument = args[index];
    if (name === 'npx' && /^(?:-c|--call)(?:$|=)|^-c.+/s.test(argument)) break; // Shell source is not a package reference.
    if (/^(?:--package|--from)=/.test(argument)) { refs.push({ kind, value: argument.slice(argument.indexOf('=') + 1) }); continue; }
    if (/^(?:--package|-p|--from)$/.test(argument) && kind !== 'container') { if (args[index + 1]) refs.push({ kind, value: args[++index] }); continue; }
    if (takesValue.test(argument)) { index++; continue; }
    if (argument.startsWith('-')) continue;
    // With --package/--from the next positional token is the executable, not another package.
    if (refs.length && !multiple && kind !== 'container') break;
    refs.push({ kind, value: argument });
    if (!multiple) break;
  }
  return { refs, installer };
}

function pinRule({ kind, value }) {
  if (!value || placeholder(value)) return 'MCL-012';
  if (kind === 'container') {
    if (/@sha256:[a-f0-9]{64}$/i.test(value)) return null;
    const tag = value.slice(value.lastIndexOf('/') + 1).split(':')[1];
    return tag === 'latest' ? 'MCL-010' : tag ? 'MCL-011' : 'MCL-012';
  }
  if (/^(?:git\+|github:|https?:).*#[a-f0-9]{40}$/i.test(value)) return null;
  if (/^(?:\.\/|\.\.\/|\/|file:)/.test(value)) return null;
  let version;
  if (kind === 'python') {
    const matched = value.match(/(?:==|~=|>=|<=|>|<|@)(.+)$/);
    if (!matched) return 'MCL-012';
    if (!/(?:==|@)/.test(matched[0])) return 'MCL-011';
    version = matched[1];
  } else {
    const at = value.lastIndexOf('@');
    if (at <= 0 || !value.slice(at + 1)) return 'MCL-012';
    version = value.slice(at + 1);
  }
  if (version.toLowerCase() === 'latest') return 'MCL-010';
  const exact = kind === 'python'
    ? /^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?(?:\+[a-z0-9.-]+)?$/i.test(version)
    : /^v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9][A-Za-z0-9.+-]*)?$/.test(version);
  return exact ? null : 'MCL-011';
}

function networkInfo(raw) {
  if (typeof raw !== 'string') return null;
  try {
    const url = new URL(raw);
    if (!/^(?:https?|wss?):$/.test(url.protocol)) return null;
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    const v4 = /^\d+\.\d+\.\d+\.\d+$/.test(host);
    const mapped = host.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    const mappedHex = host.match(/^::ffff:([a-f0-9]{1,4}):([a-f0-9]{1,4})$/i);
    const octets = mappedHex ? [parseInt(mappedHex[1], 16) >> 8, parseInt(mappedHex[1], 16) & 255, parseInt(mappedHex[2], 16) >> 8, parseInt(mappedHex[2], 16) & 255] : (mapped?.[1] ?? host).split('.').map(Number);
    const isV4 = v4 || mapped || mappedHex;
    const loopback = host === 'localhost' || host.endsWith('.localhost') || host === '::1' || (isV4 && octets[0] === 127);
    const privateAddress = isV4 && (octets[0] === 10 || octets[0] === 0 || octets[0] === 169 && octets[1] === 254 || octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31 || octets[0] === 192 && octets[1] === 168)
      || host.includes(':') && /^(?:fc|fd|fe[89ab])/i.test(host) || host === '::';
    return { url, host, loopback, privateAddress: Boolean(privateAddress), literal: v4 || host.includes(':') };
  } catch { return null; }
}

function hasAuth(server) {
  if (objectLike(server.headers) && Object.entries(server.headers).some(([key, value]) => credentialKey.test(key) && typeof value === 'string' && Boolean(value.trim()))) return true;
  return ['auth', 'authentication', 'oauth', 'oauth2', 'bearerToken', 'apiKey'].some(key => {
    const value = server[key];
    if (objectLike(value)) return Object.keys(value).length > 0 && !/^(?:none|anonymous|disabled)$/i.test(value.type ?? '');
    return value === true || typeof value === 'string' && value.length > 0 && !/^(?:none|anonymous|disabled)$/i.test(value);
  });
}
function wildcard(value) {
  return value === true || typeof value === 'string' && /^(?:\*|all)$/i.test(value)
    || Array.isArray(value) && value.some(item => item === '*' || item === 'all')
    || objectLike(value) && (truthy(value.all) || truthy(value['*']));
}

function rootPath(value) { return /^(?:\/|[A-Za-z]:[\\/]|file:\/\/\/[A-Za-z]:\/?|file:\/\/\/)$/.test(value.trim()); }
function homePath(value) { return /^(?:~(?:[\\/]|$)|\$(?:HOME|USERPROFILE)(?:[\\/]|$)|\$\{(?:env:)?(?:HOME|USERPROFILE)\}(?:[\\/]|$)|\/(?:home|Users|root)(?:\/|$)|[A-Za-z]:[\\/]Users(?:[\\/]|$))/i.test(value.trim()); }
function mountSensitive(value) {
  const volume = value.replace(/^(?:--volume=|-v)/, '');
  const source = value.match(/(?:^|,)\s*(?:source|src)=([^,]+)/)?.[1]
    ?? (/^[A-Za-z]:[\\/]/.test(volume) ? volume.slice(0, volume.indexOf(':', 2) === -1 ? undefined : volume.indexOf(':', 2)) : volume.split(':')[0]);
  return rootPath(source) || homePath(source) || /^(?:\/(?:etc|proc|sys|dev|boot)(?:\/|$)|\/var\/run\/(?:docker|podman)\.sock$|\/run\/(?:docker|podman)\.sock$)/.test(source);
}

function lintServer(result, server, index) {
  const label = `server#${index + 1}`;
  const add = (id, field) => addFinding(result, id, label, field);
  const rawCommand = typeof server.command === 'string' ? server.command : '';
  const rawArgs = strings(server.args);
  const invocation = commandInvocation(rawCommand, rawArgs);
  const { command, args } = invocation;
  if (server.command !== undefined && typeof server.command !== 'string' || server.args !== undefined && (!Array.isArray(server.args) || server.args.some(arg => typeof arg !== 'string')) || !command && typeof server.url !== 'string' && typeof server.serverUrl !== 'string' && typeof server.endpoint !== 'string') {
    result.valid = false; add('MCL-001', 'configuration');
  }
  if (sectionSecret(server.env) || sectionSecret(server.environment)) add('MCL-003', 'env');
  if (argumentSecret(args)) add('MCL-004', 'args');
  if (sectionSecret(server.headers)) add('MCL-005', 'headers');
  if (sectionSecret(server.query) || sectionSecret(server.queryParams)) add('MCL-006', 'query');
  const inlineOperators = shellOperators(invocation.inlineCode);
  if (inlineOperators.chain || inlineOperators.substitution || inlineOperators.redirection) {
    add('MCL-009', 'command');
    inspectShell(add, invocation.inlineCode, 'command');
  }
  const unwrapped = unwrapInvocation(invocation);
  for (const evaluated of invocationEvaluations(unwrapped)) {
    const field = evaluated.field;
    add('MCL-009', field);
    if (evaluated.code !== null) {
      if (/^(?:python|node|perl|ruby)$/.test(evaluated.kind)) {
        for (const code of embeddedShells(evaluated.code, evaluated.kind)) inspectShell(add, code, field);
      } else if (evaluated.kind === 'powershell') inspectPowerShell(add, evaluated.code, field);
      else inspectShell(add, evaluated.code, field);
    }
  }
  const packages = packageReferences(unwrapped?.command ?? command, unwrapped?.args ?? args);
  if (packages.installer) add('MCL-013', 'command');
  for (const reference of packages.refs) { const id = pinRule(reference); if (id) add(id, 'args'); }
  for (const field of ['url', 'serverUrl', 'endpoint']) {
    const info = networkInfo(server[field]);
    if (!info) continue;
    if (info.url.username || info.url.password) add('MCL-006', 'url');
    for (const [key, value] of info.url.searchParams) if (containsSecret(value, key) || containsSecret(key)) add('MCL-006', 'query');
    if (!info.loopback) {
      if (/^(?:http|ws):$/.test(info.url.protocol)) add('MCL-014', 'url');
      if (info.literal) add('MCL-015', 'url');
      if (info.privateAddress) add('MCL-016', 'url');
      if (!hasAuth(server)) add('MCL-024', 'authentication');
    }
  }
  const container = /^(?:docker|podman)$/.test(basename(command));
  if (container) {
    if (args.some(arg => arg === '--privileged' || arg === '--privileged=true' || /^--cap-add=(?:ALL|SYS_ADMIN)$/i.test(arg)) || args.some((arg, i) => arg === '--cap-add' && /^(?:ALL|SYS_ADMIN)$/i.test(args[i + 1] ?? ''))) add('MCL-019', 'args');
    if (args.some((arg, i) => /^(?:--user|-u)=(?:root|0)(?::|$)/.test(arg) || /^(?:--user|-u)$/.test(arg) && /^(?:root|0)(?::|$)/.test(args[i + 1] ?? ''))) add('MCL-020', 'args');
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      const mount = /^(?:--volume|--mount|-v)=/.test(arg) ? arg.slice(arg.indexOf('=') + 1) : /^(?:--volume|--mount|-v)$/.test(arg) ? args[i + 1] : /^-v.+/.test(arg) ? arg.slice(2) : null;
      if (mount && mountSensitive(mount)) add('MCL-021', 'args');
      if (arg === '--network=host' || arg === '--net=host' || /^(?:--network|--net)$/.test(arg) && args[i + 1] === 'host') add('MCL-027', 'args');
    }
  }
  const pathValues = [...args];
  for (const argument of args) {
    const pathFlag = argument.match(/^--(?:root|path|directory|allowed-directory|allowedDirectories|cwd)=(.*)$/);
    if (pathFlag) pathValues.push(pathFlag[1]);
  }
  traverse(server, (key, value) => {
    if (/^(?:roots?|paths?|allowedDirectories|directory|cwd)$/i.test(key)) pathValues.push(...(typeof value === 'string' ? [value] : strings(value)));
    if (/^(?:privileged|allowPrivilegeEscalation)$/i.test(key) && truthy(value)) add('MCL-019', 'container');
    if (/^(?:user|runAsUser)$/i.test(key) && (value === 0 || /^(?:root|0)(?::|$)/.test(typeof value === 'string' ? value : ''))) add('MCL-020', 'identity');
    if (/^(?:autoApprove|autoApproveTools|alwaysAllow|skipApproval|dangerouslySkipPermissions)$/i.test(key) && wildcard(value)) add('MCL-022', 'approval');
    if (/^(?:requireApproval|approvalRequired)$/i.test(key) && value === false) add('MCL-022', 'approval');
    if (/^(?:allowedTools|toolAllowlist|allowTools)$/i.test(key) && wildcard(value)) add('MCL-028', 'tools');
    if (/^(?:inheritEnv|inheritEnvironment|passEnvironment|forwardEnvironment|passEnv|envForward|environmentPassthrough)$/i.test(key) && (wildcard(value) || /^(?:inherit|all)$/i.test(typeof value === 'string' ? value : ''))) add('MCL-023', 'env');
    if (/^(?:env|environment)$/i.test(key) && (value === '*' || value === 'inherit' || value === 'all' || objectLike(value) && (own(value, '*') || truthy(value.__inherit__)))) add('MCL-023', 'env');
    if (/^(?:forwardToken|tokenForwarding|passThroughToken|tokenPassthrough|forwardAuthorization|forwardAuth)$/i.test(key) && truthy(value) || /^forwardHeaders$/i.test(key) && strings(value).some(item => /^(?:authorization|\*)$/i.test(item))) add('MCL-025', 'authentication');
    if (typeof value === 'string' && credentialKey.test(key) && /(?:request|incoming|client)[.:_\[\]'-]*(?:headers?[.:_\[\]'-]*)?(?:authorization|token)|headers\.get\(['"]authorization/i.test(value)) add('MCL-025', 'authentication');
    if (/^(?:rejectUnauthorized|verifyTLS|verifySsl|verifyCertificates)$/i.test(key) && value === false || /^(?:insecure|skipTlsVerify|tlsInsecure)$/i.test(key) && truthy(value) || key === 'NODE_TLS_REJECT_UNAUTHORIZED' && String(value) === '0' || key === 'PYTHONHTTPSVERIFY' && String(value) === '0') add('MCL-026', 'tls');
    if (/^(?:host|bind|listenAddress|bindAddress)$/i.test(key) && /^(?:0\.0\.0\.0|::|\[::\]|\*)$/.test(String(value))) add('MCL-027', 'network');
    if (/^(?:volumes?|mounts?)$/i.test(key)) {
      const mounts = typeof value === 'string' ? [value] : strings(value);
      const records = Array.isArray(value) ? value : objectLike(value) ? [value] : [];
      for (const record of records) if (objectLike(record) && typeof (record.source ?? record.src) === 'string') mounts.push(record.source ?? record.src);
      if (mounts.some(mountSensitive)) add('MCL-021', 'container');
    }
  });
  if (pathValues.some(rootPath)) add('MCL-017', 'filesystem');
  if (pathValues.some(homePath)) add('MCL-018', 'filesystem');
  if (args.some((arg, i) => /^(?:--host|--bind|--listen)=(?:0\.0\.0\.0|::|\[::\])$/.test(arg) || /^(?:--host|--bind|--listen)$/.test(arg) && /^(?:0\.0\.0\.0|::|\[::\])$/.test(args[i + 1] ?? ''))) add('MCL-027', 'args');
}

export function lint_config(input, _options = {}) {
  const result = createResult();
  try {
    const parsed = parseInput(input);
    const servers = getServers(parsed.value);
    result.inputBytes = parsed.byteLength;
    result.serverCount = servers.length;
    if (parsed.duplicates) addFinding(result, 'MCL-002');
    const names = new Set();
    for (const server of servers) {
      if (typeof server.name === 'string') { if (names.has(server.name)) addFinding(result, 'MCL-002'); names.add(server.name); }
    }
    servers.forEach((server, index) => lintServer(result, server, index));
    // Approval and environment inheritance can also be client-wide.
    const globalSettings = Object.fromEntries(Object.entries(parsed.value).filter(([key]) => !['servers', 'mcpServers'].includes(key)));
    if (Object.keys(globalSettings).length) {
      const globalResult = createResult();
      lintServer(globalResult, { command: 'local-mcp', ...globalSettings }, -1);
      for (const finding of globalResult.findings) {
        if (['MCL-022', 'MCL-023', 'MCL-025', 'MCL-026', 'MCL-028'].includes(finding.ruleId)) addFinding(result, finding.ruleId, 'configuration', finding.location.field);
      }
    }
    return finish(result);
  } catch (error) { return invalid(result, error); }
}
export const lintConfig = lint_config;

export function check_version_pins(input, options = {}) {
  const result = lint_config(input, options);
  result.findings = result.findings.filter(finding => ['MCL-001', 'MCL-002', 'MCL-010', 'MCL-011', 'MCL-012', 'MCL-013'].includes(finding.ruleId));
  return finish(result);
}
export const checkVersionPins = check_version_pins;

export function compare_config(before, after, options = {}) {
  const previous = lint_config(before, options);
  const next = lint_config(after, options);
  const key = finding => `${finding.ruleId}|${finding.location.server}|${finding.location.field}`;
  const previousKeys = new Set(previous.findings.map(key));
  const nextKeys = new Set(next.findings.map(key));
  return {
    schemaVersion: '1.0.0', rulesetVersion: RULESET_VERSION, ai_generated: false, disclaimer: DISCLAIMER,
    valid: previous.valid && next.valid, before: previous.summary, after: next.summary,
    added: next.findings.filter(finding => !previousKeys.has(key(finding))),
    resolved: previous.findings.filter(finding => !nextKeys.has(key(finding))),
    unchanged: next.findings.filter(finding => previousKeys.has(key(finding))).length,
    comparisonBasis: 'Rule, field, and server position; configuration values are never returned.',
  };
}
export const compareConfig = compare_config;

export function explain_rule(identifier) {
  if (typeof identifier !== 'string' || !own(RULE_BY_ID, identifier)) return { ai_generated: false, error: 'Unknown rule identifier.' };
  return { ...RULE_BY_ID[identifier], disclaimer: DISCLAIMER };
}
export const explainRule = explain_rule;

/** Safe parser summary, intentionally excluding the parsed configuration. */
export function parseConfig(input) {
  const result = lint_config(input);
  result.findings = result.findings.filter(finding => ['MCL-001', 'MCL-002'].includes(finding.ruleId));
  return finish(result);
}

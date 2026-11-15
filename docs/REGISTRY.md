# MCP Registry and distribution: mcp-configlint

Facts about external services in this document were verified on **2026-11-13**. This repository is a local release candidate. Nothing has been published, authenticated, reserved or submitted.

The names are final but unpublished:

| Item | Value |
| --- | --- |
| npm package | `mcp-configlint`, version `0.1.0` |
| MCP Registry name | `io.github.strictstack/mcp-configlint` (alternative DNS namespace: `tech.strictstack/mcp-configlint`) |
| Source code | https://github.com/strictstack/mcp-configlint |
| Documentation | https://strictstackdocs.tech/mcp-configlint/ |
| Vendor | StrictStack, https://strictstack.tech |

The operator chose these names and checked that they were unused (HTTP 404) before publication. The URLs respond only after the operator publishes. Ownership of the namespace and of the package is proven at publication time; this document does not claim ownership, availability, publication or acceptance by any directory.

## Metadata and ownership

`server.json` uses the official Registry schema **2025-12-11**. This schema revision is independent of the MCP protocol revision. Validation uses the complete, unmodified schema in `schemas/` and checks its SHA-256 against `LICENSES.json`. Passing JSON Schema validation does not demonstrate namespace control, package ownership or existence, policy acceptance or completed publication.

The [official requirements](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/server-json/official-registry-requirements.md) describe the namespace and package ownership checks. The [package types guide](https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/package-types.mdx) requires `mcpName` in the npm `package.json` (or `mcp-name: SERVER_NAME` in a PyPI README/description) to match `server.json`. In this repository `package.json#mcpName` and `server.json#name` are both `io.github.strictstack/mcp-configlint`.

For the `io.github.strictstack/*` namespace the Registry authenticates through GitHub and requires the token to be able to read organization membership. For `tech.strictstack/*` it authenticates through a DNS TXT record on `strictstack.tech` (see the [authentication guide](https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/authentication.mdx), consulted 2026-11-15).

The original ConfigLint code is licensed under Apache-2.0. The validation schemas have their own terms, preserved in `schemas/licenses/`; they are neither code nor runtime dependencies.

## Distribution channels and costs

| Channel | Evidence on the verification date | Operator action and limitations |
| --- | --- | --- |
| [Official MCP Registry](https://github.com/modelcontextprotocol/registry) | Open catalogue; the publication requirements consulted do not document a publication fee | Publish the package first, prove namespace control, then submit the metadata. Review the requirements in force at release time. |
| [npm public packages](https://www.npmjs.com/products) | The free plan includes public packages | Suitable hosting for ConfigLint. Scoped public packages require public access settings and an operator-controlled scope. |
| [MCP Market](https://mcpmarket.com/submit) | Free Queue option explicitly at $0; the page estimates 4–6 weeks | Manual submission of the public repository. Paid promotion is optional and out of scope. Acceptance and timing are not guaranteed. |
| [Glama](https://glama.ai/mcp/faq) | Repository submission for open-source servers; the [pricing](https://glama.ai/pricing) page describes free hosting for open source | Possible channel for ConfigLint under Apache-2.0. Repository availability, review and terms must be checked. |
| [PulseMCP](https://www.pulsemcp.com/submit) | New submissions and updates suspended; entry through the official Registry is recommended | Wait for reopening; a possible future automatic import is not a completed listing. |
| [Smithery](https://www.smithery.ai/future) | The public directory remains; CLI, API, proxy, accounts and keys ended on 2026-10-31 | Do not follow obsolete Smithery CLI publication instructions. No current submission route was verified. |

The [mcp.so submission page](https://mcp.so/submit?type=server) showed a $39 fee, so it is excluded from the free publication route. Hosting, paid featuring, domains and optional accounts with paid features are not required for the local checks.

## Publication commands

Publication is performed only by the operator through `scripts/publish-public-release.sh`; see "Publishing (operator only)" in the [README](../README.md) for options, configuration, prerequisites and exit codes. Never add tokens to this repository.

Local checks, without publication:

```sh
python3 scripts/validate_registry.py
bash scripts/publish-public-release.sh --dry-run
```

With `--confirmar`, after the local verification steps, the script runs these external commands in order (each step is skipped if the remote state already matches and refused if it differs):

```sh
git ls-remote https://github.com/strictstack/mcp-configlint.git refs/heads/main
git push https://github.com/strictstack/mcp-configlint.git <HEAD>:refs/heads/main
npm publish <tgz> --access public --ignore-scripts
mcp-publisher login github          # token via MCP_GITHUB_TOKEN in the child environment
# or, for tech.strictstack/mcp-configlint:
mcp-publisher login dns --domain strictstack.tech   # key via MCP_PRIVATE_KEY in the child environment
mcp-publisher publish
```

Before `npm publish` the script checks `https://registry.npmjs.org/mcp-configlint/0.1.0`; before `mcp-publisher publish` it checks the version already published in the Registry. Credentials are passed only in child-process environments, never on the command line. The exact `mcp-publisher` syntax should be checked against the installed version before use.

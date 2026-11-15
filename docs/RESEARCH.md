# Standards and packaging research

Consultation date: **2026-11-13 UTC** (facts below were verified on that date). This document separates observed documentation from local checks. Functional test results belong to the project test report.

## MCP revision and compatibility

The [official versioning page](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/docs/2026-07-28/learn/versioning.mdx) identifies **2026-07-28** as the current revision. The [official announcement](https://blog.modelcontextprotocol.io/posts/2026-07-28/) confirms the final release on that date. An older result from the releases page still showed an RC label; it was not used on its own to determine the current revision.

The [compatibility specification](https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/docs/specification/2026-07-28/basic/versioning.mdx) allows supporting current stateless requests and earlier clients that use initialization. Current requests include `params._meta` with `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities`; `clientInfo` is optional. The earlier supported revision is **2025-11-25**. Current responses include `resultType: "complete"`; discovery and list results also include `ttlMs` and `cacheScope`, as in the official schema.

The [stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio) delimits each JSON-RPC message with a newline and reserves stdout for the protocol. [Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) defines `server/discover`; the [tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) defines `tools/list` and `tools/call`. The unsupported-revision error uses `-32022`. Current requests cannot inherit metadata from earlier requests.

## Validation schemas

The [Registry guide](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/server-json/generic-server-json.md) references schema **2025-12-11**, which declares JSON Schema draft-07. The publication schema revision is independent of the MCP revision. The protocol schemas declare draft 2020-12; SARIF 2.1.0, when included, declares draft-04.

The following files were retrieved directly with HTTP 200, parsed as JSON and copied without modification. The SHA-256 hashes are also recorded in `LICENSES.json`. URLs that point at `main` can change; the hashes identify the bytes actually retrieved.

| Local file | HTTP | SHA-256 | Source |
| --- | --- | --- | --- |
| `schemas/mcp-2025-11-25.schema.json` | 200 | `268a5f82ba70fd7e4b6dc4aa1e64f116f74b4d0edcb69dc046829c79dd4e97e7` | [source](https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2025-11-25/schema.json) |
| `schemas/mcp-2026-07-28.schema.json` | 200 | `edbb197ed0f92e90d658866e23cf76f107df0caac5ce25c2b9e64e1ca9a6314a` | [source](https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2026-07-28/schema.json) |
| `schemas/sarif-2.1.0.schema.json` | 200 | `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e` | [source](https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json) |
| `schemas/server-2025-12-11.schema.json` | 200 | `3fba09590c99f61735d234822279f4223fab9e300c0a81e81c91ab62a4114de0` | [source](https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json) |

The MCP repositories are in an Apache-2.0/MIT licensing transition; the full notices are preserved in `schemas/licenses/`. The SARIF schema has its own OASIS terms. These materials are used only for validation and are neither runtime dependencies nor original project code. The npm package excludes the development schemas; the source archive keeps them so that the verification can be repeated.

## Reproducible local validation

```sh
python3 scripts/validate_registry.py
# For a captured result object:
python3 scripts/validate_registry.py result.json --schema mcp-current --definition DiscoverResult
```

The development tool available in this run was `jsonschema` **4.10.3** (MIT), with `attrs` **23.2.0** (MIT) and `pyrsistent` **0.20.0** (MIT). There are zero runtime dependencies. The default tests and application start-up do not import jsonschema. The validator checks schema integrity, selects the declared dialect, refuses external `$ref` references and validates structural constraints. `format` is treated as an annotation, with no additional format validation. Namespace authentication and Registry-specific acceptance rules are not part of this check.

The environment had Python **3.12.3** and Node **24.22.1**. The npm command was not on PATH. npm **12.2.2** was obtained from the [official metadata](https://registry.npmjs.org/npm/12.2.2), its announced SHA-512 integrity was verified and the archive was placed in an ignored development folder. That tool's Node requirement, `^22.22.2 || ^24.15.0 || >=26.0.0`, accepts the observed version. No global installation was made.

ConfigLint supports Node >=22. The npm used only for verification may require a more recent patch release. Python and jsonschema are optional and used only to validate against the official schemas.

## Consultation limitations

The website URL of the versioning page failed in the browsing tool; the corresponding file in the official repository was retrieved and provided the compatibility rules. An old SARIF path under `Schemata/` returned HTTP 404; the path kept is `sarif-2.1/schema/sarif-schema-2.1.0.json`. The old PyPI help URL redirected to the documentation home page; a presumed FAQ URL was unavailable. These failures are not presented as successful checks.

Pages were consulted publicly, without authenticated services. Package or namespace control, name availability, publication acceptance, remote hosting and production authorizations were not verified. Schema validation does not demonstrate full protocol conformance. Channel prices and availability can change; [REGISTRY](REGISTRY.md) records the free channels observed and the suspended services.

## Observed packaging checks

On 2026-11-13, `server.json` passed validation against the pinned official Registry schema (static check). `npm ci --ignore-scripts` and `npm pack --dry-run --ignore-scripts` passed offline with the isolated executable. The package inventory contained 15 files on that date, including all runtime modules and both CLI entry points, with no bundled dependencies, schemas, fixtures or development tools. The inventory has not been re-measured for this documentation revision.

A locally created archive was extracted into an ignored temporary folder. JSON processing through the CLI and MCP discovery passed outside the repository working directory, without NODE_PATH (real run of the packed artefact). The captured DiscoverResult passed the current MCP schema. These checks did not publish the package or use a remote validation service.

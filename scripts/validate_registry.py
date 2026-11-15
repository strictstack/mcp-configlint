"""Offline development validation against pinned, unmodified official schemas."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = {
    "registry": "server-2025-12-11.schema.json",
    "sarif": "sarif-2.1.0.schema.json",
    "mcp-current": "mcp-2026-07-28.schema.json",
    "mcp-legacy": "mcp-2025-11-25.schema.json",
}


PROVISIONAL = re.compile(r"operator-pending|placeholder|provisional|not-owned|unpublished-local-draft", re.IGNORECASE)


def validate_project_metadata(document, root=ROOT):
    """Local coherence of npm and Registry metadata; ownership is only proven at publication."""
    errors = []
    try:
        package = json.loads((root / "package.json").read_text())
        name = document.get("name", "")
        repository = package.get("repository", {})
        repository = repository.get("url", "") if isinstance(repository, dict) else repository
        normalize = lambda value: re.sub(r"(^git\+|\.git$|/$)", "", value or "")
        if package.get("mcpName") != name:
            errors.append("mcp_name_mismatch")
        if not re.fullmatch(r"(io\.github\.[A-Za-z0-9-]+|tech\.strictstack)/" + re.escape(package.get("name", "")), name):
            errors.append("registry_name_invalid")
        if normalize(repository) != normalize(document.get("repository", {}).get("url")):
            errors.append("repository_url_mismatch")
        if package.get("homepage") != document.get("websiteUrl"):
            errors.append("website_url_mismatch")
        npm = [item for item in document.get("packages", []) if item.get("registryType") == "npm"]
        if len(npm) != 1 or npm[0].get("identifier") != package.get("name") or npm[0].get("version") != package.get("version") \
                or document.get("version") != package.get("version"):
            errors.append("package_mismatch")
        if PROVISIONAL.search(json.dumps(document)) or PROVISIONAL.search(json.dumps(package)):
            errors.append("provisional_value_present")
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        errors.append("project_metadata_unreadable_or_invalid")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("document", nargs="?", default=str(ROOT / "server.json"))
    parser.add_argument("--schema", choices=SCHEMAS, default="registry")
    parser.add_argument("--definition", help="Validate one named protocol result/request definition")
    args = parser.parse_args()
    try:
        from jsonschema.validators import validator_for
    except ImportError:
        print("Development dependency jsonschema is required; the application runtime does not require it.", file=sys.stderr)
        return 2
    path = ROOT / "schemas" / SCHEMAS[args.schema]
    if not path.is_file():
        parser.error("Schema is not bundled in this project")
    inventory = json.loads((ROOT / "LICENSES.json").read_text())
    entry = next(item for item in inventory["vendoredValidationArtifacts"] if item["path"] == str(path.relative_to(ROOT)))
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != entry["sha256"]:
        print("Pinned schema checksum mismatch", file=sys.stderr)
        return 2
    schema = json.loads(data)

    def check_local_refs(value):
        if isinstance(value, dict):
            ref = value.get("$ref")
            if isinstance(ref, str) and not ref.startswith("#"):
                raise ValueError("External schema references are disabled")
            for child in value.values():
                check_local_refs(child)
        elif isinstance(value, list):
            for child in value:
                check_local_refs(child)

    check_local_refs(schema)
    if args.definition:
        key = "$defs" if "$defs" in schema else "definitions"
        if args.definition not in schema.get(key, {}):
            parser.error("Unknown definition")
        schema["$ref"] = f"#/{key}/{args.definition}"
    cls = validator_for(schema)
    cls.check_schema(schema)
    document = json.loads(Path(args.document).read_text())
    errors = sorted(cls(schema).iter_errors(document), key=lambda error: str(list(error.path)))
    if errors:
        for error in errors:
            # Do not echo input values: configuration documents can contain credentials.
            print(json.dumps({"valid": False, "keyword": error.validator, "pathDepth": len(error.path)}))
        return 1
    result = {"valid": True, "schema": path.name, "definition": args.definition, "sha256": digest, "formatAssertion": False, "network": False}
    if args.schema == "registry" and not args.definition:
        metadata_errors = validate_project_metadata(document)
        if metadata_errors:
            for code in metadata_errors:
                print(json.dumps({"valid": False, "check": "projectMetadata", "code": code}))
            return 1
        result.update(metadataConsistent=True, provisionalName=False, publicationVerified=False)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

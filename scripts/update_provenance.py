"""Gera o inventário das fixtures sintéticas a partir dos bytes em disco."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
generator = "scripts/generate_fixtures.py" if (ROOT / "pyproject.toml").exists() else "scripts/generate-fixtures.mjs"
entries = []
for directory in ("fixtures", "data", "corpus", "samples", "testdata"):
    for path in sorted((ROOT / directory).rglob("*")):
        if not path.is_file():
            continue
        content = path.read_bytes()
        entries.append({"caminho": path.relative_to(ROOT).as_posix(), "origem": "sintetico",
                        "url": None, "licenca_spdx": "CC0-1.0", "atribuicao": "Fixtures sintéticas MIB, sem dados pessoais.",
                        "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content), "gerador": generator})
inventory = json.loads((ROOT / "LICENSES.json").read_text())
for item in inventory.get("vendoredValidationArtifacts", []):
    path = ROOT / item["path"]
    content = path.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    assert digest == item["sha256"], "Esquema público alterado desde a recolha"
    entries.append({"caminho": item["path"], "origem": "publico", "url": item["upstream"],
                    "licenca_spdx": item["license"], "atribuicao": "Aviso original preservado em " + item["licenseFile"],
                    "sha256": digest, "bytes": len(content), "gerador": "Recolha pública em build-time; bytes sem alterações"})
(ROOT / "DATA_PROVENANCE.json").write_text(json.dumps({"schema": "mib.data-provenance.v1", "entradas": entries},
                                                      ensure_ascii=False, indent=2) + "\n")
print(json.dumps({"ficheiros_inventariados": len(entries), "origens": sorted({item["origem"] for item in entries})}))

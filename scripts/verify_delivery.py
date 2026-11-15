"""Verificações locais de integridade; a certificação QA é externa."""
from datetime import datetime
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def is_strict_utc_timestamp(value):
    """Accept a valid ISO timestamp with whole seconds or microseconds and UTC Z."""
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z",
        value,
    ):
        return False
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return True


def main():
    manifest = json.loads((ROOT / "PRODUCT_MANIFEST.json").read_text())
    provenance = json.loads((ROOT / "DATA_PROVENANCE.json").read_text())
    licenses = json.loads((ROOT / "LICENSES.json").read_text())
    entries = {item["caminho"]: item for item in provenance["entradas"]}
    checks = []


    def check(name, passed):
        checks.append({"criterio": name, "conforme": bool(passed)})


    check("schema_produto", manifest.get("schema") == "mib.onda-a.product.v1")
    check("schema_proveniencia", provenance.get("schema") == "mib.data-provenance.v1")
    check("schema_licencas", licenses.get("schema") == "mib.license-inventory.v1"
          and isinstance(licenses.get("pacotes"), list) and isinstance(licenses.get("pesos"), list))
    for key, entry in entries.items():
        content = (ROOT / key).read_bytes()
        check("digest_inventario:" + key, entry["sha256"] == hashlib.sha256(content).hexdigest()
              and entry["bytes"] == len(content))
    for directory in ("fixtures", "data", "corpus", "samples", "testdata"):
        for path in (ROOT / directory).rglob("*"):
            if not path.is_file():
                continue
            key = path.relative_to(ROOT).as_posix()
            entry = entries.get(key, {})
            content = path.read_bytes()
            check("proveniencia:" + key, entry.get("sha256") == hashlib.sha256(content).hexdigest()
                  and entry.get("bytes") == len(content) and bool(entry.get("licenca_spdx")))
    check("fora_da_raiz_reservada", "_default" not in ROOT.resolve().parts)
    check("sem_symlinks_externos", all(not p.is_symlink() or p.resolve().is_relative_to(ROOT)
                                      for p in ROOT.rglob("*") if ".git" not in p.parts))
    check("modelo_regras", manifest["runtime_modelo"] == "regras")
    check("sem_remotes", not subprocess.check_output(["git", "remote"], cwd=ROOT, text=True).strip())
    receipt = json.loads((ROOT / "CLEANROOM_RECEIPT.json").read_text())
    check("recibo_gerado_em_utc_z", isinstance(receipt, dict)
          and is_strict_utc_timestamp(receipt.get("gerado_em")))
    report = json.loads((ROOT / "TEST_REPORT.json").read_text())
    check("testes_executados_sem_falhas", report["total"] > 0 and report["falhou"] == 0)
    for directory in manifest["diretorios_runtime"]:
        for path in (ROOT / directory).rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            relative = path.relative_to(ROOT).as_posix()
            if relative == manifest["egress"]["ficheiro_politica"]:
                continue
            content = path.read_text(errors="replace")
            check("hosts_apenas_politica:" + relative,
                  not any(host in content for host in manifest["egress"]["deny"]))
    print(json.dumps({"schema": "mib.local-integrity.v1", "checks": checks,
                      "qa": "pendente; gate central não executado"}, ensure_ascii=False, indent=2))
    return 0 if all(x["conforme"] for x in checks) else 1


if __name__ == "__main__":
    sys.exit(main())

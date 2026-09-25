#!/usr/bin/env python3
"""Contract checks for SAKAMOTO-60 Application Protocol Catalog."""

from __future__ import annotations

import csv
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
CATALOG = REPO / "resources/application-protocol-catalog/catalog.tsv"
BASELINE = REPO / "resources/application-protocol-catalog/released-baseline.tsv"
GENERATOR = REPO / "tools/generate_application_protocol_catalog.py"
GENERATED = [
    "app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ApplicationProtocolCatalog.java",
    "src/product/vpp/product_protocol_catalog.h",
    "generated/rust/application_protocol_catalog.rs",
    "docs/api/application-protocol-catalog.schema.json",
]
QDPI_ORDINALS = {
    "dns": 32,
    "http": 67,
    "tls": 199,
    "quic": 2521,
}


def rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8") as handle:
        filtered = [line for line in handle if line.strip() and not line.startswith("#")]
    reader = csv.DictReader(filtered, delimiter="\t",
                            fieldnames=["id", "key", "status", "category",
                                        "migration_aliases", "provider_aliases",
                                        "display_name"])
    return list(reader)


def fail(message: str) -> None:
    raise AssertionError(message)


def test_source_contract() -> None:
    seen_ids: set[int] = set()
    seen_keys: set[str] = set()
    aliases: set[str] = set()
    provider_aliases: set[str] = set()
    for row in rows(CATALOG):
        protocol_id = int(row["id"])
        key = row["key"]
        status = row["status"]
        if protocol_id in seen_ids:
            fail(f"duplicate protocol id {protocol_id}")
        seen_ids.add(protocol_id)
        if key in seen_keys:
            fail(f"duplicate protocol key {key}")
        seen_keys.add(key)
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", key):
            fail(f"key is not lowercase symbolic: {key}")
        if status not in ("active", "reserved"):
            fail(f"unexpected status for {key}: {status}")
        if status == "reserved":
            if row["category"] != "-" or row["migration_aliases"] != "-" or row["provider_aliases"] != "-":
                fail(f"reserved/tombstone entry carries active metadata: {key}")
        else:
            if row["category"] == "-":
                fail(f"active entry has no category: {key}")
        for alias in split(row["migration_aliases"]):
            if ":" in alias:
                fail(f"migration alias must not carry provider prefix: {alias}")
            if alias in seen_keys or alias in aliases:
                fail(f"duplicate migration alias: {alias}")
            aliases.add(alias)
        for alias in split(row["provider_aliases"]):
            if ":" not in alias:
                fail(f"provider alias must carry provider namespace: {alias}")
            if alias in provider_aliases:
                fail(f"duplicate provider alias: {alias}")
            provider_aliases.add(alias)
    for key, ordinal in QDPI_ORDINALS.items():
        actual = next(int(row["id"]) for row in rows(CATALOG) if row["key"] == key)
        if actual == ordinal:
            fail(f"{key} inherited forbidden qDPI/libprotoident ordinal {ordinal}")


def split(value: str) -> list[str]:
    return [] if value == "-" else [part.strip() for part in value.split(",") if part.strip()]


def test_released_mapping_append_only() -> None:
    current = {int(row["id"]): (row["key"], row["status"]) for row in rows(CATALOG)}
    with BASELINE.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip() or line.startswith("#"):
                continue
            protocol_id_s, key, status = line.rstrip("\n").split("\t")
            protocol_id = int(protocol_id_s)
            if protocol_id not in current:
                fail(f"released id disappeared instead of becoming tombstone: {protocol_id}")
            if current[protocol_id] != (key, status):
                fail(f"released mapping changed for {protocol_id}: {current[protocol_id]} != {(key, status)}")


def test_generated_outputs_are_current() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp)
        subprocess.check_call([sys.executable, str(GENERATOR), "--out-root", str(tmp_root)], cwd=REPO)
        for rel in GENERATED:
            expected = tmp_root / rel
            actual = REPO / rel
            if not actual.exists():
                fail(f"missing generated artifact: {rel}")
            if expected.read_text(encoding="utf-8") != actual.read_text(encoding="utf-8"):
                fail(f"generated artifact is stale: {rel}")


def test_schema_and_category_expansion_are_exact_ids() -> None:
    schema = json.loads((REPO / "docs/api/application-protocol-catalog.schema.json").read_text(encoding="utf-8"))
    protocol_keys = schema["properties"]["protocolKey"]["enum"]
    categories = schema["properties"]["category"]["enum"]
    active_keys = [row["key"] for row in rows(CATALOG) if row["status"] == "active"]
    if protocol_keys != active_keys:
        fail("schema protocolKey enum is not the active catalog key list")
    current_categories = sorted({row["category"] for row in rows(CATALOG) if row["status"] == "active"})
    if categories != current_categories:
        fail("schema category enum is not the active category list")
    java = (REPO / GENERATED[0]).read_text(encoding="utf-8")
    if "expandCategory" not in java or "CATEGORY_EXPANSIONS" not in java:
        fail("Java catalog does not expose Apply-time exact category expansion")
    if "BY_PROVIDER_ALIAS" not in java or "byProviderAlias" not in java:
        fail("provider alias mapping is missing or folded into policy identity")


def main() -> None:
    if shutil.which("python3") is None:
        fail("python3 required")
    test_source_contract()
    test_released_mapping_append_only()
    test_generated_outputs_are_current()
    test_schema_and_category_expansion_are_exact_ids()
    print("application protocol catalog contract: PASS")


if __name__ == "__main__":
    main()

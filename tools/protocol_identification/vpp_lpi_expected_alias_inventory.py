#!/usr/bin/env python3
"""Inventory VPP stellar_lpi expected APP_NAME coverage against Sakamoto aliases.

This is a read-only reference-contract tool for SAKAMOTO-61. It reads the
backup VPP expected-result JSON files in place and compares normalized
`APP_NAME` values with the current repo-local Application Protocol Catalog
provider aliases. It does not copy corpus files into this repository and does
not use fork-local VPP numeric APP_ID values as Sakamoto identity.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_REFERENCE_ROOT = Path("/home/js/backup/backup/Git/vpp")
DEFAULT_CORPUS_RELATIVE = Path("test/decoders/stellar_lpi/test_pcap")
CATALOG_RELATIVE = Path("resources/application-protocol-catalog/catalog.tsv")


@dataclass(frozen=True)
class CatalogEntry:
    key: str
    status: str
    provider_aliases: tuple[str, ...]


@dataclass(frozen=True)
class AliasMapping:
    app_name: str
    count: int
    app_provider_alias: str
    catalog_key: str
    catalog_provider_alias: str


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[2]


def normalize_app_name(value: object) -> str:
    return str(value).strip().upper()


def provider_alias_for_app_name(app_name: str) -> str:
    token = app_name.lower()
    token = re.sub(r"[^a-z0-9]+", "-", token)
    token = token.strip("-")
    return f"lpi:{token}"


def parse_catalog(catalog_path: Path) -> tuple[dict[str, CatalogEntry], dict[str, CatalogEntry]]:
    entries_by_key: dict[str, CatalogEntry] = {}
    aliases: dict[str, CatalogEntry] = {}

    with catalog_path.open("r", encoding="utf-8", newline="") as handle:
        rows = csv.reader((line for line in handle if not line.startswith("#")), delimiter="\t")
        for row in rows:
            if not row or len(row) < 7:
                continue
            _id, key, status, _category, _migration_aliases, provider_aliases, _display_name = row[:7]
            alias_tuple = tuple(alias.strip() for alias in provider_aliases.split(",") if alias.strip() and alias != "-")
            entry = CatalogEntry(key=key, status=status, provider_aliases=alias_tuple)
            entries_by_key[key] = entry
            if status == "active":
                for alias in alias_tuple:
                    aliases[alias] = entry

    return entries_by_key, aliases


def canonical_provider_alias(entry: CatalogEntry) -> str:
    key_alias = f"lpi:{entry.key}"
    if key_alias in entry.provider_aliases:
        return key_alias
    return entry.provider_aliases[0] if entry.provider_aliases else "-"


def load_expected_rows(expected_json_paths: Iterable[Path]) -> tuple[list[dict[str, object]], dict[str, list[dict[str, object]]]]:
    rows: list[dict[str, object]] = []
    rows_by_group: dict[str, list[dict[str, object]]] = {}
    for path in sorted(expected_json_paths):
        with path.open("r", encoding="utf-8") as handle:
            group_rows = json.load(handle)
        if not isinstance(group_rows, list):
            raise ValueError(f"expected list at {path}")
        for row in group_rows:
            if not isinstance(row, dict):
                raise ValueError(f"expected object rows at {path}")
        rows.extend(group_rows)
        rows_by_group[path.parent.name] = group_rows
    return rows, rows_by_group


def app_names_from_row(row: dict[str, object]) -> list[str]:
    names = row.get("APP_NAME")
    if names is None:
        return []
    if isinstance(names, list):
        return [normalize_app_name(name) for name in names if str(name).strip()]
    return [normalize_app_name(names)] if str(names).strip() else []


def is_unknown_row(row: dict[str, object]) -> bool:
    return row.get("APP_ID") == "UNKNOWN"


def bool_value(value: bool) -> str:
    return "true" if value else "false"


def print_kv(key: str, value: object) -> None:
    print(f"{key}={value}")


def emit_inventory(repo_root: Path, reference_root: Path, corpus_root: Path, catalog_path: Path) -> int:
    if not reference_root.is_dir():
        print(f"error: missing VPP reference root: {reference_root}", file=sys.stderr)
        return 1
    if not corpus_root.is_dir():
        print(f"error: missing stellar_lpi corpus root: {corpus_root}", file=sys.stderr)
        return 1
    if not catalog_path.is_file():
        print(f"error: missing Application Protocol Catalog TSV: {catalog_path}", file=sys.stderr)
        return 1

    entries_by_key, alias_catalog = parse_catalog(catalog_path)
    expected_json_paths = sorted(corpus_root.glob("*/*.json"))
    rows, rows_by_group = load_expected_rows(expected_json_paths)

    app_counter: Counter[str] = Counter()
    mapped: dict[str, AliasMapping] = {}
    unmapped: Counter[str] = Counter()
    rows_without_app_name = 0
    unknown_rows = 0
    multi_result_rows = 0

    for row in rows:
        names = app_names_from_row(row)
        if not names:
            rows_without_app_name += 1
        if is_unknown_row(row):
            unknown_rows += 1
        if len(names) > 1:
            multi_result_rows += 1
        for name in names:
            app_counter[name] += 1

    for app_name, count in sorted(app_counter.items()):
        app_alias = provider_alias_for_app_name(app_name)
        entry = alias_catalog.get(app_alias)
        if entry is None:
            unmapped[app_name] = count
            continue
        mapped[app_name] = AliasMapping(
            app_name=app_name,
            count=count,
            app_provider_alias=app_alias,
            catalog_key=entry.key,
            catalog_provider_alias=canonical_provider_alias(entry),
        )

    pcap_count = sum(1 for _ in corpus_root.glob("*/*.pcap"))
    group_dirs = sorted(path for path in corpus_root.iterdir() if path.is_dir())

    print_kv("source", reference_root)
    print_kv("corpusRoot", corpus_root)
    print_kv("catalog.source", catalog_path.relative_to(repo_root) if catalog_path.is_relative_to(repo_root) else catalog_path)
    print_kv("policy.copiesExpectedJsonIntoRepo", bool_value(False))
    print_kv("policy.usesVppNumericAppIdsAsSakamotoIds", bool_value(False))
    print_kv("policy.providerAliasesAreAuthoritative", bool_value(True))
    print_kv("groups.count", len(group_dirs))
    print_kv("json.count", len(expected_json_paths))
    print_kv("pcap.count", pcap_count)
    print_kv("total.expectedSessions", len(rows))
    print_kv("total.expectedRowsWithoutAppName", rows_without_app_name)
    print_kv("total.expectedUnknownRows", unknown_rows)
    print_kv("total.expectedMultiResultRows", multi_result_rows)
    print_kv("appNames.uniqueCount", len(app_counter))
    print_kv("appNames.totalOccurrences", sum(app_counter.values()))
    print_kv("catalog.providerAliases.count", len(alias_catalog))
    print_kv("catalog.providerAliases", ",".join(sorted(alias_catalog)) or "-")
    print_kv("mappedAliases.uniqueAppNames", len(mapped))
    print_kv("mappedAliases.totalOccurrences", sum(item.count for item in mapped.values()))
    print_kv("mappedAliases.appNames", ",".join(sorted(mapped)) or "-")
    print_kv("unmappedAppNames.count", len(unmapped))
    print_kv("unmappedAppNames.totalOccurrences", sum(unmapped.values()))
    print_kv("unmappedAppNames", ",".join(sorted(unmapped)) or "-")

    for app_name in sorted(mapped):
        item = mapped[app_name]
        prefix = f"mappedAlias.{app_name}"
        print_kv(f"{prefix}.count", item.count)
        print_kv(f"{prefix}.appProviderAlias", item.app_provider_alias)
        print_kv(f"{prefix}.catalogKey", item.catalog_key)
        print_kv(f"{prefix}.catalogProviderAlias", item.catalog_provider_alias)

    for app_name in sorted(unmapped):
        print_kv(f"unmappedApp.{app_name}.count", unmapped[app_name])
        print_kv(f"unmappedApp.{app_name}.appProviderAlias", provider_alias_for_app_name(app_name))

    for group in sorted(rows_by_group):
        group_rows = rows_by_group[group]
        group_apps: Counter[str] = Counter()
        group_multi_result_rows = 0
        group_rows_without_app = 0
        group_unknown_rows = 0
        for row in group_rows:
            names = app_names_from_row(row)
            if not names:
                group_rows_without_app += 1
            if is_unknown_row(row):
                group_unknown_rows += 1
            if len(names) > 1:
                group_multi_result_rows += 1
            for name in names:
                group_apps[name] += 1
        group_jsons = sorted(path.name for path in (corpus_root / group).glob("*.json"))
        print_kv(f"group.{group}.json", len(group_jsons))
        print_kv(f"group.{group}.expectedJson", ",".join(group_jsons) or "-")
        print_kv(f"group.{group}.expectedSessions", len(group_rows))
        print_kv(f"group.{group}.expectedRowsWithoutAppName", group_rows_without_app)
        print_kv(f"group.{group}.expectedUnknownRows", group_unknown_rows)
        print_kv(f"group.{group}.expectedMultiResultRows", group_multi_result_rows)
        print_kv(f"group.{group}.uniqueAppNames", len(group_apps))
        print_kv(f"group.{group}.expectedApps", ",".join(sorted(group_apps)) or "-")

    # Keep DNS/HTTP/QUIC evidence obvious for grep-based contract tests while
    # still deriving the values above from JSON and the current catalog.
    for required in ("DNS", "HTTP", "QUIC"):
        if required not in mapped:
            print(f"error: required mapped evidence missing: {required}", file=sys.stderr)
            return 1

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reference-root",
        type=Path,
        default=Path(os.environ.get("VPP_REFERENCE_ROOT", DEFAULT_REFERENCE_ROOT)),
        help="backup VPP checkout root",
    )
    parser.add_argument(
        "--corpus-root",
        type=Path,
        default=None,
        help="stellar_lpi test_pcap root; defaults under --reference-root",
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        default=None,
        help="Application Protocol Catalog TSV; defaults to repo resource catalog",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_script()
    reference_root = args.reference_root.resolve()
    corpus_root = (
        args.corpus_root
        or Path(os.environ.get("VPP_LPI_CORPUS_ROOT", reference_root / DEFAULT_CORPUS_RELATIVE))
    ).resolve()
    catalog_path = (args.catalog or repo_root / CATALOG_RELATIVE).resolve()
    return emit_inventory(repo_root, reference_root, corpus_root, catalog_path)


if __name__ == "__main__":
    raise SystemExit(main())

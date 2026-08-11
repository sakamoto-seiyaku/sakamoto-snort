#!/usr/bin/env python3
"""Generate SAKAMOTO Application Protocol Catalog constants from the TSV source."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path


SOURCE = Path("resources/application-protocol-catalog/catalog.tsv")


@dataclass(frozen=True)
class Entry:
    id: int
    key: str
    status: str
    category: str
    migration_aliases: tuple[str, ...]
    provider_aliases: tuple[str, ...]
    display_name: str

    @property
    def const_name(self) -> str:
        return re.sub(r"[^A-Za-z0-9]+", "_", self.key).upper()


def split_list(value: str) -> tuple[str, ...]:
    if value == "-":
        return ()
    return tuple(part.strip() for part in value.split(",") if part.strip())


def parse_catalog(path: Path) -> list[Entry]:
    entries: list[Entry] = []
    ids: set[int] = set()
    keys: set[str] = set()
    aliases: set[str] = set()
    provider_aliases: set[str] = set()
    key_re = re.compile(r"^[a-z0-9][a-z0-9-]*$")
    provider_re = re.compile(r"^[a-z0-9][a-z0-9-]*:[a-z0-9][a-z0-9-]*$")
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 7:
                raise ValueError(f"{path}:{line_no}: expected 7 tab-separated columns")
            entry = Entry(
                id=int(parts[0]),
                key=parts[1],
                status=parts[2],
                category=parts[3],
                migration_aliases=split_list(parts[4]),
                provider_aliases=split_list(parts[5]),
                display_name=parts[6],
            )
            if entry.id in ids:
                raise ValueError(f"{path}:{line_no}: duplicate protocol id {entry.id}")
            ids.add(entry.id)
            if not key_re.match(entry.key):
                raise ValueError(f"{path}:{line_no}: key must be lowercase symbolic")
            if entry.key in keys:
                raise ValueError(f"{path}:{line_no}: duplicate protocol key {entry.key}")
            keys.add(entry.key)
            if entry.status not in ("active", "reserved"):
                raise ValueError(f"{path}:{line_no}: unsupported status {entry.status}")
            if entry.status == "active" and entry.category == "-":
                raise ValueError(f"{path}:{line_no}: active entry must have a category")
            if entry.status == "reserved":
                if entry.category != "-" or entry.migration_aliases or entry.provider_aliases:
                    raise ValueError(f"{path}:{line_no}: reserved entries carry no metadata")
            for alias in entry.migration_aliases:
                if not key_re.match(alias):
                    raise ValueError(f"{path}:{line_no}: migration alias must be lowercase")
                if alias in keys or alias in aliases:
                    raise ValueError(f"{path}:{line_no}: duplicate migration alias {alias}")
                aliases.add(alias)
            for alias in entry.provider_aliases:
                if not provider_re.match(alias):
                    raise ValueError(f"{path}:{line_no}: provider alias must be provider:key")
                if alias in provider_aliases:
                    raise ValueError(f"{path}:{line_no}: duplicate provider alias {alias}")
                provider_aliases.add(alias)
            entries.append(entry)
    return sorted(entries, key=lambda entry: entry.id)


def active(entries: list[Entry]) -> list[Entry]:
    return [entry for entry in entries if entry.status == "active"]


def categories(entries: list[Entry]) -> dict[str, list[Entry]]:
    grouped: dict[str, list[Entry]] = {}
    for entry in active(entries):
        grouped.setdefault(entry.category, []).append(entry)
    return {name: sorted(values, key=lambda entry: entry.id) for name, values in sorted(grouped.items())}


def write_java(entries: list[Entry], out_root: Path) -> None:
    path = out_root / "app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ApplicationProtocolCatalog.java"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [
        "package com.sakamoto.snort.androidruntime;",
        "",
        "import java.util.ArrayList;",
        "import java.util.Collections;",
        "import java.util.LinkedHashMap;",
        "import java.util.List;",
        "import java.util.Map;",
        "",
        "/** Generated from resources/application-protocol-catalog/catalog.tsv. */",
        "public final class ApplicationProtocolCatalog {",
        "    public static final int CATALOG_VERSION = 1;",
        "    private ApplicationProtocolCatalog() {}",
        "",
        "    public static final class Entry {",
        "        public final int id;",
        "        public final String key;",
        "        public final String status;",
        "        public final String category;",
        "        public final String displayName;",
        "",
        "        private Entry(int id, String key, String status, String category, String displayName) {",
        "            this.id = id;",
        "            this.key = key;",
        "            this.status = status;",
        "            this.category = category;",
        "            this.displayName = displayName;",
        "        }",
        "",
        "        public boolean active() {",
        "            return \"active\".equals(status);",
        "        }",
        "    }",
        "",
    ]
    for entry in entries:
        lines.append(f"    public static final int ID_{entry.const_name} = {entry.id};")
    lines.extend([
        "",
        "    private static final Entry[] ENTRIES = new Entry[] {",
    ])
    for entry in entries:
        category = "" if entry.category == "-" else entry.category
        lines.append(
            f"        new Entry({entry.id}, \"{entry.key}\", \"{entry.status}\", "
            f"\"{category}\", \"{entry.display_name}\"),"
        )
    lines.extend([
        "    };",
        "",
        "    private static final Map<String, Entry> BY_KEY = buildByKey();",
        "    private static final Map<String, Entry> BY_MIGRATION_ALIAS = buildMigrationAliases();",
        "    private static final Map<String, Entry> BY_PROVIDER_ALIAS = buildProviderAliases();",
        "    private static final Map<String, List<Integer>> CATEGORY_EXPANSIONS = buildCategories();",
        "",
        "    public static Entry byKey(String key) {",
        "        return BY_KEY.get(key);",
        "    }",
        "",
        "    public static Entry byMigrationAlias(String alias) {",
        "        return BY_MIGRATION_ALIAS.get(alias);",
        "    }",
        "",
        "    public static Entry byProviderAlias(String alias) {",
        "        return BY_PROVIDER_ALIAS.get(alias);",
        "    }",
        "",
        "    public static List<Integer> expandCategory(String category) {",
        "        List<Integer> ids = CATEGORY_EXPANSIONS.get(category);",
        "        return ids == null ? Collections.emptyList() : ids;",
        "    }",
        "",
        "    public static List<Entry> entries() {",
        "        List<Entry> copy = new ArrayList<Entry>();",
        "        Collections.addAll(copy, ENTRIES);",
        "        return Collections.unmodifiableList(copy);",
        "    }",
        "",
        "    private static Map<String, Entry> buildByKey() {",
        "        Map<String, Entry> byKey = new LinkedHashMap<String, Entry>();",
        "        for (Entry entry : ENTRIES) {",
        "            byKey.put(entry.key, entry);",
        "        }",
        "        return Collections.unmodifiableMap(byKey);",
        "    }",
        "",
        "    private static Map<String, Entry> buildMigrationAliases() {",
        "        Map<String, Entry> aliases = new LinkedHashMap<String, Entry>();",
    ])
    for entry in entries:
        for alias in entry.migration_aliases:
            lines.append(f"        aliases.put(\"{alias}\", BY_KEY.get(\"{entry.key}\"));")
    lines.extend([
        "        return Collections.unmodifiableMap(aliases);",
        "    }",
        "",
        "    private static Map<String, Entry> buildProviderAliases() {",
        "        Map<String, Entry> aliases = new LinkedHashMap<String, Entry>();",
    ])
    for entry in entries:
        for alias in entry.provider_aliases:
            lines.append(f"        aliases.put(\"{alias}\", BY_KEY.get(\"{entry.key}\"));")
    lines.extend([
        "        return Collections.unmodifiableMap(aliases);",
        "    }",
        "",
        "    private static Map<String, List<Integer>> buildCategories() {",
        "        Map<String, List<Integer>> categories = new LinkedHashMap<String, List<Integer>>();",
    ])
    for category, values in categories(entries).items():
        ids = ", ".join(str(entry.id) for entry in values)
        lines.append(f"        categories.put(\"{category}\", immutableIds(new int[] {{{ids}}}));")
    lines.extend([
        "        return Collections.unmodifiableMap(categories);",
        "    }",
        "",
        "    private static List<Integer> immutableIds(int[] values) {",
        "        List<Integer> ids = new ArrayList<Integer>();",
        "        for (int value : values) {",
        "            ids.add(Integer.valueOf(value));",
        "        }",
        "        return Collections.unmodifiableList(ids);",
        "    }",
        "}",
        "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def write_cpp(entries: list[Entry], out_root: Path) -> None:
    path = out_root / "src/core/protocol/ApplicationProtocolCatalog.hpp"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "#pragma once",
        "",
        "#include <array>",
        "#include <cstdint>",
        "#include <optional>",
        "#include <string_view>",
        "",
        "namespace sucre::protocol {",
        "",
        "enum class ApplicationProtocolId : std::uint32_t {",
    ]
    for entry in entries:
        lines.append(f"    {entry.const_name} = {entry.id},")
    lines.extend([
        "};",
        "",
        "struct ApplicationProtocolEntry {",
        "    ApplicationProtocolId id;",
        "    std::string_view key;",
        "    std::string_view status;",
        "    std::string_view category;",
        "};",
        "",
        "struct ApplicationProtocolProviderAlias {",
        "    std::string_view alias;",
        "    ApplicationProtocolId id;",
        "};",
        "",
        "inline constexpr std::uint32_t kApplicationProtocolCatalogVersion = 1;",
        "inline constexpr std::array<ApplicationProtocolEntry, %d> kApplicationProtocolCatalog = {{"
        % len(entries),
    ])
    for entry in entries:
        category = "" if entry.category == "-" else entry.category
        lines.append(
            f"    {{ApplicationProtocolId::{entry.const_name}, \"{entry.key}\", "
            f"\"{entry.status}\", \"{category}\"}},"
        )
    lines.extend([
        "}};",
        "",
        "inline constexpr std::array<ApplicationProtocolProviderAlias, %d>"
        % sum(len(entry.provider_aliases) for entry in entries),
        "    kApplicationProtocolProviderAliases = {{",
    ])
    for entry in entries:
        for alias in entry.provider_aliases:
            lines.append(
                f"        {{\"{alias}\", ApplicationProtocolId::{entry.const_name}}},"
            )
    lines.extend([
        "    }};",
        "",
        "inline constexpr std::string_view applicationProtocolKey(ApplicationProtocolId id) {",
        "    for (const auto &entry : kApplicationProtocolCatalog) {",
        "        if (entry.id == id) {",
        "            return entry.key;",
        "        }",
        "    }",
        "    return {};",
        "}",
        "",
        "inline constexpr std::string_view applicationProtocolCategory(ApplicationProtocolId id) {",
        "    for (const auto &entry : kApplicationProtocolCatalog) {",
        "        if (entry.id == id) {",
        "            return entry.category;",
        "        }",
        "    }",
        "    return {};",
        "}",
        "",
        "inline constexpr std::optional<ApplicationProtocolId>",
        "applicationProtocolIdForProviderAlias(std::string_view alias) {",
        "    for (const auto &entry : kApplicationProtocolProviderAliases) {",
        "        if (entry.alias == alias) {",
        "            return entry.id;",
        "        }",
        "    }",
        "    return std::nullopt;",
        "}",
        "",
        "inline constexpr bool applicationProtocolIsActive(ApplicationProtocolId id) {",
        "    for (const auto &entry : kApplicationProtocolCatalog) {",
        "        if (entry.id == id) {",
        "            return entry.status == std::string_view{\"active\"};",
        "        }",
        "    }",
        "    return false;",
        "}",
        "",
        "} // namespace sucre::protocol",
        "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def write_rust(entries: list[Entry], out_root: Path) -> None:
    path = out_root / "generated/rust/application_protocol_catalog.rs"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "// Generated from resources/application-protocol-catalog/catalog.tsv.",
        "",
        "pub const APPLICATION_PROTOCOL_CATALOG_VERSION: u32 = 1;",
        "",
    ]
    for entry in entries:
        lines.append(f"pub const APPLICATION_PROTOCOL_ID_{entry.const_name}: u32 = {entry.id};")
    lines.extend([
        "",
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
        "pub struct ApplicationProtocolEntry {",
        "    pub id: u32,",
        "    pub key: &'static str,",
        "    pub status: &'static str,",
        "    pub category: &'static str,",
        "}",
        "",
        "pub const APPLICATION_PROTOCOL_CATALOG: &[ApplicationProtocolEntry] = &[",
    ])
    for entry in entries:
        category = "" if entry.category == "-" else entry.category
        lines.append(
            f"    ApplicationProtocolEntry {{ id: {entry.id}, key: \"{entry.key}\", "
            f"status: \"{entry.status}\", category: \"{category}\" }},"
        )
    lines.extend([
        "];",
        "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def write_schema(entries: list[Entry], out_root: Path) -> None:
    path = out_root / "docs/api/application-protocol-catalog.schema.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    keys = [entry.key for entry in active(entries)]
    cats = list(categories(entries).keys())
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://sakamoto.local/schema/application-protocol-catalog.v1.json",
        "title": "Sakamoto Application Protocol Catalog v1",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "protocolKey": {
                "type": "string",
                "enum": keys,
                "description": "Stable ApplicationProtocolKey used by authoring/import/export/API.",
            },
            "category": {
                "type": "string",
                "enum": cats,
                "description": "Authoring/presentation selector expanded to exact protocol IDs at Apply.",
            },
        },
        "oneOf": [{"required": ["protocolKey"]}, {"required": ["category"]}],
    }
    path.write_text(json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_all(entries: list[Entry], out_root: Path) -> None:
    write_java(entries, out_root)
    write_cpp(entries, out_root)
    write_rust(entries, out_root)
    write_schema(entries, out_root)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default=str(SOURCE))
    parser.add_argument("--out-root", default=".")
    args = parser.parse_args()
    write_all(parse_catalog(Path(args.source)), Path(args.out_root))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Reject hidden java.lang.Process APIs in Android DEX output.

The Android SDK stubs shipped in some platform trees contain hidden/future
methods on java.lang.Process.  A javac API-surface check therefore has to be
backed by an inspection of the method/type references that D8 emitted.  This
small verifier reads the DEX ID tables directly so it does not depend on an
optional dexdump/baksmali installation and can inspect either a raw .dex file
or every classes*.dex entry in an APK.
"""

from __future__ import annotations

import struct
import sys
import zipfile
from pathlib import Path


PROCESS_DESCRIPTOR = "Ljava/lang/Process;"
PROCESS_HANDLE_PREFIX = "Ljava/lang/ProcessHandle"
DEX_HEADER_SIZE = 112
DEX_ENDIAN_CONSTANT = 0x12345678
DEX_VERSIONS = frozenset(
    f"{version:03d}".encode("ascii") for version in range(35, 42)
)


class DexError(Exception):
    """Raised when an input is not a readable DEX file."""


def u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise DexError(f"u16 offset outside DEX: {offset}")
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise DexError(f"u32 offset outside DEX: {offset}")
    return struct.unpack_from("<I", data, offset)[0]


def read_uleb128(
    data: bytes, offset: int, limit: int | None = None
) -> tuple[int, int]:
    if limit is None:
        limit = len(data)
    value = 0
    shift = 0
    for _ in range(5):
        if offset < 0 or offset >= limit or offset >= len(data):
            raise DexError("truncated ULEB128")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return value, offset
        shift += 7
    raise DexError("invalid ULEB128")


def read_string(data: bytes, offset: int, data_end: int) -> str:
    if offset < 0 or offset >= data_end:
        raise DexError(f"DEX string data offset is outside the data section: {offset}")
    _, cursor = read_uleb128(data, offset, data_end)
    end = data.find(b"\0", cursor, data_end)
    if end < 0:
        raise DexError("unterminated DEX string")
    # Descriptors and method names relevant to this check are ASCII.  Keep
    # malformed unrelated strings readable without hiding a forbidden name.
    return data[cursor:end].decode("utf-8", errors="replace")


def checked_range(
    offset: int,
    size: int,
    file_size: int,
    label: str,
    *,
    minimum_offset: int = DEX_HEADER_SIZE,
) -> int:
    """Return the end of a bounded DEX region, or fail closed."""
    if size < 0 or offset < 0 or offset > file_size:
        raise DexError(f"DEX {label} offset is outside the file: {offset}")
    if size == 0:
        return offset
    if offset < minimum_offset:
        raise DexError(f"DEX {label} overlaps the header: {offset}")
    if size > file_size - offset:
        raise DexError(f"DEX {label} is outside the file")
    return offset + size


def checked_table(
    data: bytes,
    count_offset: int,
    table_offset: int,
    item_size: int,
    label: str,
) -> tuple[int, int]:
    count = u32(data, count_offset)
    offset = u32(data, table_offset)
    if count == 0 and offset != 0:
        raise DexError(
            f"DEX {label} ID table offset must be zero when empty"
        )
    size = count * item_size
    end = checked_range(offset, size, len(data), f"{label} ID table")
    return count, end


def dex_header(data: bytes) -> dict[str, int]:
    """Validate the fixed DEX header before following any offsets."""
    if len(data) < DEX_HEADER_SIZE:
        raise DexError("truncated DEX header")
    magic = data[:8]
    if magic[:4] != b"dex\n" or magic[7] != 0:
        raise DexError("input does not have a DEX header")
    version = magic[4:7]
    if version not in DEX_VERSIONS:
        raise DexError(f"unsupported DEX version: {version!r}")

    file_size = u32(data, 32)
    if file_size != len(data):
        raise DexError(
            f"DEX file_size {file_size} does not match actual length {len(data)}"
        )
    header_size = u32(data, 36)
    if header_size != DEX_HEADER_SIZE:
        raise DexError(f"unsupported DEX header_size: {header_size}")
    endian_tag = u32(data, 40)
    if endian_tag != DEX_ENDIAN_CONSTANT:
        if endian_tag == 0x78563412:
            raise DexError("reverse-endian DEX is not supported")
        raise DexError(f"invalid DEX endian_tag: 0x{endian_tag:08x}")

    link_size = u32(data, 44)
    link_offset = u32(data, 48)
    if link_size == 0 and link_offset != 0:
        raise DexError("DEX link section offset must be zero when empty")
    checked_range(link_offset, link_size, file_size, "link section")

    map_offset = u32(data, 52)
    string_count, _ = checked_table(data, 56, 60, 4, "string")
    type_count, _ = checked_table(data, 64, 68, 4, "type")
    proto_count, _ = checked_table(data, 72, 76, 12, "proto")
    field_count, _ = checked_table(data, 80, 84, 8, "field")
    method_count, _ = checked_table(data, 88, 92, 8, "method")
    class_count, _ = checked_table(data, 96, 100, 32, "class definition")

    data_size = u32(data, 104)
    data_offset = u32(data, 108)
    if data_size == 0:
        raise DexError("DEX data section is missing")
    data_end = checked_range(data_offset, data_size, file_size, "data section")
    if not map_offset or not data_offset <= map_offset < data_end:
        raise DexError("DEX map_list offset is outside the data section")
    map_size_end = checked_range(
        map_offset, 4, data_end, "map_list header", minimum_offset=data_offset
    )
    map_count = u32(data, map_offset)
    checked_range(
        map_size_end,
        map_count * 12,
        data_end,
        "map_list entries",
        minimum_offset=data_offset,
    )

    return {
        "string_count": string_count,
        "string_offset": u32(data, 60),
        "type_count": type_count,
        "type_offset": u32(data, 68),
        "proto_count": proto_count,
        "proto_offset": u32(data, 76),
        "field_count": field_count,
        "field_offset": u32(data, 84),
        "method_count": method_count,
        "method_offset": u32(data, 92),
        "class_count": class_count,
        "class_offset": u32(data, 100),
        "data_offset": data_offset,
        "data_end": data_end,
    }


def dex_strings(data: bytes, header: dict[str, int]) -> list[str]:
    string_count = header["string_count"]
    string_offset = header["string_offset"]
    offsets_end = checked_range(
        string_offset,
        string_count * 4,
        len(data),
        "string ID table",
    )
    del offsets_end
    offsets = [u32(data, string_offset + index * 4) for index in range(string_count)]
    return [read_string(data, offset, header["data_end"]) for offset in offsets]


def strip_array_prefix(descriptor: str) -> str:
    """Normalize every array dimension before checking a type descriptor."""
    while descriptor.startswith("["):
        descriptor = descriptor[1:]
    return descriptor


def is_forbidden_process_handle(descriptor: str) -> bool:
    normalized = strip_array_prefix(descriptor)
    # Keep this conservative: ProcessHandle itself, nested classes, and names
    # in the same class family are unsupported on the Android public surface.
    return normalized.startswith(PROCESS_HANDLE_PREFIX)


def validate_type_list(
    data: bytes, offset: int, header: dict[str, int], label: str
) -> list[int]:
    if offset == 0:
        return []
    if offset < header["data_offset"] or offset >= header["data_end"]:
        raise DexError(f"DEX {label} offset is outside the data section")
    count = u32(data, offset)
    start = offset + 4
    end = checked_range(
        start,
        count * 2,
        header["data_end"],
        f"{label} entries",
        minimum_offset=header["data_offset"],
    )
    del end
    values = [u16(data, start + index * 2) for index in range(count)]
    for value in values:
        if value >= header["type_count"]:
            raise DexError(f"DEX {label} type index is invalid")
    return values


def forbidden_references(data: bytes) -> list[str]:
    header = dex_header(data)
    strings = dex_strings(data, header)

    type_count = header["type_count"]
    type_offset = header["type_offset"]
    type_descriptors: list[str] = []
    for index in range(type_count):
        string_index = u32(data, type_offset + index * 4)
        if string_index >= len(strings):
            raise DexError("DEX type ID string index is invalid")
        type_descriptors.append(strings[string_index])

    findings: list[str] = []
    for descriptor in type_descriptors:
        if is_forbidden_process_handle(descriptor):
            findings.append(f"type {descriptor}")

    proto_count = header["proto_count"]
    proto_offset = header["proto_offset"]
    proto_returns: list[str] = []
    for index in range(proto_count):
        entry = proto_offset + index * 12
        return_type = u32(data, entry + 4)
        parameters_offset = u32(data, entry + 8)
        if return_type >= len(type_descriptors):
            raise DexError("DEX proto return type index is invalid")
        proto_returns.append(type_descriptors[return_type])
        if parameters_offset == 0:
            continue
        validate_type_list(data, parameters_offset, header, "proto parameter list")

    # This checker intentionally works at DEX ID-table level.  It does not
    # parse code_item/invoke instructions: any unsupported method/type ID in
    # the final DEX is rejected conservatively, including definition-only
    # fixtures.  That is the acceptance policy, not a parser limitation.
    method_count = header["method_count"]
    method_offset = header["method_offset"]
    for index in range(method_count):
        entry = method_offset + index * 8
        class_index = u16(data, entry)
        proto_index = u16(data, entry + 2)
        name_index = u32(data, entry + 4)
        if class_index >= len(type_descriptors) or proto_index >= len(proto_returns):
            raise DexError("DEX method ID index is invalid")
        if name_index >= len(strings):
            raise DexError("DEX method ID name index is invalid")
        name = strings[name_index]
        descriptor = type_descriptors[class_index]
        if descriptor == PROCESS_DESCRIPTOR and name == "pid":
            findings.append("method java/lang/Process.pid")
        if descriptor == PROCESS_DESCRIPTOR and name == "toHandle":
            findings.append("method java/lang/Process.toHandle")

    field_count = header["field_count"]
    field_offset = header["field_offset"]
    for index in range(field_count):
        entry = field_offset + index * 8
        class_index = u16(data, entry)
        type_index = u16(data, entry + 2)
        name_index = u32(data, entry + 4)
        if class_index >= len(type_descriptors) or type_index >= len(type_descriptors):
            raise DexError("DEX field ID type index is invalid")
        if name_index >= len(strings):
            raise DexError("DEX field ID name index is invalid")

    class_count = header["class_count"]
    class_offset = header["class_offset"]
    for index in range(class_count):
        entry = class_offset + index * 32
        class_index = u32(data, entry)
        superclass_index = u32(data, entry + 8)
        interfaces_offset = u32(data, entry + 12)
        source_file_index = u32(data, entry + 16)
        annotations_offset = u32(data, entry + 20)
        class_data_offset = u32(data, entry + 24)
        static_values_offset = u32(data, entry + 28)
        if class_index >= len(type_descriptors):
            raise DexError("DEX class definition type index is invalid")
        if superclass_index != 0xFFFFFFFF and superclass_index >= len(type_descriptors):
            raise DexError("DEX class definition superclass index is invalid")
        if source_file_index != 0xFFFFFFFF and source_file_index >= len(strings):
            raise DexError("DEX class definition source string index is invalid")
        validate_type_list(data, interfaces_offset, header, "class interface list")
        for label, offset in (
            ("class annotations", annotations_offset),
            ("class data", class_data_offset),
            ("class static values", static_values_offset),
        ):
            if offset and not header["data_offset"] <= offset < header["data_end"]:
                raise DexError(f"DEX {label} offset is outside the data section")

    return sorted(set(findings))


def dex_inputs(path: Path) -> list[tuple[str, bytes]]:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            names = sorted(name for name in archive.namelist()
                           if name == "classes.dex" or
                           (name.startswith("classes") and name.endswith(".dex")))
            if not names:
                raise DexError(f"APK has no classes*.dex entries: {path}")
            return [(name, archive.read(name)) for name in names]
    return [(path.name, path.read_bytes())]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <classes.dex|apk>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    try:
        inputs = dex_inputs(path)
        findings: list[str] = []
        for name, data in inputs:
            findings.extend(f"{name}: {finding}"
                            for finding in forbidden_references(data))
    except (OSError, zipfile.BadZipFile, DexError, IndexError) as error:
        print(f"Android Process API gate: ERROR: {error}", file=sys.stderr)
        return 2
    if findings:
        print("Android Process API gate: FAIL: unsupported references detected:",
              file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(f"Android Process API gate: PASS: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

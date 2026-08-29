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


def read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(5):
        if offset >= len(data):
            raise DexError("truncated ULEB128")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, offset
        shift += 7
    raise DexError("invalid ULEB128")


def read_string(data: bytes, offset: int) -> str:
    _, cursor = read_uleb128(data, offset)
    end = data.find(b"\0", cursor)
    if end < 0:
        raise DexError("unterminated DEX string")
    # Descriptors and method names relevant to this check are ASCII.  Keep
    # malformed unrelated strings readable without hiding a forbidden name.
    return data[cursor:end].decode("utf-8", errors="replace")


def dex_strings(data: bytes) -> list[str]:
    if len(data) < 112 or data[:4] != b"dex\n" or data[7] != 0:
        raise DexError("input does not have a DEX header")
    string_count = u32(data, 56)
    string_offset = u32(data, 60)
    end = string_offset + string_count * 4
    if string_offset > len(data) or end > len(data):
        raise DexError("DEX string ID table is outside the file")
    offsets = [u32(data, string_offset + index * 4) for index in range(string_count)]
    return [read_string(data, offset) for offset in offsets]


def forbidden_references(data: bytes) -> list[str]:
    strings = dex_strings(data)

    type_count = u32(data, 64)
    type_offset = u32(data, 68)
    type_end = type_offset + type_count * 4
    if type_offset > len(data) or type_end > len(data):
        raise DexError("DEX type ID table is outside the file")
    type_descriptors = [strings[u32(data, type_offset + index * 4)]
                        for index in range(type_count)]

    findings: list[str] = []
    for descriptor in type_descriptors:
        if descriptor.startswith(PROCESS_HANDLE_PREFIX):
            findings.append(f"type {descriptor}")

    proto_count = u32(data, 72)
    proto_offset = u32(data, 76)
    proto_end = proto_offset + proto_count * 12
    if proto_offset > len(data) or proto_end > len(data):
        raise DexError("DEX proto ID table is outside the file")
    proto_returns: list[str] = []
    proto_parameters: list[tuple[str, ...]] = []
    for index in range(proto_count):
        entry = proto_offset + index * 12
        return_type = u32(data, entry + 4)
        parameters_offset = u32(data, entry + 8)
        if return_type >= len(type_descriptors):
            raise DexError("DEX proto return type index is invalid")
        proto_returns.append(type_descriptors[return_type])
        if parameters_offset == 0:
            proto_parameters.append(())
            continue
        parameter_count = u32(data, parameters_offset)
        parameter_start = parameters_offset + 4
        parameter_end = parameter_start + parameter_count * 2
        if parameter_end > len(data):
            raise DexError("DEX proto parameter list is outside the file")
        parameters: list[str] = []
        for parameter_index in range(parameter_count):
            parameter_type = u16(data, parameter_start + parameter_index * 2)
            if parameter_type >= len(type_descriptors):
                raise DexError("DEX proto parameter type index is invalid")
            parameters.append(type_descriptors[parameter_type])
        proto_parameters.append(tuple(parameters))

    method_count = u32(data, 88)
    method_offset = u32(data, 92)
    method_end = method_offset + method_count * 8
    if method_offset > len(data) or method_end > len(data):
        raise DexError("DEX method ID table is outside the file")
    for index in range(method_count):
        entry = method_offset + index * 8
        class_index = u16(data, entry)
        proto_index = u16(data, entry + 2)
        name_index = u32(data, entry + 4)
        if class_index >= len(type_descriptors) or proto_index >= len(proto_returns):
            raise DexError("DEX method ID index is invalid")
        name = strings[name_index]
        descriptor = type_descriptors[class_index]
        if descriptor == PROCESS_DESCRIPTOR and name == "pid":
            if proto_returns[proto_index] == "J" and not proto_parameters[proto_index]:
                findings.append("method java/lang/Process.pid:()J")
        if descriptor == PROCESS_DESCRIPTOR and name == "toHandle":
            findings.append("method java/lang/Process.toHandle")
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

/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <sys/stat.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace PackageState {

constexpr uint32_t kAidAppStart = 10000;
constexpr uint32_t kAidUserOffset = 100000;

struct PackagesListSnapshot {
    std::unordered_map<std::string, uint32_t> packageToAppId;
    std::unordered_map<uint32_t, std::vector<std::string>> appIdToNames;
};

struct PackageRestrictionsSnapshot {
    std::unordered_set<std::string> installedPackages;
};

inline bool isValidPackageName(std::string_view name);

namespace detail {

inline constexpr size_t kMaxPackagesListBytes = 16 * 1024 * 1024;
inline constexpr size_t kMaxPackageRestrictionsBytes = 16 * 1024 * 1024;
inline constexpr size_t kMaxPackageNameBytes = 256;

inline bool statFileSize(const char *path, size_t &outSize, std::string *error) {
    struct stat st {};
    if (stat(path, &st) != 0) {
        if (error) {
            *error = std::string("stat failed: ") + std::strerror(errno);
        }
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        if (error) {
            *error = "not a regular file";
        }
        return false;
    }
    if (st.st_size < 0) {
        if (error) {
            *error = "negative size";
        }
        return false;
    }
    outSize = static_cast<size_t>(st.st_size);
    return true;
}

inline bool readFileToStringLimited(const char *path, const size_t maxBytes, std::string &out,
                                    std::string *error) {
    size_t size = 0;
    if (!statFileSize(path, size, error)) {
        return false;
    }
    if (size > maxBytes) {
        if (error) {
            *error = "file too large";
        }
        return false;
    }

    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in.is_open()) {
        if (error) {
            *error = std::string("open failed: ") + std::strerror(errno);
        }
        return false;
    }

    out.assign(size, '\0');
    if (size > 0) {
        in.read(out.data(), static_cast<std::streamsize>(size));
        if (in.gcount() != static_cast<std::streamsize>(size)) {
            if (error) {
                *error = "short read";
            }
            return false;
        }
    }
    return true;
}

inline bool parseDecimalU32(const std::string_view token, uint32_t &out) {
    if (token.empty() || token.size() > 10) {
        return false;
    }
    uint64_t value = 0;
    for (const char ch : token) {
        if (ch < '0' || ch > '9') {
            return false;
        }
        value = value * 10 + static_cast<uint64_t>(ch - '0');
        if (value > std::numeric_limits<uint32_t>::max()) {
            return false;
        }
    }
    out = static_cast<uint32_t>(value);
    return true;
}

inline bool parseXmlBool(const std::string_view value, const bool defaultValue) {
    if (value == "true" || value == "1") {
        return true;
    }
    if (value == "false" || value == "0") {
        return false;
    }
    return defaultValue;
}

struct AttrView {
    std::string_view name;
    std::string_view value;
};

inline std::string hexPrefix(const std::string_view data, const size_t maxBytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    const size_t n = std::min(data.size(), maxBytes);
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(data[i]);
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 0x0f]);
    }
    return out;
}

inline std::string asciiPrefix(const std::string_view data, const size_t maxBytes) {
    const size_t n = std::min(data.size(), maxBytes);
    std::string out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(data[i]);
        if (c >= 32 && c < 127 && c != '"' && c != '\\') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('.');
        }
    }
    return out;
}

inline bool parseNextXmlAttr(const std::string_view s, size_t &pos, AttrView &out) {
    const size_t n = s.size();
    while (pos < n) {
        const unsigned char c = static_cast<unsigned char>(s[pos]);
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            ++pos;
            continue;
        }
        break;
    }
    if (pos >= n) {
        return false;
    }

    const size_t nameStart = pos;
    while (pos < n) {
        const unsigned char c = static_cast<unsigned char>(s[pos]);
        const bool isNameChar = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                (c >= '0' && c <= '9') || c == '_' || c == ':' || c == '-';
        if (!isNameChar) {
            break;
        }
        ++pos;
    }
    if (pos == nameStart) {
        return false;
    }
    const std::string_view attrName = s.substr(nameStart, pos - nameStart);

    while (pos < n) {
        const unsigned char c = static_cast<unsigned char>(s[pos]);
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            ++pos;
            continue;
        }
        break;
    }
    if (pos >= n || s[pos] != '=') {
        return false;
    }
    ++pos;

    while (pos < n) {
        const unsigned char c = static_cast<unsigned char>(s[pos]);
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            ++pos;
            continue;
        }
        break;
    }
    if (pos >= n) {
        return false;
    }

    const char quote = s[pos];
    if (quote != '"' && quote != '\'') {
        return false;
    }
    ++pos;

    const size_t valueStart = pos;
    while (pos < n && s[pos] != quote) {
        ++pos;
    }
    if (pos >= n) {
        return false;
    }
    const std::string_view attrValue = s.substr(valueStart, pos - valueStart);
    ++pos;

    out = AttrView{attrName, attrValue};
    return true;
}

inline bool decodeModifiedUtf8(const std::string_view in, std::string &out, std::string *error) {
    out.clear();
    out.reserve(in.size());

    size_t i = 0;
    while (i < in.size()) {
        const unsigned char a = static_cast<unsigned char>(in[i++]);
        uint16_t ch = 0;
        if (a < 0x80) {
            ch = a;
        } else if ((a & 0xe0) == 0xc0) {
            if (i >= in.size()) {
                if (error) {
                    *error = "bad second byte at end";
                }
                return false;
            }
            const unsigned char b = static_cast<unsigned char>(in[i++]);
            if ((b & 0xc0) != 0x80) {
                if (error) {
                    *error = "bad second byte";
                }
                return false;
            }
            ch = static_cast<uint16_t>(((a & 0x1f) << 6) | (b & 0x3f));
        } else if ((a & 0xf0) == 0xe0) {
            if (i + 1 >= in.size()) {
                if (error) {
                    *error = "bad third byte at end";
                }
                return false;
            }
            const unsigned char b = static_cast<unsigned char>(in[i++]);
            const unsigned char c = static_cast<unsigned char>(in[i++]);
            if ((b & 0xc0) != 0x80 || (c & 0xc0) != 0x80) {
                if (error) {
                    *error = "bad second or third byte";
                }
                return false;
            }
            ch = static_cast<uint16_t>(((a & 0x0f) << 12) | ((b & 0x3f) << 6) | (c & 0x3f));
        } else {
            if (error) {
                *error = "bad byte";
            }
            return false;
        }

        if (ch < 0x80) {
            out.push_back(static_cast<char>(ch));
        } else if (ch < 0x800) {
            out.push_back(static_cast<char>(0xc0 | ((ch >> 6) & 0x1f)));
            out.push_back(static_cast<char>(0x80 | (ch & 0x3f)));
        } else {
            out.push_back(static_cast<char>(0xe0 | ((ch >> 12) & 0x0f)));
            out.push_back(static_cast<char>(0x80 | ((ch >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (ch & 0x3f)));
        }
    }
    return true;
}

struct AbxReader {
    const unsigned char *pos = nullptr;
    const unsigned char *end = nullptr;
    std::vector<std::string> interned;

    explicit AbxReader(const std::string_view data)
        : pos(reinterpret_cast<const unsigned char *>(data.data())),
          end(reinterpret_cast<const unsigned char *>(data.data()) + data.size()) {
        interned.reserve(32);
    }

    [[nodiscard]] size_t remaining() const {
        return pos <= end ? static_cast<size_t>(end - pos) : 0u;
    }

    bool skip(const size_t bytes, std::string *error) {
        if (remaining() < bytes) {
            if (error) {
                *error = "unexpected EOF";
            }
            return false;
        }
        pos += bytes;
        return true;
    }

    bool readU8(uint8_t &out, std::string *error) {
        if (remaining() < 1) {
            if (error) {
                *error = "unexpected EOF";
            }
            return false;
        }
        out = *pos++;
        return true;
    }

    bool peekU8(uint8_t &out) const {
        if (remaining() < 1) {
            return false;
        }
        out = *pos;
        return true;
    }

    bool readU16(uint16_t &out, std::string *error) {
        if (remaining() < 2) {
            if (error) {
                *error = "unexpected EOF";
            }
            return false;
        }
        out = static_cast<uint16_t>((static_cast<uint16_t>(pos[0]) << 8) |
                                    static_cast<uint16_t>(pos[1]));
        pos += 2;
        return true;
    }

    bool readI32(int32_t &out, std::string *error) {
        if (remaining() < 4) {
            if (error) {
                *error = "unexpected EOF";
            }
            return false;
        }
        const uint32_t value = (static_cast<uint32_t>(pos[0]) << 24) |
                               (static_cast<uint32_t>(pos[1]) << 16) |
                               (static_cast<uint32_t>(pos[2]) << 8) |
                               static_cast<uint32_t>(pos[3]);
        out = static_cast<int32_t>(value);
        pos += 4;
        return true;
    }

    bool readI64(int64_t &out, std::string *error) {
        if (remaining() < 8) {
            if (error) {
                *error = "unexpected EOF";
            }
            return false;
        }
        const uint64_t hi = (static_cast<uint64_t>(pos[0]) << 24) |
                            (static_cast<uint64_t>(pos[1]) << 16) |
                            (static_cast<uint64_t>(pos[2]) << 8) | static_cast<uint64_t>(pos[3]);
        const uint64_t lo = (static_cast<uint64_t>(pos[4]) << 24) |
                            (static_cast<uint64_t>(pos[5]) << 16) |
                            (static_cast<uint64_t>(pos[6]) << 8) | static_cast<uint64_t>(pos[7]);
        out = static_cast<int64_t>((hi << 32) | lo);
        pos += 8;
        return true;
    }

    bool readUtf(std::string &out, std::string *error) {
        uint16_t len = 0;
        if (!readU16(len, error)) {
            return false;
        }
        if (remaining() < len) {
            if (error) {
                *error = "unexpected EOF";
            }
            return false;
        }
        const std::string_view bytes{reinterpret_cast<const char *>(pos), len};
        pos += len;
        std::string decodeError;
        if (!decodeModifiedUtf8(bytes, out, &decodeError)) {
            if (error) {
                *error = std::string("invalid modified-utf8: ") + decodeError;
            }
            return false;
        }
        return true;
    }

    bool readInternedUtf(std::string &out, std::string *error) {
        uint16_t ref = 0;
        if (!readU16(ref, error)) {
            return false;
        }

        if (ref == 0xffff) {
            std::string s;
            if (!readUtf(s, error)) {
                return false;
            }
            if (interned.size() < 0xffff) {
                interned.emplace_back(s);
            }
            out = std::move(s);
            return true;
        }

        if (ref >= interned.size()) {
            if (error) {
                *error = "invalid interned string reference";
            }
            return false;
        }
        out = interned[ref];
        return true;
    }
};

inline bool isAbxData(const std::string_view data) {
    static constexpr unsigned char kMagic[4] = {0x41, 0x42, 0x58, 0x00}; // "ABX\0"
    return data.size() >= sizeof(kMagic) && std::memcmp(data.data(), kMagic, sizeof(kMagic)) == 0;
}

inline bool abxReadPossiblyInternedText(AbxReader &r, const uint8_t type, std::string &out,
                                       std::string *error) {
    constexpr uint8_t TYPE_NULL = 1 << 4;
    constexpr uint8_t TYPE_STRING = 2 << 4;
    constexpr uint8_t TYPE_STRING_INTERNED = 3 << 4;
    if (type == TYPE_STRING_INTERNED) {
        return r.readInternedUtf(out, error);
    }
    if (type == TYPE_STRING) {
        return r.readUtf(out, error);
    }
    if (type == TYPE_NULL) {
        out.clear();
        return true;
    }
    if (error) {
        *error = "unexpected type for text";
    }
    return false;
}

inline bool abxSkipValue(AbxReader &r, const uint8_t type, std::string *error) {
    constexpr uint8_t TYPE_NULL = 1 << 4;
    constexpr uint8_t TYPE_STRING = 2 << 4;
    constexpr uint8_t TYPE_STRING_INTERNED = 3 << 4;
    constexpr uint8_t TYPE_BYTES_HEX = 4 << 4;
    constexpr uint8_t TYPE_BYTES_BASE64 = 5 << 4;
    constexpr uint8_t TYPE_INT = 6 << 4;
    constexpr uint8_t TYPE_INT_HEX = 7 << 4;
    constexpr uint8_t TYPE_LONG = 8 << 4;
    constexpr uint8_t TYPE_LONG_HEX = 9 << 4;
    constexpr uint8_t TYPE_FLOAT = 10 << 4;
    constexpr uint8_t TYPE_DOUBLE = 11 << 4;
    constexpr uint8_t TYPE_BOOLEAN_TRUE = 12 << 4;
    constexpr uint8_t TYPE_BOOLEAN_FALSE = 13 << 4;

    if (type == TYPE_NULL || type == TYPE_BOOLEAN_TRUE || type == TYPE_BOOLEAN_FALSE) {
        return true;
    }
    if (type == TYPE_STRING) {
        std::string tmp;
        return r.readUtf(tmp, error);
    }
    if (type == TYPE_STRING_INTERNED) {
        std::string tmp;
        return r.readInternedUtf(tmp, error);
    }
    if (type == TYPE_BYTES_HEX || type == TYPE_BYTES_BASE64) {
        uint16_t len = 0;
        if (!r.readU16(len, error)) {
            return false;
        }
        return r.skip(len, error);
    }
    if (type == TYPE_INT || type == TYPE_INT_HEX || type == TYPE_FLOAT) {
        int32_t tmp = 0;
        return r.readI32(tmp, error);
    }
    if (type == TYPE_LONG || type == TYPE_LONG_HEX || type == TYPE_DOUBLE) {
        int64_t tmp = 0;
        return r.readI64(tmp, error);
    }
    if (error) {
        *error = "unexpected value type";
    }
    return false;
}

inline bool abxReadValueAsBool(AbxReader &r, const uint8_t type, const bool defaultValue,
                               bool &out, std::string *error) {
    constexpr uint8_t TYPE_NULL = 1 << 4;
    constexpr uint8_t TYPE_STRING = 2 << 4;
    constexpr uint8_t TYPE_STRING_INTERNED = 3 << 4;
    constexpr uint8_t TYPE_INT = 6 << 4;
    constexpr uint8_t TYPE_INT_HEX = 7 << 4;
    constexpr uint8_t TYPE_LONG = 8 << 4;
    constexpr uint8_t TYPE_LONG_HEX = 9 << 4;
    constexpr uint8_t TYPE_BOOLEAN_TRUE = 12 << 4;
    constexpr uint8_t TYPE_BOOLEAN_FALSE = 13 << 4;

    if (type == TYPE_BOOLEAN_TRUE) {
        out = true;
        return true;
    }
    if (type == TYPE_BOOLEAN_FALSE) {
        out = false;
        return true;
    }
    if (type == TYPE_NULL) {
        out = defaultValue;
        return true;
    }
    if (type == TYPE_STRING) {
        std::string s;
        if (!r.readUtf(s, error)) {
            return false;
        }
        out = parseXmlBool(s, defaultValue);
        return true;
    }
    if (type == TYPE_STRING_INTERNED) {
        std::string s;
        if (!r.readInternedUtf(s, error)) {
            return false;
        }
        out = parseXmlBool(s, defaultValue);
        return true;
    }
    if (type == TYPE_INT || type == TYPE_INT_HEX) {
        int32_t v = 0;
        if (!r.readI32(v, error)) {
            return false;
        }
        out = v != 0;
        return true;
    }
    if (type == TYPE_LONG || type == TYPE_LONG_HEX) {
        int64_t v = 0;
        if (!r.readI64(v, error)) {
            return false;
        }
        out = v != 0;
        return true;
    }
    if (error) {
        *error = "unexpected boolean value type";
    }
    return false;
}

inline bool parsePackageRestrictionsAbxData(const std::string_view data,
                                           PackageRestrictionsSnapshot &out, std::string *error) {
    out = {};

    AbxReader r(data);
    if (!r.skip(4, error)) {
        return false;
    }

    constexpr uint8_t TOKEN_ATTRIBUTE = 15;
    constexpr uint8_t START_DOCUMENT = 0;
    constexpr uint8_t END_DOCUMENT = 1;
    constexpr uint8_t START_TAG = 2;
    constexpr uint8_t END_TAG = 3;
    constexpr uint8_t TEXT = 4;
    constexpr uint8_t CDSECT = 5;
    constexpr uint8_t ENTITY_REF = 6;
    constexpr uint8_t IGNORABLE_WHITESPACE = 7;
    constexpr uint8_t PROCESSING_INSTRUCTION = 8;
    constexpr uint8_t COMMENT = 9;
    constexpr uint8_t DOCDECL = 10;

    bool sawAnyPkg = false;
    while (r.remaining() > 0) {
        uint8_t event = 0;
        if (!r.readU8(event, error)) {
            return false;
        }
        const uint8_t token = event & 0x0f;
        const uint8_t type = event & 0xf0;

        if (token == TOKEN_ATTRIBUTE) {
            std::string attrName;
            if (!r.readInternedUtf(attrName, error)) {
                return false;
            }
            if (!abxSkipValue(r, type, error)) {
                return false;
            }
            continue;
        }

        if (token == START_TAG) {
            std::string tagName;
            if (!abxReadPossiblyInternedText(r, type, tagName, error)) {
                return false;
            }

            std::optional<std::string> nameAttr;
            std::optional<bool> instAttr;
            std::optional<bool> installedAttr;

            for (;;) {
                uint8_t next = 0;
                if (!r.peekU8(next)) {
                    break;
                }
                if ((next & 0x0f) != TOKEN_ATTRIBUTE) {
                    break;
                }

                uint8_t attrEvent = 0;
                if (!r.readU8(attrEvent, error)) {
                    return false;
                }
                const uint8_t attrType = attrEvent & 0xf0;
                std::string attrName;
                if (!r.readInternedUtf(attrName, error)) {
                    return false;
                }

                if (attrName == "name") {
                    std::string value;
                    if (!abxReadPossiblyInternedText(r, attrType, value, error)) {
                        return false;
                    }
                    nameAttr = std::move(value);
                } else if (attrName == "inst") {
                    bool v = true;
                    if (!abxReadValueAsBool(r, attrType, true, v, error)) {
                        return false;
                    }
                    instAttr = v;
                } else if (attrName == "installed") {
                    bool v = true;
                    if (!abxReadValueAsBool(r, attrType, true, v, error)) {
                        return false;
                    }
                    installedAttr = v;
                } else {
                    if (!abxSkipValue(r, attrType, error)) {
                        return false;
                    }
                }
            }

            if (tagName == "pkg" || tagName == "package") {
                sawAnyPkg = true;
                if (!nameAttr.has_value()) {
                    if (error) {
                        *error = "missing pkg name attribute";
                    }
                    return false;
                }
                if (!isValidPackageName(*nameAttr)) {
                    if (error) {
                        *error = "invalid pkg name";
                    }
                    return false;
                }
                const bool installed =
                    instAttr.has_value()   ? *instAttr
                    : installedAttr.has_value() ? *installedAttr
                                               : true;
                if (installed) {
                    out.installedPackages.emplace(std::move(*nameAttr));
                }
            }
            continue;
        }

        // Ignore remaining events by consuming their payload.
        if (token == END_TAG) {
            std::string tmp;
            if (!abxReadPossiblyInternedText(r, type, tmp, error)) {
                return false;
            }
            continue;
        }

        if (token == START_DOCUMENT || token == END_DOCUMENT) {
            // No payload for typical documents; tolerate TYPE_NULL.
            if (!abxSkipValue(r, type, error)) {
                return false;
            }
            continue;
        }

        if (token == TEXT || token == CDSECT || token == PROCESSING_INSTRUCTION || token == COMMENT ||
            token == DOCDECL || token == IGNORABLE_WHITESPACE || token == ENTITY_REF) {
            std::string tmp;
            if (!abxReadPossiblyInternedText(r, type, tmp, error)) {
                return false;
            }
            continue;
        }

        if (error) {
            *error = "unknown ABX token";
        }
        return false;
    }

    if (!sawAnyPkg) {
        if (error) {
            constexpr size_t kHexBytes = 16;
            constexpr size_t kAsciiBytes = 64;
            *error = "ABX: no <pkg>/<package> entries found (size=" + std::to_string(data.size()) +
                     ", prefix_hex=" + hexPrefix(data, kHexBytes) + ", prefix_ascii=\"" +
                     asciiPrefix(data, kAsciiBytes) + "\")";
        }
        return false;
    }
    return true;
}

} // namespace detail

inline bool isValidPackageName(const std::string_view name) {
    if (name.empty() || name.size() > detail::kMaxPackageNameBytes) {
        return false;
    }
    if (name.find("..") != std::string_view::npos) {
        return false;
    }
    for (const unsigned char c : name) {
        if (c < 33 || c == 127 || c >= 128) {
            return false;
        }
        if (c == '/' || c == '\\') {
            return false;
        }
    }
    return true;
}

inline bool parsePackagesListFile(const char *path, PackagesListSnapshot &out, std::string *error) {
    out = {};

    std::string data;
    if (!detail::readFileToStringLimited(path, detail::kMaxPackagesListBytes, data, error)) {
        return false;
    }

    size_t lineStart = 0;
    while (lineStart < data.size()) {
        size_t lineEnd = data.find('\n', lineStart);
        if (lineEnd == std::string::npos) {
            lineEnd = data.size();
        }
        std::string_view line{data.data() + lineStart, lineEnd - lineStart};
        lineStart = lineEnd + 1;

        size_t pos = 0;
        auto nextToken = [&](std::string_view &tok) -> bool {
            const size_t n = line.size();
            while (pos < n) {
                const unsigned char c = static_cast<unsigned char>(line[pos]);
                if (c == ' ' || c == '\t' || c == '\r') {
                    ++pos;
                    continue;
                }
                break;
            }
            if (pos >= n) {
                return false;
            }
            const size_t start = pos;
            while (pos < n) {
                const unsigned char c = static_cast<unsigned char>(line[pos]);
                if (c == ' ' || c == '\t' || c == '\r') {
                    break;
                }
                ++pos;
            }
            tok = line.substr(start, pos - start);
            return true;
        };

        std::string_view nameTok;
        std::string_view uidTok;
        if (!nextToken(nameTok)) {
            continue; // empty line
        }
        if (!nextToken(uidTok)) {
            if (error) {
                *error = "malformed line (missing uid)";
            }
            return false;
        }

        if (!isValidPackageName(nameTok)) {
            if (error) {
                *error = "invalid package name";
            }
            return false;
        }

        uint32_t appId = 0;
        if (!detail::parseDecimalU32(uidTok, appId)) {
            if (error) {
                *error = "invalid uid token";
            }
            return false;
        }

        if (appId < kAidAppStart || appId >= kAidUserOffset) {
            continue; // system/shared UIDs are not tracked as apps
        }

        const std::string name{nameTok};
        if (const auto it = out.packageToAppId.find(name); it != out.packageToAppId.end()) {
            if (it->second != appId) {
                if (error) {
                    *error = "conflicting appId for package";
                }
                return false;
            }
        } else {
            out.packageToAppId.emplace(name, appId);
        }

        auto &names = out.appIdToNames[appId];
        names.emplace_back(name);
    }

    return true;
}

inline bool parsePackageRestrictionsFile(const char *path, PackageRestrictionsSnapshot &out,
                                        std::string *error) {
    out = {};

    std::string data;
    if (!detail::readFileToStringLimited(path, detail::kMaxPackageRestrictionsBytes, data, error)) {
        return false;
    }

    if (detail::isAbxData(data)) {
        return detail::parsePackageRestrictionsAbxData(data, out, error);
    }

    size_t pos = 0;
    bool sawAnyPkg = false;
    while (pos < data.size()) {
        const size_t pkgStart = data.find("<pkg", pos);
        const size_t packageStart = data.find("<package", pos);
        if (pkgStart == std::string::npos && packageStart == std::string::npos) {
            break;
        }

        const bool isPkgTag = (pkgStart != std::string::npos) &&
                              (packageStart == std::string::npos || pkgStart < packageStart);
        const size_t start = isPkgTag ? pkgStart : packageStart;
        pos = start + (isPkgTag ? 4u : 8u);

        const char next = pos < data.size() ? data[pos] : '\0';
        const bool isTagBoundary = next == ' ' || next == '\t' || next == '\r' || next == '\n' ||
                                   next == '>' || next == '/';
        if (!isTagBoundary) {
            continue;
        }

        const size_t end = data.find('>', pos);
        if (end == std::string::npos) {
            if (error) {
                *error = isPkgTag ? "unterminated <pkg> tag" : "unterminated <package> tag";
            }
            return false;
        }

        std::string_view attrs{data.data() + pos, end - pos};
        pos = end + 1;

        sawAnyPkg = true;

        std::string_view nameAttr;
        std::string_view instAttr;
        std::string_view installedAttr;

        size_t attrPos = 0;
        for (;;) {
            detail::AttrView attr;
            if (!detail::parseNextXmlAttr(attrs, attrPos, attr)) {
                break;
            }
            if (attr.name == "name") {
                nameAttr = attr.value;
            } else if (attr.name == "inst") {
                instAttr = attr.value;
            } else if (attr.name == "installed") {
                installedAttr = attr.value;
            }
        }

        if (nameAttr.empty()) {
            if (error) {
                *error = "missing pkg name attribute";
            }
            return false;
        }
        if (!isValidPackageName(nameAttr)) {
            if (error) {
                *error = "invalid pkg name";
            }
            return false;
        }

        const std::string_view installedToken = !instAttr.empty() ? instAttr : installedAttr;
        const bool installed = detail::parseXmlBool(installedToken, true);
        if (installed) {
            out.installedPackages.emplace(std::string(nameAttr));
        }
    }

    if (!sawAnyPkg) {
        if (error) {
            constexpr size_t kHexBytes = 16;
            constexpr size_t kAsciiBytes = 64;
            const std::string_view sv{data};
            *error = "no <pkg>/<package> entries found (size=" + std::to_string(sv.size()) +
                     ", prefix_hex=" + detail::hexPrefix(sv, kHexBytes) + ", prefix_ascii=\"" +
                     detail::asciiPrefix(sv, kAsciiBytes) + "\")";
        }
        return false;
    }

    return true;
}

} // namespace PackageState

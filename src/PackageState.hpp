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

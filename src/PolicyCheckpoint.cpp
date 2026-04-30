/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <PolicyCheckpoint.hpp>

#include <AppManager.hpp>
#include <BlockingListManager.hpp>
#include <ControlVNextCodec.hpp>
#include <DomainManager.hpp>
#include <PacketManager.hpp>
#include <RulesManager.hpp>
#include <Settings.hpp>

#include <rapidjson/document.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_set>

namespace PolicyCheckpoint {

namespace {

constexpr std::string_view kMagic = "sucre-snort-policy-checkpoint";

[[nodiscard]] Status okStatus() { return Status{.ok = true}; }

[[nodiscard]] Status errStatus(std::string code, std::string message) {
    return Status{.ok = false, .code = std::move(code), .message = std::move(message)};
}

[[nodiscard]] rapidjson::Value makeString(const std::string_view value,
                                         rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out;
    out.SetString(value.data(), static_cast<rapidjson::SizeType>(value.size()), alloc);
    return out;
}

[[nodiscard]] std::string slotPath(const std::uint32_t slot) {
    return Settings::saveDirPolicyCheckpointsPath() + "slot" + std::to_string(slot) + ".bundle";
}

[[nodiscard]] std::string tmpSlotPath(const std::uint32_t slot) {
    const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
    return slotPath(slot) + ".tmp." + std::to_string(static_cast<long long>(::getpid())) + "." +
           std::to_string(tick);
}

[[nodiscard]] Status ensureDir(const std::string &dir) {
    if (::mkdir(dir.c_str(), 0700) == 0 || errno == EEXIST) {
        return okStatus();
    }
    return errStatus("INTERNAL_ERROR", "failed to create directory");
}

[[nodiscard]] Status ensureCheckpointDir() {
    return ensureDir(Settings::saveDirPolicyCheckpointsPath());
}

[[nodiscard]] std::string tmpSiblingPath(const std::string &path) {
    const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
    return path + ".tmp." + std::to_string(static_cast<long long>(::getpid())) + "." +
           std::to_string(tick);
}

[[nodiscard]] std::uint64_t nowUnixSeconds() {
    return static_cast<std::uint64_t>(std::time(nullptr));
}

[[nodiscard]] bool statFile(const std::string &path, std::uint64_t &size) {
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0) {
        return false;
    }
    if (st.st_size < 0) {
        return false;
    }
    size = static_cast<std::uint64_t>(st.st_size);
    return true;
}

[[nodiscard]] Status readFileBounded(const std::string &path, std::string &out,
                                     std::uint64_t &sizeBytes) {
    if (!statFile(path, sizeBytes)) {
        if (errno == ENOENT) {
            return errStatus("NOT_FOUND", "checkpoint slot is empty");
        }
        return errStatus("INTERNAL_ERROR", "failed to stat checkpoint slot");
    }
    if (sizeBytes > kMaxSlotBytes) {
        return errStatus("CAPACITY_EXCEEDED", "checkpoint slot exceeds 64 MiB cap");
    }

    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in.is_open()) {
        return errStatus("INTERNAL_ERROR", "failed to open checkpoint slot");
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    if (!in.good() && !in.eof()) {
        return errStatus("INTERNAL_ERROR", "failed to read checkpoint slot");
    }
    if (out.size() != sizeBytes) {
        return errStatus("INVALID_ARGUMENT", "checkpoint slot read was truncated");
    }
    return okStatus();
}

[[nodiscard]] Status writeSlotAtomically(const std::uint32_t slot, const std::string &data) {
    if (data.size() > kMaxSlotBytes) {
        return errStatus("CAPACITY_EXCEEDED", "checkpoint bundle exceeds 64 MiB cap");
    }
    if (auto st = ensureCheckpointDir(); !st.ok) {
        return st;
    }

    const std::string tmp = tmpSlotPath(slot);
    {
        std::ofstream out(tmp, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            return errStatus("INTERNAL_ERROR", "failed to open checkpoint temp file");
        }
        out.write(data.data(), static_cast<std::streamsize>(data.size()));
        out.close();
        if (!out) {
            (void)::unlink(tmp.c_str());
            return errStatus("INTERNAL_ERROR", "failed to write checkpoint temp file");
        }
    }

    std::uint64_t tmpSize = 0;
    if (!statFile(tmp, tmpSize)) {
        (void)::unlink(tmp.c_str());
        return errStatus("INTERNAL_ERROR", "failed to stat checkpoint temp file");
    }
    if (tmpSize > kMaxSlotBytes) {
        (void)::unlink(tmp.c_str());
        return errStatus("CAPACITY_EXCEEDED", "checkpoint temp file exceeds 64 MiB cap");
    }

    const std::string finalPath = slotPath(slot);
    if (::rename(tmp.c_str(), finalPath.c_str()) != 0) {
        (void)::unlink(tmp.c_str());
        return errStatus("INTERNAL_ERROR", "failed to commit checkpoint slot");
    }
    return okStatus();
}

[[nodiscard]] bool hasDuplicateKeys(const rapidjson::Value &object) {
    if (!object.IsObject()) {
        return false;
    }
    std::unordered_set<std::string> seen;
    for (auto it = object.MemberBegin(); it != object.MemberEnd(); ++it) {
        const std::string key(it->name.GetString(), it->name.GetStringLength());
        if (!seen.insert(key).second) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] Status rejectUnknownOrDuplicate(const rapidjson::Value &object,
                                              std::initializer_list<std::string_view> allowed,
                                              const std::string_view where) {
    if (!object.IsObject()) {
        return errStatus("INVALID_ARGUMENT", std::string(where) + " must be object");
    }
    if (hasDuplicateKeys(object)) {
        return errStatus("INVALID_ARGUMENT", "duplicate key in " + std::string(where));
    }
    if (const auto unknown = ControlVNext::findUnknownKey(object, allowed); unknown.has_value()) {
        return errStatus("SYNTAX_ERROR",
                         "unknown " + std::string(where) + " key: " + std::string(*unknown));
    }
    return okStatus();
}

[[nodiscard]] const rapidjson::Value *member(const rapidjson::Value &object,
                                             const std::string_view key) {
    if (!object.IsObject()) {
        return nullptr;
    }
    for (auto it = object.MemberBegin(); it != object.MemberEnd(); ++it) {
        if (it->name.IsString() && it->name.GetStringLength() == key.size() &&
            std::memcmp(it->name.GetString(), key.data(), key.size()) == 0) {
            return &it->value;
        }
    }
    return nullptr;
}

[[nodiscard]] Status requireBool(const rapidjson::Value &object, const std::string_view key,
                                 bool &out) {
    const auto *v = member(object, key);
    if (v == nullptr) {
        return errStatus("INVALID_ARGUMENT", "missing " + std::string(key));
    }
    if (!v->IsBool()) {
        return errStatus("INVALID_ARGUMENT", std::string(key) + " must be bool");
    }
    out = v->GetBool();
    return okStatus();
}

[[nodiscard]] Status requireU32(const rapidjson::Value &object, const std::string_view key,
                                std::uint32_t &out) {
    const auto *v = member(object, key);
    if (v == nullptr) {
        return errStatus("INVALID_ARGUMENT", "missing " + std::string(key));
    }
    if (!v->IsUint()) {
        return errStatus("INVALID_ARGUMENT", std::string(key) + " must be u32");
    }
    out = v->GetUint();
    return okStatus();
}

[[nodiscard]] Status requireU64(const rapidjson::Value &object, const std::string_view key,
                                std::uint64_t &out) {
    const auto *v = member(object, key);
    if (v == nullptr) {
        return errStatus("INVALID_ARGUMENT", "missing " + std::string(key));
    }
    if (!v->IsUint64()) {
        return errStatus("INVALID_ARGUMENT", std::string(key) + " must be u64");
    }
    out = v->GetUint64();
    return okStatus();
}

[[nodiscard]] Status requireI32(const rapidjson::Value &object, const std::string_view key,
                                std::int32_t &out) {
    const auto *v = member(object, key);
    if (v == nullptr) {
        return errStatus("INVALID_ARGUMENT", "missing " + std::string(key));
    }
    if (!v->IsInt()) {
        return errStatus("INVALID_ARGUMENT", std::string(key) + " must be i32");
    }
    out = v->GetInt();
    return okStatus();
}

[[nodiscard]] Status requireString(const rapidjson::Value &object, const std::string_view key,
                                   std::string &out) {
    const auto *v = member(object, key);
    if (v == nullptr) {
        return errStatus("INVALID_ARGUMENT", "missing " + std::string(key));
    }
    if (!v->IsString()) {
        return errStatus("INVALID_ARGUMENT", std::string(key) + " must be string");
    }
    out.assign(v->GetString(), v->GetStringLength());
    return okStatus();
}

[[nodiscard]] std::optional<Rule::Type> parseRuleType(const std::string_view value) {
    if (value == "domain") {
        return Rule::DOMAIN;
    }
    if (value == "wildcard") {
        return Rule::WILDCARD;
    }
    if (value == "regex") {
        return Rule::REGEX;
    }
    return std::nullopt;
}

[[nodiscard]] std::string_view ruleTypeString(const Rule::Type type) {
    switch (type) {
    case Rule::DOMAIN:
        return "domain";
    case Rule::WILDCARD:
        return "wildcard";
    case Rule::REGEX:
        return "regex";
    }
    return "domain";
}

[[nodiscard]] std::optional<Stats::Color> parseListKind(const std::string_view value) {
    if (value == "block") {
        return Stats::BLACK;
    }
    if (value == "allow") {
        return Stats::WHITE;
    }
    return std::nullopt;
}

[[nodiscard]] std::string_view listKindString(const Stats::Color color) {
    return color == Stats::WHITE ? "allow" : "block";
}

[[nodiscard]] std::string trimTrailingSlashes(std::string path) {
    while (path.size() > 1 && path.back() == '/') {
        path.pop_back();
    }
    return path;
}

[[nodiscard]] std::string ensureTrailingSlash(std::string path) {
    if (!path.empty() && path.back() != '/') {
        path.push_back('/');
    }
    return path;
}

[[nodiscard]] std::string domainListsFinalDir() {
    return trimTrailingSlashes(Settings::saveDirDomainListsPath());
}

[[nodiscard]] std::string domainListFilePathInDir(std::string dir,
                                                  const DomainListSnapshot &list) {
    return ensureTrailingSlash(std::move(dir)) + list.listId + (list.enabled ? "" : ".disabled");
}

[[nodiscard]] Status writeFileAtomically(const std::string &finalPath, const std::string &data) {
    const std::string tmp = tmpSiblingPath(finalPath);
    {
        std::ofstream out(tmp, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            return errStatus("INTERNAL_ERROR", "failed to open checkpoint staging file");
        }
        out.write(data.data(), static_cast<std::streamsize>(data.size()));
        out.close();
        if (!out) {
            (void)::unlink(tmp.c_str());
            return errStatus("INTERNAL_ERROR", "failed to write checkpoint staging file");
        }
    }
    if (::rename(tmp.c_str(), finalPath.c_str()) != 0) {
        (void)::unlink(tmp.c_str());
        return errStatus("INTERNAL_ERROR", "failed to commit checkpoint staging file");
    }
    return okStatus();
}

void removeTreeNoexcept(const std::string &path) noexcept {
    if (path.empty()) {
        return;
    }
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
}

[[nodiscard]] Status ensureCleanDirectory(const std::string &path) {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
    if (ec) {
        return errStatus("INTERNAL_ERROR", "failed to clear checkpoint staging directory");
    }
    std::filesystem::create_directories(path, ec);
    if (ec) {
        return errStatus("INTERNAL_ERROR", "failed to create checkpoint staging directory");
    }
    return okStatus();
}

[[nodiscard]] Status prepareDomainListFiles(const std::vector<DomainListSnapshot> &lists,
                                            RestoreStaging &staging) {
    staging.domainListsStageDir = tmpSiblingPath(domainListsFinalDir() + ".stage");
    staging.domainListsBackupDir.clear();
    staging.domainListsPublished = false;

    if (auto st = ensureCleanDirectory(staging.domainListsStageDir); !st.ok) {
        return st;
    }
    for (const auto &list : lists) {
        std::string data;
        for (const auto &domain : list.domains) {
            data.append(domain);
            data.push_back('\n');
        }
        if (auto st = writeFileAtomically(domainListFilePathInDir(staging.domainListsStageDir, list),
                                          data);
            !st.ok) {
            removeTreeNoexcept(staging.domainListsStageDir);
            staging.domainListsStageDir.clear();
            return st;
        }
    }
    return okStatus();
}

void cleanupStaleDomainListFiles(const std::vector<DomainListSnapshot> &lists) {
    std::unordered_set<std::string> keep;
    keep.reserve(lists.size() * 2);
    for (const auto &list : lists) {
        keep.insert(list.listId);
        keep.insert(list.listId + ".disabled");
    }

    const std::string dirPath = Settings::saveDirDomainListsPath();
    DIR *dir = ::opendir(dirPath.c_str());
    if (dir == nullptr) {
        return;
    }
    while (dirent *de = ::readdir(dir)) {
        const std::string name(de->d_name);
        if (name == "." || name == "..") {
            continue;
        }
        if (keep.find(name) == keep.end()) {
            (void)::unlink((dirPath + name).c_str());
        }
    }
    ::closedir(dir);
}

void rollbackDomainListFiles(RestoreStaging &staging) noexcept {
    const std::string finalDir = domainListsFinalDir();
    if (staging.domainListsPublished) {
        removeTreeNoexcept(finalDir);
        if (!staging.domainListsBackupDir.empty()) {
            if (::rename(staging.domainListsBackupDir.c_str(), finalDir.c_str()) == 0) {
                staging.domainListsBackupDir.clear();
            }
        }
    } else {
        removeTreeNoexcept(staging.domainListsStageDir);
    }
    staging = RestoreStaging{};
}

void commitDomainListFiles(RestoreStaging &staging) noexcept {
    removeTreeNoexcept(staging.domainListsBackupDir);
    staging = RestoreStaging{};
}

[[nodiscard]] Status publishDomainListFiles(RestoreStaging &staging) {
    if (staging.domainListsStageDir.empty()) {
        return errStatus("INTERNAL_ERROR", "checkpoint domain list staging missing");
    }

    const std::string finalDir = domainListsFinalDir();
    const auto parent = std::filesystem::path(finalDir).parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return errStatus("INTERNAL_ERROR", "failed to create checkpoint domain list parent");
        }
    }

    std::error_code ec;
    const bool finalExists = std::filesystem::exists(finalDir, ec);
    if (ec) {
        return errStatus("INTERNAL_ERROR", "failed to stat checkpoint domain list directory");
    }

    if (finalExists) {
        staging.domainListsBackupDir = tmpSiblingPath(finalDir + ".backup");
        removeTreeNoexcept(staging.domainListsBackupDir);
        if (::rename(finalDir.c_str(), staging.domainListsBackupDir.c_str()) != 0) {
            staging.domainListsBackupDir.clear();
            return errStatus("INTERNAL_ERROR", "failed to stage previous domain list directory");
        }
    }

    if (::rename(staging.domainListsStageDir.c_str(), finalDir.c_str()) != 0) {
        if (!staging.domainListsBackupDir.empty()) {
            (void)::rename(staging.domainListsBackupDir.c_str(), finalDir.c_str());
            staging.domainListsBackupDir.clear();
        }
        return errStatus("INTERNAL_ERROR", "failed to publish checkpoint domain list directory");
    }

    staging.domainListsPublished = true;
    return okStatus();
}

[[nodiscard]] Status parseUpdatedAtTime(const std::string &updatedAt, std::time_t &out) {
    out = 0;
    if (updatedAt.empty()) {
        return okStatus();
    }

    std::tm tm {};
    std::istringstream ss{updatedAt};
    ss >> std::get_time(&tm, "%Y-%m-%d_%H:%M:%S");
    if (ss.fail() || !ss.eof()) {
        return errStatus("INVALID_ARGUMENT", "domain list updatedAt invalid");
    }
    out = std::mktime(&tm);
    return okStatus();
}

[[nodiscard]] Status
buildBlockingListsForRestore(const std::vector<DomainListSnapshot> &snapshots,
                             std::unordered_map<std::string, BlockingList> &out) {
    out.clear();
    out.reserve(snapshots.size());
    for (const auto &list : snapshots) {
        std::time_t updatedAt = 0;
        if (auto st = parseUpdatedAtTime(list.updatedAt, updatedAt); !st.ok) {
            return st;
        }
        out.try_emplace(list.listId, list.listId, list.name, list.url, list.color, list.mask,
                        updatedAt, list.outdated, list.etag, list.enabled, list.domainsCount);
    }
    return okStatus();
}

[[nodiscard]] bool isValidGuid36(const std::string_view guid) {
    if (guid.size() != 36) {
        return false;
    }
    for (std::size_t i = 0; i < guid.size(); ++i) {
        const bool hyphen = i == 8 || i == 13 || i == 18 || i == 23;
        const unsigned char ch = static_cast<unsigned char>(guid[i]);
        if (hyphen) {
            if (ch != '-') {
                return false;
            }
        } else if (!std::isxdigit(ch)) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool isValidDomainString(const std::string_view domain) {
    if (domain.empty() || domain.size() > HOST_NAME_MAX) {
        return false;
    }
    for (const unsigned char ch : domain) {
        if (ch == '\0' || ch < 0x20 || ch == ' ') {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool isValidUpdatedAtString(const std::string_view updatedAt) {
    if (updatedAt.empty()) {
        return true;
    }
    std::tm tm {};
    std::istringstream ss{std::string(updatedAt)};
    ss >> std::get_time(&tm, "%Y-%m-%d_%H:%M:%S");
    return !ss.fail() && ss.eof();
}

template <class T>
[[nodiscard]] Status parseArray(const rapidjson::Value &object, const std::string_view key,
                                std::vector<T> &out,
                                const std::function<Status(const rapidjson::Value &, T &)> &parseItem) {
    const auto *v = member(object, key);
    if (v == nullptr) {
        return errStatus("INVALID_ARGUMENT", "missing " + std::string(key));
    }
    if (!v->IsArray()) {
        return errStatus("INVALID_ARGUMENT", std::string(key) + " must be array");
    }
    out.clear();
    out.reserve(v->Size());
    for (const auto &item : v->GetArray()) {
        T parsed{};
        if (auto st = parseItem(item, parsed); !st.ok) {
            return st;
        }
        out.push_back(std::move(parsed));
    }
    return okStatus();
}

[[nodiscard]] Status parseStringItem(const rapidjson::Value &value, std::string &out) {
    if (!value.IsString()) {
        return errStatus("INVALID_ARGUMENT", "array item must be string");
    }
    out.assign(value.GetString(), value.GetStringLength());
    return okStatus();
}

[[nodiscard]] Status parseU32Item(const rapidjson::Value &value, std::uint32_t &out) {
    if (!value.IsUint()) {
        return errStatus("INVALID_ARGUMENT", "array item must be u32");
    }
    out = value.GetUint();
    return okStatus();
}

[[nodiscard]] rapidjson::Value makeStringArray(const std::vector<std::string> &items,
                                               rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out(rapidjson::kArrayType);
    for (const auto &item : items) {
        out.PushBack(makeString(item, alloc), alloc);
    }
    return out;
}

[[nodiscard]] rapidjson::Value makeU32Array(const std::vector<std::uint32_t> &items,
                                            rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out(rapidjson::kArrayType);
    for (const auto item : items) {
        out.PushBack(item, alloc);
    }
    return out;
}

[[nodiscard]] Status parsePolicyScope(const rapidjson::Value &value,
                                      DomainPolicyScopeSnapshot &out) {
    if (auto st = rejectUnknownOrDuplicate(value, {"allowDomains", "blockDomains", "allowRuleIds",
                                                   "blockRuleIds"},
                                           "domainPolicy scope");
        !st.ok) {
        return st;
    }
    if (auto st = parseArray<std::string>(value, "allowDomains", out.allowDomains, parseStringItem);
        !st.ok) {
        return st;
    }
    if (auto st = parseArray<std::string>(value, "blockDomains", out.blockDomains, parseStringItem);
        !st.ok) {
        return st;
    }
    if (auto st = parseArray<std::uint32_t>(value, "allowRuleIds", out.allowRuleIds, parseU32Item);
        !st.ok) {
        return st;
    }
    return parseArray<std::uint32_t>(value, "blockRuleIds", out.blockRuleIds, parseU32Item);
}

[[nodiscard]] rapidjson::Value makePolicyScope(const DomainPolicyScopeSnapshot &scope,
                                               rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out(rapidjson::kObjectType);
    out.AddMember("allowDomains", makeStringArray(scope.allowDomains, alloc), alloc);
    out.AddMember("blockDomains", makeStringArray(scope.blockDomains, alloc), alloc);
    out.AddMember("allowRuleIds", makeU32Array(scope.allowRuleIds, alloc), alloc);
    out.AddMember("blockRuleIds", makeU32Array(scope.blockRuleIds, alloc), alloc);
    return out;
}

[[nodiscard]] Status parseDeviceConfig(const rapidjson::Value &value, DeviceConfigSnapshot &out) {
    if (auto st = rejectUnknownOrDuplicate(value, {"blockEnabled", "blockMask", "blockIface",
                                                   "reverseDns", "ipRulesEnabled"},
                                           "deviceConfig");
        !st.ok) {
        return st;
    }
    std::uint32_t mask = 0;
    std::uint32_t iface = 0;
    if (auto st = requireBool(value, "blockEnabled", out.blockEnabled); !st.ok) return st;
    if (auto st = requireU32(value, "blockMask", mask); !st.ok) return st;
    if (auto st = requireU32(value, "blockIface", iface); !st.ok) return st;
    if (auto st = requireBool(value, "reverseDns", out.reverseDns); !st.ok) return st;
    if (auto st = requireBool(value, "ipRulesEnabled", out.ipRulesEnabled); !st.ok) return st;
    if (mask > std::numeric_limits<std::uint8_t>::max() || !Settings::isValidAppBlockMask(mask)) {
        return errStatus("INVALID_ARGUMENT", "deviceConfig.blockMask invalid");
    }
    if (iface > std::numeric_limits<std::uint8_t>::max()) {
        return errStatus("INVALID_ARGUMENT", "deviceConfig.blockIface invalid");
    }
    out.blockMask = static_cast<std::uint8_t>(mask);
    out.blockIface = static_cast<std::uint8_t>(iface);
    return okStatus();
}

[[nodiscard]] rapidjson::Value makeDeviceConfig(const DeviceConfigSnapshot &cfg,
                                                rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out(rapidjson::kObjectType);
    out.AddMember("blockEnabled", cfg.blockEnabled, alloc);
    out.AddMember("blockMask", static_cast<std::uint32_t>(cfg.blockMask), alloc);
    out.AddMember("blockIface", static_cast<std::uint32_t>(cfg.blockIface), alloc);
    out.AddMember("reverseDns", cfg.reverseDns, alloc);
    out.AddMember("ipRulesEnabled", cfg.ipRulesEnabled, alloc);
    return out;
}

[[nodiscard]] Status parseAppConfigItem(const rapidjson::Value &value, AppConfigSnapshot &out) {
    if (auto st =
            rejectUnknownOrDuplicate(value, {"uid", "blockMask", "blockIface", "useCustomList"},
                                     "appConfig");
        !st.ok) {
        return st;
    }
    std::uint32_t mask = 0;
    std::uint32_t iface = 0;
    if (auto st = requireU32(value, "uid", out.uid); !st.ok) return st;
    if (auto st = requireU32(value, "blockMask", mask); !st.ok) return st;
    if (auto st = requireU32(value, "blockIface", iface); !st.ok) return st;
    if (auto st = requireBool(value, "useCustomList", out.useCustomList); !st.ok) return st;
    if (mask > std::numeric_limits<std::uint8_t>::max() || !Settings::isValidAppBlockMask(mask)) {
        return errStatus("INVALID_ARGUMENT", "appConfig.blockMask invalid");
    }
    if (iface > std::numeric_limits<std::uint8_t>::max()) {
        return errStatus("INVALID_ARGUMENT", "appConfig.blockIface invalid");
    }
    out.blockMask = static_cast<std::uint8_t>(mask);
    out.blockIface = static_cast<std::uint8_t>(iface);
    return okStatus();
}

[[nodiscard]] rapidjson::Value makeAppConfigItem(const AppConfigSnapshot &cfg,
                                                 rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out(rapidjson::kObjectType);
    out.AddMember("uid", cfg.uid, alloc);
    out.AddMember("blockMask", static_cast<std::uint32_t>(cfg.blockMask), alloc);
    out.AddMember("blockIface", static_cast<std::uint32_t>(cfg.blockIface), alloc);
    out.AddMember("useCustomList", cfg.useCustomList, alloc);
    return out;
}

[[nodiscard]] Status parseDomainRuleItem(const rapidjson::Value &value, DomainRuleSnapshot &out) {
    if (auto st = rejectUnknownOrDuplicate(value, {"ruleId", "type", "pattern"}, "domainRule");
        !st.ok) {
        return st;
    }
    std::string type;
    if (auto st = requireU32(value, "ruleId", out.ruleId); !st.ok) return st;
    if (auto st = requireString(value, "type", type); !st.ok) return st;
    if (auto parsed = parseRuleType(type); parsed.has_value()) {
        out.type = *parsed;
    } else {
        return errStatus("INVALID_ARGUMENT", "domainRule.type invalid");
    }
    return requireString(value, "pattern", out.pattern);
}

[[nodiscard]] rapidjson::Value makeDomainRuleItem(const DomainRuleSnapshot &rule,
                                                  rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out(rapidjson::kObjectType);
    out.AddMember("ruleId", rule.ruleId, alloc);
    out.AddMember("type", makeString(ruleTypeString(rule.type), alloc), alloc);
    out.AddMember("pattern", makeString(rule.pattern, alloc), alloc);
    return out;
}

[[nodiscard]] Status parseDomainRules(const rapidjson::Value &value, DomainRulesSnapshot &out) {
    if (auto st = rejectUnknownOrDuplicate(value, {"nextRuleId", "rules"}, "domainRules");
        !st.ok) {
        return st;
    }
    if (auto st = requireU32(value, "nextRuleId", out.nextRuleId); !st.ok) return st;
    return parseArray<DomainRuleSnapshot>(value, "rules", out.rules, parseDomainRuleItem);
}

[[nodiscard]] rapidjson::Value makeDomainRules(const DomainRulesSnapshot &rules,
                                               rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out(rapidjson::kObjectType);
    out.AddMember("nextRuleId", rules.nextRuleId, alloc);
    rapidjson::Value arr(rapidjson::kArrayType);
    for (const auto &rule : rules.rules) {
        arr.PushBack(makeDomainRuleItem(rule, alloc), alloc);
    }
    out.AddMember("rules", arr, alloc);
    return out;
}

[[nodiscard]] Status parseDomainPolicy(const rapidjson::Value &value, DomainPolicySnapshot &out) {
    if (auto st = rejectUnknownOrDuplicate(value, {"device", "apps"}, "domainPolicy"); !st.ok) {
        return st;
    }
    const auto *device = member(value, "device");
    if (device == nullptr) {
        return errStatus("INVALID_ARGUMENT", "missing domainPolicy.device");
    }
    if (auto st = parsePolicyScope(*device, out.device); !st.ok) {
        return st;
    }

    const auto parseAppPolicy = [](const rapidjson::Value &item,
                                   AppDomainPolicySnapshot &parsed) -> Status {
        if (auto st = rejectUnknownOrDuplicate(item, {"uid", "policy"}, "domainPolicy app");
            !st.ok) {
            return st;
        }
        if (auto st = requireU32(item, "uid", parsed.uid); !st.ok) {
            return st;
        }
        const auto *policy = member(item, "policy");
        if (policy == nullptr) {
            return errStatus("INVALID_ARGUMENT", "missing domainPolicy app.policy");
        }
        return parsePolicyScope(*policy, parsed.policy);
    };
    return parseArray<AppDomainPolicySnapshot>(value, "apps", out.apps, parseAppPolicy);
}

[[nodiscard]] rapidjson::Value makeDomainPolicy(const DomainPolicySnapshot &policy,
                                                rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out(rapidjson::kObjectType);
    out.AddMember("device", makePolicyScope(policy.device, alloc), alloc);
    rapidjson::Value apps(rapidjson::kArrayType);
    for (const auto &app : policy.apps) {
        rapidjson::Value item(rapidjson::kObjectType);
        item.AddMember("uid", app.uid, alloc);
        item.AddMember("policy", makePolicyScope(app.policy, alloc), alloc);
        apps.PushBack(item, alloc);
    }
    out.AddMember("apps", apps, alloc);
    return out;
}

[[nodiscard]] Status parseDomainListItem(const rapidjson::Value &value, DomainListSnapshot &out) {
    if (auto st = rejectUnknownOrDuplicate(value, {"listId", "listKind", "mask", "enabled",
                                                   "url", "name", "updatedAt", "etag", "outdated",
                                                   "domainsCount", "domains"},
                                           "domainList");
        !st.ok) {
        return st;
    }
    std::string kind;
    std::uint32_t mask = 0;
    if (auto st = requireString(value, "listId", out.listId); !st.ok) return st;
    if (auto st = requireString(value, "listKind", kind); !st.ok) return st;
    if (auto parsed = parseListKind(kind); parsed.has_value()) {
        out.color = *parsed;
    } else {
        return errStatus("INVALID_ARGUMENT", "domainList.listKind invalid");
    }
    if (auto st = requireU32(value, "mask", mask); !st.ok) return st;
    if (auto st = requireBool(value, "enabled", out.enabled); !st.ok) return st;
    if (auto st = requireString(value, "url", out.url); !st.ok) return st;
    if (auto st = requireString(value, "name", out.name); !st.ok) return st;
    if (auto st = requireString(value, "updatedAt", out.updatedAt); !st.ok) return st;
    if (auto st = requireString(value, "etag", out.etag); !st.ok) return st;
    if (auto st = requireBool(value, "outdated", out.outdated); !st.ok) return st;
    if (auto st = requireU32(value, "domainsCount", out.domainsCount); !st.ok) return st;
    if (auto st = parseArray<std::string>(value, "domains", out.domains, parseStringItem); !st.ok) {
        return st;
    }
    if (mask > std::numeric_limits<std::uint8_t>::max() || !Settings::isValidBlockingListMask(mask)) {
        return errStatus("INVALID_ARGUMENT", "domainList.mask invalid");
    }
    out.mask = static_cast<std::uint8_t>(mask);
    return okStatus();
}

[[nodiscard]] rapidjson::Value makeDomainListItem(const DomainListSnapshot &list,
                                                  rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out(rapidjson::kObjectType);
    out.AddMember("listId", makeString(list.listId, alloc), alloc);
    out.AddMember("listKind", makeString(listKindString(list.color), alloc), alloc);
    out.AddMember("mask", static_cast<std::uint32_t>(list.mask), alloc);
    out.AddMember("enabled", list.enabled, alloc);
    out.AddMember("url", makeString(list.url, alloc), alloc);
    out.AddMember("name", makeString(list.name, alloc), alloc);
    out.AddMember("updatedAt", makeString(list.updatedAt, alloc), alloc);
    out.AddMember("etag", makeString(list.etag, alloc), alloc);
    out.AddMember("outdated", list.outdated, alloc);
    out.AddMember("domainsCount", list.domainsCount, alloc);
    out.AddMember("domains", makeStringArray(list.domains, alloc), alloc);
    return out;
}

[[nodiscard]] Status parsePortPredicate(const rapidjson::Value &value,
                                        IpRulesEngine::PortPredicate &out) {
    if (auto st = rejectUnknownOrDuplicate(value, {"kind", "lo", "hi"}, "iprules port"); !st.ok) {
        return st;
    }
    std::uint32_t kind = 0;
    std::uint32_t lo = 0;
    std::uint32_t hi = 0;
    if (auto st = requireU32(value, "kind", kind); !st.ok) return st;
    if (auto st = requireU32(value, "lo", lo); !st.ok) return st;
    if (auto st = requireU32(value, "hi", hi); !st.ok) return st;
    if (kind > static_cast<std::uint32_t>(IpRulesEngine::PortPredicate::Kind::RANGE) ||
        lo > std::numeric_limits<std::uint16_t>::max() ||
        hi > std::numeric_limits<std::uint16_t>::max()) {
        return errStatus("INVALID_ARGUMENT", "iprules port invalid");
    }
    out.kind = static_cast<IpRulesEngine::PortPredicate::Kind>(kind);
    out.lo = static_cast<std::uint16_t>(lo);
    out.hi = static_cast<std::uint16_t>(hi);
    return okStatus();
}

[[nodiscard]] rapidjson::Value makePortPredicate(const IpRulesEngine::PortPredicate &port,
                                                 rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out(rapidjson::kObjectType);
    out.AddMember("kind", static_cast<std::uint32_t>(port.kind), alloc);
    out.AddMember("lo", static_cast<std::uint32_t>(port.lo), alloc);
    out.AddMember("hi", static_cast<std::uint32_t>(port.hi), alloc);
    return out;
}

[[nodiscard]] Status parseCidrV4(const rapidjson::Value &value, IpRulesEngine::CidrV4 &out) {
    if (auto st = rejectUnknownOrDuplicate(value, {"any", "addr", "prefix"}, "iprules cidr4");
        !st.ok) {
        return st;
    }
    if (auto st = requireBool(value, "any", out.any); !st.ok) return st;
    if (auto st = requireU32(value, "addr", out.addr); !st.ok) return st;
    std::uint32_t prefix = 0;
    if (auto st = requireU32(value, "prefix", prefix); !st.ok) return st;
    if (prefix > 32) {
        return errStatus("INVALID_ARGUMENT", "iprules cidr4 prefix invalid");
    }
    out.prefix = static_cast<std::uint8_t>(prefix);
    return okStatus();
}

[[nodiscard]] rapidjson::Value makeCidrV4(const IpRulesEngine::CidrV4 &cidr,
                                          rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out(rapidjson::kObjectType);
    out.AddMember("any", cidr.any, alloc);
    out.AddMember("addr", cidr.addr, alloc);
    out.AddMember("prefix", static_cast<std::uint32_t>(cidr.prefix), alloc);
    return out;
}

[[nodiscard]] Status parseCidrV6(const rapidjson::Value &value, IpRulesEngine::CidrV6 &out) {
    if (auto st = rejectUnknownOrDuplicate(value, {"any", "addr", "prefix"}, "iprules cidr6");
        !st.ok) {
        return st;
    }
    if (auto st = requireBool(value, "any", out.any); !st.ok) return st;
    std::uint32_t prefix = 0;
    if (auto st = requireU32(value, "prefix", prefix); !st.ok) return st;
    if (prefix > 128) {
        return errStatus("INVALID_ARGUMENT", "iprules cidr6 prefix invalid");
    }
    const auto *addr = member(value, "addr");
    if (addr == nullptr || !addr->IsArray() || addr->Size() != out.addr.size()) {
        return errStatus("INVALID_ARGUMENT", "iprules cidr6 addr must be 16-byte array");
    }
    for (rapidjson::SizeType i = 0; i < addr->Size(); ++i) {
        if (!(*addr)[i].IsUint() || (*addr)[i].GetUint() > 255u) {
            return errStatus("INVALID_ARGUMENT", "iprules cidr6 addr item invalid");
        }
        out.addr[i] = static_cast<std::uint8_t>((*addr)[i].GetUint());
    }
    out.prefix = static_cast<std::uint8_t>(prefix);
    return okStatus();
}

[[nodiscard]] rapidjson::Value makeCidrV6(const IpRulesEngine::CidrV6 &cidr,
                                          rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out(rapidjson::kObjectType);
    out.AddMember("any", cidr.any, alloc);
    rapidjson::Value addr(rapidjson::kArrayType);
    for (const auto byte : cidr.addr) {
        addr.PushBack(static_cast<std::uint32_t>(byte), alloc);
    }
    out.AddMember("addr", addr, alloc);
    out.AddMember("prefix", static_cast<std::uint32_t>(cidr.prefix), alloc);
    return out;
}

[[nodiscard]] Status parseIpRuleItem(const rapidjson::Value &value, IpRulesEngine::RuleDef &out) {
    if (auto st = rejectUnknownOrDuplicate(
            value, {"ruleId", "uid", "clientRuleId", "family", "action", "priority", "enabled",
                    "enforce", "log", "dir", "iface", "ifindex", "proto", "src", "dst", "src6",
                    "dst6", "sport", "dport", "ctState", "ctDir"},
            "iprules rule");
        !st.ok) {
        return st;
    }
    std::uint32_t tmp = 0;
    if (auto st = requireU32(value, "ruleId", out.ruleId); !st.ok) return st;
    if (auto st = requireU32(value, "uid", out.uid); !st.ok) return st;
    if (auto st = requireString(value, "clientRuleId", out.clientRuleId); !st.ok) return st;
    if (auto st = requireU32(value, "family", tmp); !st.ok) return st;
    out.family = static_cast<IpRulesEngine::Family>(tmp);
    if (auto st = requireU32(value, "action", tmp); !st.ok) return st;
    out.action = static_cast<IpRulesEngine::Action>(tmp);
    if (auto st = requireI32(value, "priority", out.priority); !st.ok) return st;
    if (auto st = requireBool(value, "enabled", out.enabled); !st.ok) return st;
    if (auto st = requireBool(value, "enforce", out.enforce); !st.ok) return st;
    if (auto st = requireBool(value, "log", out.log); !st.ok) return st;
    if (auto st = requireU32(value, "dir", tmp); !st.ok) return st;
    out.dir = static_cast<IpRulesEngine::Direction>(tmp);
    if (auto st = requireU32(value, "iface", tmp); !st.ok) return st;
    out.iface = static_cast<IpRulesEngine::IfaceKind>(tmp);
    if (auto st = requireU32(value, "ifindex", out.ifindex); !st.ok) return st;
    if (auto st = requireU32(value, "proto", tmp); !st.ok) return st;
    out.proto = static_cast<IpRulesEngine::Proto>(tmp);
    const auto *src = member(value, "src");
    const auto *dst = member(value, "dst");
    const auto *src6 = member(value, "src6");
    const auto *dst6 = member(value, "dst6");
    const auto *sport = member(value, "sport");
    const auto *dport = member(value, "dport");
    if (src == nullptr || dst == nullptr || src6 == nullptr || dst6 == nullptr ||
        sport == nullptr || dport == nullptr) {
        return errStatus("INVALID_ARGUMENT", "missing iprules nested fields");
    }
    if (auto st = parseCidrV4(*src, out.src); !st.ok) return st;
    if (auto st = parseCidrV4(*dst, out.dst); !st.ok) return st;
    if (auto st = parseCidrV6(*src6, out.src6); !st.ok) return st;
    if (auto st = parseCidrV6(*dst6, out.dst6); !st.ok) return st;
    if (auto st = parsePortPredicate(*sport, out.sport); !st.ok) return st;
    if (auto st = parsePortPredicate(*dport, out.dport); !st.ok) return st;
    if (auto st = requireU32(value, "ctState", tmp); !st.ok) return st;
    out.ctState = static_cast<IpRulesEngine::CtState>(tmp);
    if (auto st = requireU32(value, "ctDir", tmp); !st.ok) return st;
    out.ctDir = static_cast<IpRulesEngine::CtDirection>(tmp);
    return okStatus();
}

[[nodiscard]] rapidjson::Value makeIpRuleItem(const IpRulesEngine::RuleDef &rule,
                                              rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out(rapidjson::kObjectType);
    out.AddMember("ruleId", rule.ruleId, alloc);
    out.AddMember("uid", rule.uid, alloc);
    out.AddMember("clientRuleId", makeString(rule.clientRuleId, alloc), alloc);
    out.AddMember("family", static_cast<std::uint32_t>(rule.family), alloc);
    out.AddMember("action", static_cast<std::uint32_t>(rule.action), alloc);
    out.AddMember("priority", rule.priority, alloc);
    out.AddMember("enabled", rule.enabled, alloc);
    out.AddMember("enforce", rule.enforce, alloc);
    out.AddMember("log", rule.log, alloc);
    out.AddMember("dir", static_cast<std::uint32_t>(rule.dir), alloc);
    out.AddMember("iface", static_cast<std::uint32_t>(rule.iface), alloc);
    out.AddMember("ifindex", rule.ifindex, alloc);
    out.AddMember("proto", static_cast<std::uint32_t>(rule.proto), alloc);
    out.AddMember("src", makeCidrV4(rule.src, alloc), alloc);
    out.AddMember("dst", makeCidrV4(rule.dst, alloc), alloc);
    out.AddMember("src6", makeCidrV6(rule.src6, alloc), alloc);
    out.AddMember("dst6", makeCidrV6(rule.dst6, alloc), alloc);
    out.AddMember("sport", makePortPredicate(rule.sport, alloc), alloc);
    out.AddMember("dport", makePortPredicate(rule.dport, alloc), alloc);
    out.AddMember("ctState", static_cast<std::uint32_t>(rule.ctState), alloc);
    out.AddMember("ctDir", static_cast<std::uint32_t>(rule.ctDir), alloc);
    return out;
}

[[nodiscard]] Status parseIpRules(const rapidjson::Value &value,
                                  IpRulesEngine::PolicySnapshot &out) {
    if (auto st = rejectUnknownOrDuplicate(value, {"nextRuleId", "rules"}, "iprules"); !st.ok) {
        return st;
    }
    if (auto st = requireU32(value, "nextRuleId", out.nextRuleId); !st.ok) return st;
    return parseArray<IpRulesEngine::RuleDef>(value, "rules", out.rules, parseIpRuleItem);
}

[[nodiscard]] rapidjson::Value makeIpRules(const IpRulesEngine::PolicySnapshot &snapshot,
                                           rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out(rapidjson::kObjectType);
    out.AddMember("nextRuleId", snapshot.nextRuleId, alloc);
    rapidjson::Value rules(rapidjson::kArrayType);
    for (const auto &rule : snapshot.rules) {
        rules.PushBack(makeIpRuleItem(rule, alloc), alloc);
    }
    out.AddMember("rules", rules, alloc);
    return out;
}

[[nodiscard]] Status parseBundleDocument(const rapidjson::Document &doc, Bundle &out) {
    if (auto st = rejectUnknownOrDuplicate(doc, {"magic", "formatVersion", "createdAt", "sections"},
                                           "bundle");
        !st.ok) {
        return st;
    }
    std::string magic;
    if (auto st = requireString(doc, "magic", magic); !st.ok) return st;
    if (magic != kMagic) {
        return errStatus("INVALID_ARGUMENT", "checkpoint magic mismatch");
    }
    if (auto st = requireU32(doc, "formatVersion", out.formatVersion); !st.ok) return st;
    if (out.formatVersion != kFormatVersion) {
        return errStatus("INVALID_ARGUMENT", "unsupported checkpoint format version");
    }
    if (auto st = requireU64(doc, "createdAt", out.createdAt); !st.ok) return st;

    const auto *sections = member(doc, "sections");
    if (sections == nullptr) {
        return errStatus("INVALID_ARGUMENT", "missing sections");
    }
    if (auto st = rejectUnknownOrDuplicate(*sections, {"deviceConfig", "appConfigs", "domainRules",
                                                       "domainPolicy", "domainLists", "ipRules"},
                                           "sections");
        !st.ok) {
        return st;
    }

    const auto *deviceConfig = member(*sections, "deviceConfig");
    const auto *domainRules = member(*sections, "domainRules");
    const auto *domainPolicy = member(*sections, "domainPolicy");
    const auto *ipRules = member(*sections, "ipRules");
    if (deviceConfig == nullptr || domainRules == nullptr || domainPolicy == nullptr ||
        ipRules == nullptr) {
        return errStatus("INVALID_ARGUMENT", "missing required checkpoint section");
    }
    if (auto st = parseDeviceConfig(*deviceConfig, out.deviceConfig); !st.ok) return st;
    if (auto st = parseArray<AppConfigSnapshot>(*sections, "appConfigs", out.appConfigs,
                                                parseAppConfigItem);
        !st.ok) {
        return st;
    }
    if (auto st = parseDomainRules(*domainRules, out.domainRules); !st.ok) return st;
    if (auto st = parseDomainPolicy(*domainPolicy, out.domainPolicy); !st.ok) return st;
    if (auto st = parseArray<DomainListSnapshot>(*sections, "domainLists", out.domainLists,
                                                 parseDomainListItem);
        !st.ok) {
        return st;
    }
    return parseIpRules(*ipRules, out.ipRules);
}

[[nodiscard]] std::string formatUpdatedAt(const std::time_t updatedAt) {
    if (updatedAt == 0) {
        return {};
    }
    std::tm tm {};
    if (localtime_r(&updatedAt, &tm) == nullptr) {
        return {};
    }
    char buf[20] {};
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%d_%H:%M:%S", &tm) != 19) {
        return {};
    }
    return std::string(buf);
}

void sortPolicyScope(DomainPolicyScopeSnapshot &scope) {
    std::sort(scope.allowDomains.begin(), scope.allowDomains.end());
    std::sort(scope.blockDomains.begin(), scope.blockDomains.end());
    std::sort(scope.allowRuleIds.begin(), scope.allowRuleIds.end());
    std::sort(scope.blockRuleIds.begin(), scope.blockRuleIds.end());
}

void addPolicyScope(const DomainPolicyScopeSnapshot &scope, const App::Ptr &app) {
    for (const auto &domain : scope.allowDomains) {
        if (app == nullptr) {
            domManager.addCustomDomain(domain, Stats::WHITE);
        } else {
            app->addCustomDomain(domain, Stats::WHITE);
        }
    }
    for (const auto &domain : scope.blockDomains) {
        if (app == nullptr) {
            domManager.addCustomDomain(domain, Stats::BLACK);
        } else {
            app->addCustomDomain(domain, Stats::BLACK);
        }
    }
    for (const auto ruleId : scope.allowRuleIds) {
        if (app == nullptr) {
            rulesManager.addCustom(ruleId, Stats::WHITE, true);
        } else {
            rulesManager.addCustom(app, ruleId, Stats::WHITE, true);
        }
    }
    for (const auto ruleId : scope.blockRuleIds) {
        if (app == nullptr) {
            rulesManager.addCustom(ruleId, Stats::BLACK, true);
        } else {
            rulesManager.addCustom(app, ruleId, Stats::BLACK, true);
        }
    }
}

[[nodiscard]] Status validatePolicyScope(const DomainPolicyScopeSnapshot &scope,
                                         const std::unordered_set<std::uint32_t> &ruleIds) {
    const auto checkDomains = [](const std::vector<std::string> &domains) -> bool {
        std::set<std::string> seen;
        for (const auto &domain : domains) {
            if (!isValidDomainString(domain) || !seen.insert(domain).second) {
                return false;
            }
        }
        return true;
    };
    const auto checkRuleIds = [&](const std::vector<std::uint32_t> &ids) -> bool {
        std::set<std::uint32_t> seen;
        for (const auto id : ids) {
            if (ruleIds.find(id) == ruleIds.end() || !seen.insert(id).second) {
                return false;
            }
        }
        return true;
    };
    if (!checkDomains(scope.allowDomains) || !checkDomains(scope.blockDomains)) {
        return errStatus("INVALID_ARGUMENT", "invalid or duplicate domain policy domain");
    }
    if (!checkRuleIds(scope.allowRuleIds) || !checkRuleIds(scope.blockRuleIds)) {
        return errStatus("INVALID_ARGUMENT", "invalid or duplicate domain policy ruleId");
    }
    return okStatus();
}

} // namespace

bool isValidSlot(const std::uint32_t slot) noexcept { return slot < kSlotCount; }

std::array<SlotMetadata, kSlotCount> listSlots() {
    std::array<SlotMetadata, kSlotCount> out {};
    for (std::uint32_t slot = 0; slot < kSlotCount; ++slot) {
        SlotMetadata meta {};
        meta.slot = slot;
        const std::string path = slotPath(slot);
        std::uint64_t size = 0;
        if (statFile(path, size)) {
            meta.present = true;
            meta.sizeBytes = size;
            if (size <= kMaxSlotBytes) {
                std::string data;
                Bundle bundle;
                std::uint64_t ignoredSize = 0;
                if (readFileBounded(path, data, ignoredSize).ok && decodeBundle(data, bundle).ok) {
                    meta.formatVersion = bundle.formatVersion;
                    meta.createdAt = bundle.createdAt;
                }
            }
        }
        out[slot] = meta;
    }
    return out;
}

Status clearSlot(const std::uint32_t slot, SlotMetadata &metadata) {
    if (!isValidSlot(slot)) {
        return errStatus("INVALID_ARGUMENT", "slot must be 0, 1, or 2");
    }
    if (auto st = ensureCheckpointDir(); !st.ok) {
        return st;
    }
    const std::string path = slotPath(slot);
    if (::unlink(path.c_str()) != 0 && errno != ENOENT) {
        return errStatus("INTERNAL_ERROR", "failed to clear checkpoint slot");
    }
    metadata = SlotMetadata{.slot = slot, .present = false};
    return okStatus();
}

Status saveCurrentPolicyToSlot(const std::uint32_t slot, SlotMetadata &metadata) {
    if (!isValidSlot(slot)) {
        return errStatus("INVALID_ARGUMENT", "slot must be 0, 1, or 2");
    }
    Bundle bundle = captureLivePolicy();
    bundle.createdAt = nowUnixSeconds();
    if (auto st = validateBundle(bundle); !st.ok) {
        return st;
    }
    std::string encoded;
    if (auto st = encodeBundle(bundle, encoded); !st.ok) {
        return st;
    }
    if (auto st = writeSlotAtomically(slot, encoded); !st.ok) {
        return st;
    }
    metadata = SlotMetadata{.slot = slot,
                            .present = true,
                            .formatVersion = bundle.formatVersion,
                            .sizeBytes = static_cast<std::uint64_t>(encoded.size()),
                            .createdAt = bundle.createdAt};
    return okStatus();
}

Status readSlot(const std::uint32_t slot, Bundle &bundle, SlotMetadata &metadata) {
    if (!isValidSlot(slot)) {
        return errStatus("INVALID_ARGUMENT", "slot must be 0, 1, or 2");
    }
    std::string data;
    std::uint64_t size = 0;
    if (auto st = readFileBounded(slotPath(slot), data, size); !st.ok) {
        return st;
    }
    if (auto st = decodeBundle(data, bundle); !st.ok) {
        return st;
    }
    metadata = SlotMetadata{.slot = slot,
                            .present = true,
                            .formatVersion = bundle.formatVersion,
                            .sizeBytes = size,
                            .createdAt = bundle.createdAt};
    return okStatus();
}

Status stageBundleForRestore(const Bundle &bundle, RestoreStaging &staging) {
    cleanupRestoreStaging(staging);
    if (auto st = validateBundle(bundle); !st.ok) {
        return st;
    }
    return prepareDomainListFiles(bundle.domainLists, staging);
}

void cleanupRestoreStaging(RestoreStaging &staging) noexcept { rollbackDomainListFiles(staging); }

Bundle captureLivePolicy() {
    Bundle bundle {};
    bundle.formatVersion = kFormatVersion;
    bundle.createdAt = nowUnixSeconds();
    bundle.deviceConfig = DeviceConfigSnapshot{
        .blockEnabled = settings.blockEnabled(),
        .blockMask = settings.blockMask(),
        .blockIface = settings.blockIface(),
        .reverseDns = settings.reverseDns(),
        .ipRulesEnabled = settings.ipRulesEnabled(),
    };

    const auto apps = appManager.snapshotByUid();
    bundle.appConfigs.reserve(apps.size());
    bundle.domainPolicy.apps.reserve(apps.size());
    for (const auto &app : apps) {
        bundle.appConfigs.push_back(AppConfigSnapshot{
            .uid = app->uid(),
            .blockMask = app->blockMask(),
            .blockIface = app->blockIface(),
            .useCustomList = app->useCustomList(),
        });

        AppDomainPolicySnapshot policy {};
        policy.uid = app->uid();
        policy.policy.allowDomains = app->snapshotCustomDomains(Stats::WHITE);
        policy.policy.blockDomains = app->snapshotCustomDomains(Stats::BLACK);
        policy.policy.allowRuleIds = app->snapshotCustomRuleIds(Stats::WHITE);
        policy.policy.blockRuleIds = app->snapshotCustomRuleIds(Stats::BLACK);
        sortPolicyScope(policy.policy);
        bundle.domainPolicy.apps.push_back(std::move(policy));
    }
    std::sort(bundle.appConfigs.begin(), bundle.appConfigs.end(),
              [](const auto &a, const auto &b) { return a.uid < b.uid; });
    std::sort(bundle.domainPolicy.apps.begin(), bundle.domainPolicy.apps.end(),
              [](const auto &a, const auto &b) { return a.uid < b.uid; });

    bundle.domainRules.nextRuleId = rulesManager.nextRuleIdSnapshot();
    auto rules = rulesManager.snapshotBaseline();
    std::sort(rules.begin(), rules.end(), [](const auto &a, const auto &b) {
        return a.ruleId < b.ruleId;
    });
    bundle.domainRules.rules.reserve(rules.size());
    for (const auto &rule : rules) {
        bundle.domainRules.rules.push_back(DomainRuleSnapshot{
            .ruleId = rule.ruleId,
            .type = rule.type,
            .pattern = rule.pattern,
        });
    }

    bundle.domainPolicy.device.allowDomains = domManager.snapshotCustomDomains(Stats::WHITE);
    bundle.domainPolicy.device.blockDomains = domManager.snapshotCustomDomains(Stats::BLACK);
    bundle.domainPolicy.device.allowRuleIds = domManager.snapshotCustomRuleIds(Stats::WHITE);
    bundle.domainPolicy.device.blockRuleIds = domManager.snapshotCustomRuleIds(Stats::BLACK);
    sortPolicyScope(bundle.domainPolicy.device);

    auto lists = blockingListManager.listsSnapshot();
    std::sort(lists.begin(), lists.end(), [](const auto &a, const auto &b) {
        if (a.getColor() != b.getColor()) {
            return listKindString(a.getColor()) < listKindString(b.getColor());
        }
        return a.getId() < b.getId();
    });
    bundle.domainLists.reserve(lists.size());
    for (const auto &list : lists) {
        DomainListSnapshot snapshot {};
        snapshot.listId = list.getId();
        snapshot.color = list.getColor();
        snapshot.mask = list.getBlockMask();
        snapshot.enabled = list.isEnabled();
        snapshot.url = list.getUrl();
        snapshot.name = list.getName();
        snapshot.updatedAt = formatUpdatedAt(list.getUpdatedAt());
        snapshot.etag = list.getEtag();
        snapshot.outdated = list.isOutdated();
        snapshot.domains = domManager.snapshotDomainListContents(snapshot.listId, snapshot.color);
        std::sort(snapshot.domains.begin(), snapshot.domains.end());
        snapshot.domainsCount = static_cast<std::uint32_t>(snapshot.domains.size());
        bundle.domainLists.push_back(std::move(snapshot));
    }

    bundle.ipRules = pktManager.ipRules().policySnapshot();
    return bundle;
}

Status validateBundle(const Bundle &bundle) {
    if (bundle.formatVersion != kFormatVersion) {
        return errStatus("INVALID_ARGUMENT", "unsupported checkpoint format version");
    }
    if (!Settings::isValidAppBlockMask(bundle.deviceConfig.blockMask)) {
        return errStatus("INVALID_ARGUMENT", "device block mask invalid");
    }

    std::unordered_set<std::uint32_t> appUids;
    for (const auto &cfg : bundle.appConfigs) {
        if (!appUids.insert(cfg.uid).second) {
            return errStatus("INVALID_ARGUMENT", "duplicate app config uid");
        }
        if (!Settings::isValidAppBlockMask(cfg.blockMask)) {
            return errStatus("INVALID_ARGUMENT", "app block mask invalid");
        }
    }

    std::unordered_set<std::uint32_t> domainRuleIds;
    std::uint32_t maxDomainRuleId = 0;
    bool hasDomainRule = false;
    for (const auto &rule : bundle.domainRules.rules) {
        if (!domainRuleIds.insert(rule.ruleId).second) {
            return errStatus("INVALID_ARGUMENT", "duplicate domain ruleId");
        }
        const Rule tmp(rule.type, 0, rule.pattern);
        if (!tmp.valid()) {
            return errStatus("INVALID_ARGUMENT", "invalid domain rule");
        }
        maxDomainRuleId = std::max(maxDomainRuleId, rule.ruleId);
        hasDomainRule = true;
    }
    if (hasDomainRule && bundle.domainRules.nextRuleId <= maxDomainRuleId) {
        return errStatus("INVALID_ARGUMENT", "domainRules.nextRuleId invalid");
    }

    if (auto st = validatePolicyScope(bundle.domainPolicy.device, domainRuleIds); !st.ok) {
        return st;
    }
    std::unordered_set<std::uint32_t> policyUids;
    for (const auto &appPolicy : bundle.domainPolicy.apps) {
        if (!policyUids.insert(appPolicy.uid).second) {
            return errStatus("INVALID_ARGUMENT", "duplicate domain policy uid");
        }
        if (auto st = validatePolicyScope(appPolicy.policy, domainRuleIds); !st.ok) {
            return st;
        }
    }

    std::unordered_set<std::string> listIds;
    for (const auto &list : bundle.domainLists) {
        if (!isValidGuid36(list.listId) || !listIds.insert(list.listId).second) {
            return errStatus("INVALID_ARGUMENT", "invalid or duplicate domain listId");
        }
        if (!Settings::isValidBlockingListMask(list.mask)) {
            return errStatus("INVALID_ARGUMENT", "domain list mask invalid");
        }
        if (!isValidUpdatedAtString(list.updatedAt)) {
            return errStatus("INVALID_ARGUMENT", "domain list updatedAt invalid");
        }
        if (list.domainsCount != list.domains.size()) {
            return errStatus("INVALID_ARGUMENT", "domain list metadata/content mismatch");
        }
        std::set<std::string> seenDomains;
        for (const auto &domain : list.domains) {
            if (!isValidDomainString(domain) || !seenDomains.insert(domain).second) {
                return errStatus("INVALID_ARGUMENT", "invalid or duplicate domain list content");
            }
        }
    }

    const auto ipRulesValidation = pktManager.ipRules().validatePolicySnapshot(bundle.ipRules);
    if (!ipRulesValidation.ok) {
        return errStatus("INVALID_ARGUMENT", "invalid iprules checkpoint: " + ipRulesValidation.error);
    }
    return okStatus();
}

Status restoreBundleToLivePolicy(const Bundle &bundle, RestoreStaging &staging) {
    const auto fail = [&](const Status &status) {
        rollbackDomainListFiles(staging);
        return status;
    };

    if (auto st = validateBundle(bundle); !st.ok) {
        return fail(st);
    }

    std::unordered_map<std::string, BlockingList> restoredLists;
    if (auto st = buildBlockingListsForRestore(bundle.domainLists, restoredLists); !st.ok) {
        return fail(st);
    }

    if (auto st = publishDomainListFiles(staging); !st.ok) {
        return fail(st);
    }

    const auto ipRestore = pktManager.ipRules().restorePolicySnapshot(bundle.ipRules);
    if (!ipRestore.ok) {
        return fail(errStatus("INVALID_ARGUMENT",
                              "failed to restore iprules checkpoint: " + ipRestore.error));
    }

    settings.applyCheckpointPolicyConfig(bundle.deviceConfig.blockEnabled, bundle.deviceConfig.blockMask,
                                         bundle.deviceConfig.blockIface, bundle.deviceConfig.reverseDns,
                                         bundle.deviceConfig.ipRulesEnabled);

    const auto currentApps = appManager.snapshotByUid();
    for (const auto &app : currentApps) {
        app->applyCheckpointPolicyConfig(settings.blockMask(), settings.blockIface(), false);
        app->clearCheckpointDomainPolicy();
    }
    for (const auto &cfg : bundle.appConfigs) {
        const auto app = appManager.make(cfg.uid);
        app->applyCheckpointPolicyConfig(cfg.blockMask, cfg.blockIface, cfg.useCustomList);
        app->clearCheckpointDomainPolicy();
    }

    domManager.resetPolicyForCheckpointRestore();
    blockingListManager.replaceAllForCheckpointRestore(std::move(restoredLists));
    rulesManager.reset();

    for (const auto &rule : bundle.domainRules.rules) {
        rulesManager.upsertRuleWithId(rule.ruleId, rule.type, rule.pattern);
    }
    rulesManager.ensureNextRuleIdAtLeast(bundle.domainRules.nextRuleId);

    domManager.start(blockingListManager.getLists());

    addPolicyScope(bundle.domainPolicy.device, nullptr);
    for (const auto &appPolicy : bundle.domainPolicy.apps) {
        addPolicyScope(appPolicy.policy, appManager.make(appPolicy.uid));
    }

    cleanupStaleDomainListFiles(bundle.domainLists);
    commitDomainListFiles(staging);
    return okStatus();
}

Status encodeBundle(const Bundle &bundle, std::string &out) {
    if (auto st = validateBundle(bundle); !st.ok) {
        return st;
    }

    rapidjson::Document doc(rapidjson::kObjectType);
    auto &alloc = doc.GetAllocator();
    doc.AddMember("magic", makeString(kMagic, alloc), alloc);
    doc.AddMember("formatVersion", bundle.formatVersion, alloc);
    doc.AddMember("createdAt", bundle.createdAt, alloc);

    rapidjson::Value sections(rapidjson::kObjectType);
    sections.AddMember("deviceConfig", makeDeviceConfig(bundle.deviceConfig, alloc), alloc);

    rapidjson::Value appConfigs(rapidjson::kArrayType);
    for (const auto &cfg : bundle.appConfigs) {
        appConfigs.PushBack(makeAppConfigItem(cfg, alloc), alloc);
    }
    sections.AddMember("appConfigs", appConfigs, alloc);
    sections.AddMember("domainRules", makeDomainRules(bundle.domainRules, alloc), alloc);
    sections.AddMember("domainPolicy", makeDomainPolicy(bundle.domainPolicy, alloc), alloc);

    rapidjson::Value domainLists(rapidjson::kArrayType);
    for (const auto &list : bundle.domainLists) {
        domainLists.PushBack(makeDomainListItem(list, alloc), alloc);
    }
    sections.AddMember("domainLists", domainLists, alloc);
    sections.AddMember("ipRules", makeIpRules(bundle.ipRules, alloc), alloc);

    doc.AddMember("sections", sections, alloc);
    out = ControlVNext::encodeJson(doc, ControlVNext::JsonFormat::Compact);
    if (out.size() > kMaxSlotBytes) {
        return errStatus("CAPACITY_EXCEEDED", "checkpoint bundle exceeds 64 MiB cap");
    }
    return okStatus();
}

Status decodeBundle(const std::string &data, Bundle &out) {
    if (data.size() > kMaxSlotBytes) {
        return errStatus("CAPACITY_EXCEEDED", "checkpoint bundle exceeds 64 MiB cap");
    }
    rapidjson::Document doc;
    ControlVNext::JsonError jsonError;
    if (!ControlVNext::parseStrictJsonObject(data, doc, jsonError)) {
        return errStatus("INVALID_ARGUMENT", "checkpoint JSON parse failed: " + jsonError.message);
    }
    if (auto st = parseBundleDocument(doc, out); !st.ok) {
        return st;
    }
    return validateBundle(out);
}

} // namespace PolicyCheckpoint

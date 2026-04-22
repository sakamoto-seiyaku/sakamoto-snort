/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextSessionCommands.hpp>

#include <AppManager.hpp>
#include <BlockingListManager.hpp>
#include <ControlVNextStreamManager.hpp>
#include <DnsListener.hpp>
#include <HostManager.hpp>
#include <PackageListener.hpp>
#include <PacketManager.hpp>
#include <PerfMetrics.hpp>
#include <RulesManager.hpp>
#include <Settings.hpp>
#include <sucre-snort.hpp>

#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ControlVNextSessionCommands {

namespace {

[[nodiscard]] rapidjson::Value makeString(const std::string_view value,
                                         rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out;
    out.SetString(value.data(), static_cast<rapidjson::SizeType>(value.size()), alloc);
    return out;
}

[[nodiscard]] bool isValidToggleValue(const rapidjson::Value &value, uint32_t &out) {
    if (!value.IsUint()) {
        return false;
    }
    const uint32_t v = value.GetUint();
    if (v > 1) {
        return false;
    }
    out = v;
    return true;
}

[[nodiscard]] bool isValidIfaceKindMask(const uint32_t mask) {
    if (mask > std::numeric_limits<uint8_t>::max()) {
        return false;
    }
    constexpr uint32_t allowed = 1u | 2u | 4u | 128u;
    return (mask & ~allowed) == 0;
}

[[nodiscard]] const char *ifaceKindStrFromBit(const uint8_t bit) noexcept {
    switch (bit) {
    case 1:
        return "wifi";
    case 2:
        return "data";
    case 4:
        return "vpn";
    case 128:
        return "unmanaged";
    default:
        return "unmanaged";
    }
}

[[nodiscard]] std::optional<std::string_view>
unknownArgsKey(const rapidjson::Value &args, std::initializer_list<std::string_view> allowed) {
    return ControlVNext::findUnknownKey(args, allowed);
}

} // namespace

std::optional<ResponsePlan> handleDaemonCommand(const ControlVNext::RequestView &request,
                                                const ControlVNextSession::Limits &limits) {
    (void)limits;
    const uint32_t id = request.id;
    const rapidjson::Value &args = *request.args;

    const auto requireEmptyArgs = [&](const std::string_view cmd) -> std::optional<rapidjson::Document> {
        if (const auto unknown = unknownArgsKey(args, {}); unknown.has_value()) {
            return ControlVNext::makeErrorResponse(
                id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
        }
        (void)cmd;
        return std::nullopt;
    };

    if (request.cmd == "RESETALL") {
        if (auto err = requireEmptyArgs("RESETALL"); err.has_value()) {
            return ResponsePlan{.response = std::move(*err)};
        }

        // Force-stop and disconnect any active vNext stream subscriptions before resetting state.
        // RESETALL must not be blocked by slow stream consumers.
        for (const int fd : controlVNextStream.resetAll()) {
            (void)::shutdown(fd, SHUT_RDWR);
        }
        // Best-effort cleanup: legacy stream files are debug artifacts (no compatibility promise).
        (void)::unlink(settings.saveDnsStream.c_str());

        perfMetrics.resetAll();
        settings.reset();
        Settings::clearSaveTreeForResetAll();
        appManager.reset();
        domManager.reset();
        blockingListManager.reset();
        rulesManager.reset();
        pktManager.reset();
        hostManager.reset();
        dnsListener.reset();
        pkgListener.reset();
        snortSave();

        rapidjson::Document response = ControlVNext::makeOkResponse(id, nullptr);
        return ResponsePlan{.response = std::move(response)};
    }

    if (request.cmd == "APPS.LIST") {
        if (const auto unknown = unknownArgsKey(args, {"query", "userId", "limit"}); unknown.has_value()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
            return ResponsePlan{.response = std::move(response)};
        }

        std::string query;
        if (const auto it = args.FindMember("query"); it != args.MemberEnd()) {
            if (!it->value.IsString()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.query must be string");
                return ResponsePlan{.response = std::move(response)};
            }
            query.assign(it->value.GetString(), it->value.GetStringLength());
        }

        std::optional<uint32_t> userId;
        if (const auto it = args.FindMember("userId"); it != args.MemberEnd()) {
            if (!it->value.IsUint()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.userId must be u32");
                return ResponsePlan{.response = std::move(response)};
            }
            userId = it->value.GetUint();
        }

        uint32_t limit = 200;
        if (const auto it = args.FindMember("limit"); it != args.MemberEnd()) {
            if (!it->value.IsUint()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.limit must be u32");
                return ResponsePlan{.response = std::move(response)};
            }
            limit = it->value.GetUint();
        }
        if (limit == 0) {
            limit = 200;
        }
        if (limit > 1000) {
            limit = 1000;
        }

        const auto apps = appManager.snapshotByUid(userId);

        rapidjson::Document result(rapidjson::kObjectType);
        auto &alloc = result.GetAllocator();
        rapidjson::Value appsValue(rapidjson::kArrayType);

        bool truncated = false;
        uint32_t added = 0;

        const auto matchesQuery = [&](const App::Ptr &app) -> bool {
            if (query.empty()) {
                return true;
            }
            const std::string canonical = app->name();
            if (canonical.find(query) != std::string::npos) {
                return true;
            }
            for (const auto &name : app->names()) {
                if (name.find(query) != std::string::npos) {
                    return true;
                }
            }
            return false;
        };

        for (const auto &app : apps) {
            if (!matchesQuery(app)) {
                continue;
            }
            if (added >= limit) {
                truncated = true;
                break;
            }

            rapidjson::Value item(rapidjson::kObjectType);
            item.AddMember("uid", app->uid(), alloc);
            item.AddMember("userId", app->userId(), alloc);
            const std::string canonical = app->name();
            item.AddMember("app", makeString(canonical, alloc), alloc);

            rapidjson::Value allNamesValue(rapidjson::kArrayType);
            allNamesValue.PushBack(makeString(canonical, alloc), alloc);
            for (const auto &name : app->names()) {
                if (name == canonical) {
                    continue;
                }
                allNamesValue.PushBack(makeString(name, alloc), alloc);
            }
            item.AddMember("allNames", allNamesValue, alloc);

            appsValue.PushBack(item, alloc);
            added++;
        }

        result.AddMember("apps", appsValue, alloc);
        result.AddMember("truncated", truncated, alloc);

        rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
        return ResponsePlan{.response = std::move(response)};
    }

    if (request.cmd == "IFACES.LIST") {
        if (auto err = requireEmptyArgs("IFACES.LIST"); err.has_value()) {
            return ResponsePlan{.response = std::move(*err)};
        }

        pktManager.refreshIfacesOnce();

        auto ifaces = if_nameindex();
        if (ifaces == nullptr) {
            rapidjson::Document result(rapidjson::kObjectType);
            auto &alloc = result.GetAllocator();
            rapidjson::Value ifacesValue(rapidjson::kArrayType);
            result.AddMember("ifaces", ifacesValue, alloc);
            rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
            return ResponsePlan{.response = std::move(response)};
        }

        struct IfaceEntry {
            uint32_t ifindex = 0;
            std::string name;
            std::string kind;
            std::optional<uint32_t> type;
        };

        std::vector<IfaceEntry> entries;
        for (auto it = ifaces; it && it->if_index != 0 && it->if_name != nullptr; ++it) {
            const uint32_t ifindex = it->if_index;
            const std::string name = it->if_name;

            IfaceEntry e{};
            e.ifindex = ifindex;
            e.name = name;
            e.kind = ifaceKindStrFromBit(pktManager.ifaceKindBit(ifindex));

            const std::string typePath = std::string("/sys/class/net/") + name + "/type";
            uint32_t t = 0;
            if (std::ifstream in(typePath); in.is_open() && (in >> t)) {
                e.type = t;
            }
            entries.push_back(std::move(e));
        }
        if_freenameindex(ifaces);

        std::sort(entries.begin(), entries.end(),
                  [](const IfaceEntry &a, const IfaceEntry &b) { return a.ifindex < b.ifindex; });

        rapidjson::Document result(rapidjson::kObjectType);
        auto &alloc = result.GetAllocator();
        rapidjson::Value ifacesValue(rapidjson::kArrayType);

        for (const auto &e : entries) {
            rapidjson::Value item(rapidjson::kObjectType);
            item.AddMember("ifindex", e.ifindex, alloc);
            item.AddMember("name", makeString(e.name, alloc), alloc);
            item.AddMember("kind", makeString(e.kind, alloc), alloc);
            if (e.type.has_value()) {
                item.AddMember("type", *e.type, alloc);
            }
            ifacesValue.PushBack(item, alloc);
        }

        result.AddMember("ifaces", ifacesValue, alloc);
        rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
        return ResponsePlan{.response = std::move(response)};
    }

    if (request.cmd == "CONFIG.GET" || request.cmd == "CONFIG.SET") {
        const bool isSet = request.cmd == "CONFIG.SET";
        const auto allowed =
            isSet ? std::initializer_list<std::string_view>{"scope", "app", "set"}
                  : std::initializer_list<std::string_view>{"scope", "app", "keys"};
        if (const auto unknown = unknownArgsKey(args, allowed); unknown.has_value()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
            return ResponsePlan{.response = std::move(response)};
        }

        const auto scopeIt = args.FindMember("scope");
        if (scopeIt == args.MemberEnd()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.scope");
            return ResponsePlan{.response = std::move(response)};
        }
        if (!scopeIt->value.IsString()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.scope must be string");
            return ResponsePlan{.response = std::move(response)};
        }
        const std::string_view scope(scopeIt->value.GetString(), scopeIt->value.GetStringLength());

        const bool deviceScope = scope == "device";
        const bool appScope = scope == "app";
        if (!deviceScope && !appScope) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "INVALID_ARGUMENT", "args.scope must be \"device\" or \"app\"");
            return ResponsePlan{.response = std::move(response)};
        }

        const auto appIt = args.FindMember("app");
        if (deviceScope) {
            if (appIt != args.MemberEnd()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.app not allowed for device scope");
                return ResponsePlan{.response = std::move(response)};
            }
        } else {
            if (appIt == args.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.app");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!appIt->value.IsObject()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.app must be object");
                return ResponsePlan{.response = std::move(response)};
            }
        }

        const auto resolveApp = [&]() -> std::pair<App::Ptr, std::optional<rapidjson::Document>> {
            if (!appScope) {
                return {nullptr, std::nullopt};
            }

            const rapidjson::Value &selector = appIt->value;
            if (const auto unknown = ControlVNext::findUnknownKey(selector, {"uid", "pkg", "userId"});
                unknown.has_value()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "SYNTAX_ERROR", "unknown selector key: " + std::string(*unknown));
                return {nullptr, std::move(response)};
            }

            const auto uidIt = selector.FindMember("uid");
            const auto pkgIt = selector.FindMember("pkg");
            const auto userIt = selector.FindMember("userId");

            const bool hasUid = uidIt != selector.MemberEnd();
            const bool hasPkg = pkgIt != selector.MemberEnd();
            const bool hasUser = userIt != selector.MemberEnd();

            if (hasUid) {
                if (hasPkg || hasUser) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT", "selector must be either {uid} or {pkg,userId}");
                    return {nullptr, std::move(response)};
                }
                if (!uidIt->value.IsUint()) {
                    rapidjson::Document response =
                        ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "selector.uid must be u32");
                    return {nullptr, std::move(response)};
                }
                const auto app = appManager.find(uidIt->value.GetUint());
                if (!app) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "SELECTOR_NOT_FOUND", "app selector not found");
                    auto &alloc = response.GetAllocator();
                    rapidjson::Value candidates(rapidjson::kArrayType);
                    response["error"].AddMember("candidates", candidates, alloc);
                    return {nullptr, std::move(response)};
                }
                return {app, std::nullopt};
            }

            if (hasPkg || hasUser) {
                if (!hasPkg || !hasUser) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "MISSING_ARGUMENT", "selector requires pkg and userId");
                    return {nullptr, std::move(response)};
                }
                if (!pkgIt->value.IsString()) {
                    rapidjson::Document response =
                        ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "selector.pkg must be string");
                    return {nullptr, std::move(response)};
                }
                if (!userIt->value.IsUint()) {
                    rapidjson::Document response =
                        ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "selector.userId must be u32");
                    return {nullptr, std::move(response)};
                }
                const std::string pkg(pkgIt->value.GetString(), pkgIt->value.GetStringLength());
                const uint32_t userId = userIt->value.GetUint();
                const auto app = appManager.findByName(pkg, userId);
                if (!app) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "SELECTOR_NOT_FOUND", "app selector not found");
                    auto &alloc = response.GetAllocator();
                    rapidjson::Value candidates(rapidjson::kArrayType);
                    response["error"].AddMember("candidates", candidates, alloc);
                    return {nullptr, std::move(response)};
                }
                return {app, std::nullopt};
            }

            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "selector requires uid or pkg+userId");
            return {nullptr, std::move(response)};
        };

        auto [targetApp, selectorError] = resolveApp();
        if (selectorError.has_value()) {
            return ResponsePlan{.response = std::move(*selectorError)};
        }

        if (!isSet) {
            const auto keysIt = args.FindMember("keys");
            if (keysIt == args.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.keys");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!keysIt->value.IsArray()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.keys must be array");
                return ResponsePlan{.response = std::move(response)};
            }

            rapidjson::Document result(rapidjson::kObjectType);
            auto &alloc = result.GetAllocator();
            rapidjson::Value values(rapidjson::kObjectType);

            for (const auto &keyVal : keysIt->value.GetArray()) {
                if (!keyVal.IsString()) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT", "args.keys items must be string");
                    return ResponsePlan{.response = std::move(response)};
                }
                const std::string_view key(keyVal.GetString(), keyVal.GetStringLength());
                rapidjson::Value keyName = makeString(key, alloc);

                if (deviceScope) {
                    if (key == "block.enabled") {
                        values.AddMember(keyName, settings.blockEnabled() ? 1 : 0, alloc);
                    } else if (key == "iprules.enabled") {
                        values.AddMember(keyName, settings.ipRulesEnabled() ? 1 : 0, alloc);
                    } else if (key == "rdns.enabled") {
                        values.AddMember(keyName, settings.reverseDns() ? 1 : 0, alloc);
                    } else if (key == "perfmetrics.enabled") {
                        values.AddMember(keyName, perfMetrics.enabled() ? 1 : 0, alloc);
                    } else if (key == "block.mask.default") {
                        values.AddMember(keyName, static_cast<uint32_t>(settings.blockMask()), alloc);
                    } else if (key == "block.ifaceKindMask.default") {
                        values.AddMember(keyName, static_cast<uint32_t>(settings.blockIface()), alloc);
                    } else {
                        rapidjson::Document response =
                            ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "unsupported key: " + std::string(key));
                        return ResponsePlan{.response = std::move(response)};
                    }
                } else {
                    if (key == "tracked") {
                        values.AddMember(keyName, targetApp->tracked() ? 1 : 0, alloc);
                    } else if (key == "block.mask") {
                        values.AddMember(keyName, static_cast<uint32_t>(targetApp->blockMask()), alloc);
                    } else if (key == "block.ifaceKindMask") {
                        values.AddMember(keyName, static_cast<uint32_t>(targetApp->blockIface()), alloc);
                    } else if (key == "domain.custom.enabled") {
                        values.AddMember(keyName, targetApp->useCustomList() ? 1 : 0, alloc);
                    } else {
                        rapidjson::Document response =
                            ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "unsupported key: " + std::string(key));
                        return ResponsePlan{.response = std::move(response)};
                    }
                }
            }

            result.AddMember("values", values, alloc);
            rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
            return ResponsePlan{.response = std::move(response)};
        }

        const auto setIt = args.FindMember("set");
        if (setIt == args.MemberEnd()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.set");
            return ResponsePlan{.response = std::move(response)};
        }
        if (!setIt->value.IsObject()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.set must be object");
            return ResponsePlan{.response = std::move(response)};
        }

        const rapidjson::Value &setObj = setIt->value;

        struct DeviceUpdates {
            std::optional<bool> blockEnabled;
            std::optional<bool> ipRulesEnabled;
            std::optional<bool> rdnsEnabled;
            std::optional<bool> perfMetricsEnabled;
            std::optional<uint8_t> blockMaskDefault;
            std::optional<uint8_t> blockIfaceKindMaskDefault;
        };

        struct AppUpdates {
            std::optional<bool> tracked;
            std::optional<uint8_t> blockMask;
            std::optional<uint8_t> blockIfaceKindMask;
            std::optional<bool> domainCustomEnabled;
        };

        DeviceUpdates deviceUpdates;
        AppUpdates appUpdates;

        for (auto it = setObj.MemberBegin(); it != setObj.MemberEnd(); ++it) {
            if (!it->name.IsString()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.set keys must be string");
                return ResponsePlan{.response = std::move(response)};
            }
            const std::string_view key(it->name.GetString(), it->name.GetStringLength());
            const rapidjson::Value &value = it->value;

            if (deviceScope) {
                if (key == "block.enabled") {
                    uint32_t v = 0;
                    if (!isValidToggleValue(value, v)) {
                        rapidjson::Document response =
                            ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "block.enabled must be 0|1");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    deviceUpdates.blockEnabled = (v == 1);
                } else if (key == "iprules.enabled") {
                    uint32_t v = 0;
                    if (!isValidToggleValue(value, v)) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "iprules.enabled must be 0|1");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    deviceUpdates.ipRulesEnabled = (v == 1);
                } else if (key == "rdns.enabled") {
                    uint32_t v = 0;
                    if (!isValidToggleValue(value, v)) {
                        rapidjson::Document response =
                            ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "rdns.enabled must be 0|1");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    deviceUpdates.rdnsEnabled = (v == 1);
                } else if (key == "perfmetrics.enabled") {
                    uint32_t v = 0;
                    if (!isValidToggleValue(value, v)) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "perfmetrics.enabled must be 0|1");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    deviceUpdates.perfMetricsEnabled = (v == 1);
                } else if (key == "block.mask.default") {
                    if (!value.IsUint()) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "block.mask.default must be u8");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    const uint32_t raw = value.GetUint();
                    if (raw > std::numeric_limits<uint8_t>::max() || !Settings::isValidAppBlockMask(raw)) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "block.mask.default invalid");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    deviceUpdates.blockMaskDefault =
                        Settings::normalizeAppBlockMask(static_cast<uint8_t>(raw));
                } else if (key == "block.ifaceKindMask.default") {
                    if (!value.IsUint()) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "block.ifaceKindMask.default must be u8");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    const uint32_t raw = value.GetUint();
                    if (!isValidIfaceKindMask(raw)) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "block.ifaceKindMask.default invalid");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    deviceUpdates.blockIfaceKindMaskDefault = static_cast<uint8_t>(raw);
                } else {
                    rapidjson::Document response =
                        ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "unsupported key: " + std::string(key));
                    return ResponsePlan{.response = std::move(response)};
                }
            } else {
                if (key == "tracked") {
                    uint32_t v = 0;
                    if (!isValidToggleValue(value, v)) {
                        rapidjson::Document response =
                            ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "tracked must be 0|1");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    appUpdates.tracked = (v == 1);
                } else if (key == "block.mask") {
                    if (!value.IsUint()) {
                        rapidjson::Document response =
                            ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "block.mask must be u8");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    const uint32_t raw = value.GetUint();
                    if (raw > std::numeric_limits<uint8_t>::max() || !Settings::isValidAppBlockMask(raw)) {
                        rapidjson::Document response =
                            ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "block.mask invalid");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    appUpdates.blockMask = Settings::normalizeAppBlockMask(static_cast<uint8_t>(raw));
                } else if (key == "block.ifaceKindMask") {
                    if (!value.IsUint()) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "block.ifaceKindMask must be u8");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    const uint32_t raw = value.GetUint();
                    if (!isValidIfaceKindMask(raw)) {
                        rapidjson::Document response =
                            ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "block.ifaceKindMask invalid");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    appUpdates.blockIfaceKindMask = static_cast<uint8_t>(raw);
                } else if (key == "domain.custom.enabled") {
                    uint32_t v = 0;
                    if (!isValidToggleValue(value, v)) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "domain.custom.enabled must be 0|1");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    appUpdates.domainCustomEnabled = (v == 1);
                } else {
                    rapidjson::Document response =
                        ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "unsupported key: " + std::string(key));
                    return ResponsePlan{.response = std::move(response)};
                }
            }
        }

        if (deviceScope) {
            if (deviceUpdates.blockEnabled.has_value()) {
                settings.blockEnabled(*deviceUpdates.blockEnabled);
                controlVNextStream.observeBlockEnabled(*deviceUpdates.blockEnabled);
            }
            if (deviceUpdates.ipRulesEnabled.has_value()) {
                settings.ipRulesEnabled(*deviceUpdates.ipRulesEnabled);
            }
            if (deviceUpdates.rdnsEnabled.has_value()) {
                settings.reverseDns(*deviceUpdates.rdnsEnabled);
            }
            if (deviceUpdates.perfMetricsEnabled.has_value()) {
                perfMetrics.setEnabled(*deviceUpdates.perfMetricsEnabled);
            }
            if (deviceUpdates.blockMaskDefault.has_value()) {
                settings.blockMask(*deviceUpdates.blockMaskDefault);
            }
            if (deviceUpdates.blockIfaceKindMaskDefault.has_value()) {
                settings.blockIface(*deviceUpdates.blockIfaceKindMaskDefault);
            }
        } else {
            if (appUpdates.tracked.has_value()) {
                targetApp->tracked(*appUpdates.tracked);
            }
            if (appUpdates.domainCustomEnabled.has_value()) {
                targetApp->useCustomList(*appUpdates.domainCustomEnabled);
            }
            if (appUpdates.blockMask.has_value()) {
                targetApp->blockMask(*appUpdates.blockMask);
            }
            if (appUpdates.blockIfaceKindMask.has_value()) {
                targetApp->blockIface(*appUpdates.blockIfaceKindMask);
            }
            targetApp->save();
        }

        rapidjson::Document response = ControlVNext::makeOkResponse(id, nullptr);
        return ResponsePlan{.response = std::move(response)};
    }

    return std::nullopt;
}

} // namespace ControlVNextSessionCommands

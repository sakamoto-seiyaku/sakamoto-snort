/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <AppManager.hpp>
#include <ControlVNextCodec.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ControlVNextSessionCommands {

[[nodiscard]] inline rapidjson::Value makeSelectorString(const std::string_view value,
                                                         rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out;
    out.SetString(value.data(), static_cast<rapidjson::SizeType>(value.size()), alloc);
    return out;
}

[[nodiscard]] inline std::pair<App::Ptr, std::optional<rapidjson::Document>>
resolveAppSelector(const uint32_t id, const rapidjson::Value &selector) {
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
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "SELECTOR_NOT_FOUND", "app selector not found");
            auto &alloc = response.GetAllocator();
            response["error"].AddMember("candidates", rapidjson::Value(rapidjson::kArrayType), alloc);
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

        std::vector<App::Ptr> matches;
        for (const auto &app : appManager.snapshotByUid(userId)) {
            if (app->name() == pkg) {
                matches.push_back(app);
            }
        }

        if (matches.empty()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "SELECTOR_NOT_FOUND", "app selector not found");
            auto &alloc = response.GetAllocator();
            response["error"].AddMember("candidates", rapidjson::Value(rapidjson::kArrayType), alloc);
            return {nullptr, std::move(response)};
        }

        if (matches.size() == 1) {
            return {matches[0], std::nullopt};
        }

        std::sort(matches.begin(), matches.end(),
                  [](const App::Ptr &a, const App::Ptr &b) { return a->uid() < b->uid(); });

        rapidjson::Document response =
            ControlVNext::makeErrorResponse(id, "SELECTOR_AMBIGUOUS", "app selector ambiguous");
        auto &alloc = response.GetAllocator();
        rapidjson::Value candidates(rapidjson::kArrayType);
        for (const auto &app : matches) {
            rapidjson::Value item(rapidjson::kObjectType);
            item.AddMember("uid", app->uid(), alloc);
            item.AddMember("userId", app->userId(), alloc);
            const std::string canonical = app->name();
            item.AddMember("app", makeSelectorString(canonical, alloc), alloc);
            candidates.PushBack(item, alloc);
        }
        response["error"].AddMember("candidates", candidates, alloc);
        return {nullptr, std::move(response)};
    }

    rapidjson::Document response =
        ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "selector requires uid or pkg+userId");
    return {nullptr, std::move(response)};
}

} // namespace ControlVNextSessionCommands

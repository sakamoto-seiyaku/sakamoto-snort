/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <ControlVNextStreamManager.hpp>

#include <rapidjson/document.h>

#include <cstdint>

namespace ControlVNextStreamJson {

[[nodiscard]] rapidjson::Document makeStartedNotice(ControlVNextStreamManager::Type stream,
                                                    std::uint32_t effectiveHorizonSec,
                                                    std::uint32_t effectiveMinSize);

[[nodiscard]] rapidjson::Document makeSuppressedNotice(ControlVNextStreamManager::Type stream,
                                                       std::uint32_t windowMs,
                                                       const TrafficSnapshot &traffic);

[[nodiscard]] rapidjson::Document makeDroppedNotice(ControlVNextStreamManager::Type stream,
                                                    std::uint32_t windowMs,
                                                    std::uint64_t droppedEvents);

[[nodiscard]] rapidjson::Document makeDnsEvent(const ControlVNextStreamManager::DnsEvent &event);

[[nodiscard]] rapidjson::Document makePktEvent(const ControlVNextStreamManager::PktEvent &event);

[[nodiscard]] rapidjson::Document makeActivityEvent(const ControlVNextStreamManager::ActivityEvent &event);

} // namespace ControlVNextStreamJson


/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextSessionCommands.hpp>

#include <AppManager.hpp>
#include <ControlVNextSessionSelectors.hpp>
#include <DomainManager.hpp>
#include <PacketManager.hpp>
#include <PerfMetrics.hpp>
#include <FlowTelemetry.hpp>
#include <RulesManager.hpp>
#include <TrafficCounters.hpp>

#include <algorithm>
#include <cstdint>
#include <mutex>
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

[[nodiscard]] std::optional<std::string_view>
unknownArgsKey(const rapidjson::Value &args, const std::initializer_list<std::string_view> allowed) {
    return ControlVNext::findUnknownKey(args, allowed);
}

[[nodiscard]] bool isSupportedMetricName(const std::string_view name) noexcept {
    return name == "perf" || name == "reasons" || name == "domainSources" || name == "traffic" ||
           name == "conntrack" || name == "domainRuleStats" || name == "telemetry";
}

[[nodiscard]] bool nameAllowsAppSelector(const std::string_view name) noexcept {
    return name == "traffic" || name == "domainSources";
}

void addPerfSummary(rapidjson::Value &out, rapidjson::Document::AllocatorType &alloc,
                    const PerfMetrics::Summary &s) {
    out.AddMember("samples", s.samples, alloc);
    out.AddMember("min", s.min, alloc);
    out.AddMember("avg", s.avg, alloc);
    out.AddMember("p50", s.p50, alloc);
    out.AddMember("p95", s.p95, alloc);
    out.AddMember("p99", s.p99, alloc);
    out.AddMember("max", s.max, alloc);
}

void addDomainSources(rapidjson::Value &out, rapidjson::Document::AllocatorType &alloc,
                      const DomainPolicySourcesSnapshot &snap) {
    for (const auto source : kDomainPolicySources) {
        const size_t idx = static_cast<size_t>(source);
        rapidjson::Value item(rapidjson::kObjectType);
        item.AddMember("allow", snap.sources[idx].allow, alloc);
        item.AddMember("block", snap.sources[idx].block, alloc);
        out.AddMember(makeString(domainPolicySourceStr(source), alloc), item, alloc);
    }
}

void addTraffic(rapidjson::Value &out, rapidjson::Document::AllocatorType &alloc,
                const TrafficSnapshot &snap) {
    for (size_t i = 0; i < kTrafficMetricKeys.size(); ++i) {
        rapidjson::Value item(rapidjson::kObjectType);
        item.AddMember("allow", snap.dims[i].allow, alloc);
        item.AddMember("block", snap.dims[i].block, alloc);
        out.AddMember(makeString(kTrafficMetricKeys[i], alloc), item, alloc);
    }
}

} // namespace

std::optional<ResponsePlan> handleMetricsCommand(const ControlVNext::RequestView &request,
                                                 const ControlVNextSession::Limits &limits) {
    (void)limits;
    const uint32_t id = request.id;
    const rapidjson::Value &args = *request.args;

    const bool isGet = request.cmd == "METRICS.GET";
    const bool isReset = request.cmd == "METRICS.RESET";
    if (!isGet && !isReset) {
        return std::nullopt;
    }

    if (const auto unknown = unknownArgsKey(args, {"name", "app"}); unknown.has_value()) {
        rapidjson::Document response =
            ControlVNext::makeErrorResponse(id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
        return ResponsePlan{.response = std::move(response)};
    }

    const auto nameIt = args.FindMember("name");
    if (nameIt == args.MemberEnd()) {
        rapidjson::Document response =
            ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.name");
        return ResponsePlan{.response = std::move(response)};
    }
    if (!nameIt->value.IsString()) {
        rapidjson::Document response =
            ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.name must be string");
        return ResponsePlan{.response = std::move(response)};
    }
    const std::string_view name(nameIt->value.GetString(), nameIt->value.GetStringLength());
    if (!isSupportedMetricName(name)) {
        rapidjson::Document response =
            ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "unknown metrics name: " + std::string(name));
        return ResponsePlan{.response = std::move(response)};
    }

    const auto appIt = args.FindMember("app");
    const bool hasApp = appIt != args.MemberEnd();
    App::Ptr app = nullptr;

    if (hasApp) {
        if (!nameAllowsAppSelector(name)) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "INVALID_ARGUMENT", "args.app is only allowed for name=traffic or name=domainSources");
            return ResponsePlan{.response = std::move(response)};
        }
        if (!appIt->value.IsObject()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.app must be object");
            return ResponsePlan{.response = std::move(response)};
        }
        auto [resolvedApp, selectorErr] = resolveAppSelector(id, appIt->value);
        if (selectorErr.has_value()) {
            return ResponsePlan{.response = std::move(*selectorErr)};
        }
        app = std::move(resolvedApp);
    }

    if (isGet) {
        rapidjson::Document result(rapidjson::kObjectType);
        auto &alloc = result.GetAllocator();

        if (name == "perf") {
            const auto snap = perfMetrics.snapshotForControl();
            rapidjson::Value perf(rapidjson::kObjectType);

            rapidjson::Value nfq(rapidjson::kObjectType);
            addPerfSummary(nfq, alloc, snap.nfq_total_us);
            perf.AddMember("nfq_total_us", nfq, alloc);

            rapidjson::Value dns(rapidjson::kObjectType);
            addPerfSummary(dns, alloc, snap.dns_decision_us);
            perf.AddMember("dns_decision_us", dns, alloc);

            result.AddMember("perf", perf, alloc);
        } else if (name == "reasons") {
            const auto snap = pktManager.reasonMetricsSnapshot();
            rapidjson::Value reasons(rapidjson::kObjectType);
            for (const auto reasonId : kPacketReasonIds) {
                const size_t idx = static_cast<size_t>(reasonId);
                rapidjson::Value item(rapidjson::kObjectType);
                item.AddMember("packets", snap.reasons[idx].packets, alloc);
                item.AddMember("bytes", snap.reasons[idx].bytes, alloc);
                reasons.AddMember(makeString(packetReasonIdStr(reasonId), alloc), item, alloc);
            }
            result.AddMember("reasons", reasons, alloc);
        } else if (name == "domainSources") {
            DomainPolicySourcesSnapshot snap{};
            if (app != nullptr) {
                snap = app->domainPolicySourcesSnapshot();
                result.AddMember("uid", app->uid(), alloc);
                result.AddMember("userId", app->userId(), alloc);
                const std::string canonical = app->name();
                result.AddMember("app", makeString(canonical, alloc), alloc);
            } else {
                snap = domManager.domainPolicySourcesSnapshot();
            }

            rapidjson::Value sources(rapidjson::kObjectType);
            addDomainSources(sources, alloc, snap);
            result.AddMember("sources", sources, alloc);
        } else if (name == "traffic") {
            TrafficSnapshot snap{};
            if (app != nullptr) {
                snap = app->trafficSnapshot();
                result.AddMember("uid", app->uid(), alloc);
                result.AddMember("userId", app->userId(), alloc);
                const std::string canonical = app->name();
                result.AddMember("app", makeString(canonical, alloc), alloc);
            } else {
                const auto apps = appManager.snapshotByUid(std::nullopt);
                for (const auto &one : apps) {
                    const auto oneSnap = one->trafficSnapshot();
                    for (size_t i = 0; i < kTrafficMetricKeys.size(); ++i) {
                        snap.dims[i].allow += oneSnap.dims[i].allow;
                        snap.dims[i].block += oneSnap.dims[i].block;
                    }
                }
            }

            rapidjson::Value traffic(rapidjson::kObjectType);
            addTraffic(traffic, alloc, snap);
            result.AddMember("traffic", traffic, alloc);
        } else if (name == "conntrack") {
            const auto snap = pktManager.conntrackMetricsSnapshot();
            rapidjson::Value ct(rapidjson::kObjectType);
            ct.AddMember("totalEntries", snap.totalEntries, alloc);
            ct.AddMember("creates", snap.creates, alloc);
            ct.AddMember("expiredRetires", snap.expiredRetires, alloc);
            ct.AddMember("overflowDrops", snap.overflowDrops, alloc);
            {
                rapidjson::Value byFamily(rapidjson::kObjectType);
                auto addFam = [&](const char *name,
                                  const Conntrack::MetricsSnapshot::Family &fam) {
                    rapidjson::Value obj(rapidjson::kObjectType);
                    obj.AddMember("totalEntries", fam.totalEntries, alloc);
                    obj.AddMember("creates", fam.creates, alloc);
                    obj.AddMember("expiredRetires", fam.expiredRetires, alloc);
                    obj.AddMember("overflowDrops", fam.overflowDrops, alloc);
                    byFamily.AddMember(makeString(name, alloc), obj, alloc);
                };
                addFam("ipv4", snap.byFamily.ipv4);
                addFam("ipv6", snap.byFamily.ipv6);
                ct.AddMember("byFamily", byFamily, alloc);
            }
            result.AddMember("conntrack", ct, alloc);
        } else if (name == "domainRuleStats") {
            const auto snap = rulesManager.snapshotBaselineRuleStats();
            rapidjson::Value rules(rapidjson::kArrayType);
            for (const auto &r : snap) {
                rapidjson::Value item(rapidjson::kObjectType);
                item.AddMember("ruleId", r.ruleId, alloc);
                item.AddMember("allowHits", r.allowHits, alloc);
                item.AddMember("blockHits", r.blockHits, alloc);
                rules.PushBack(item, alloc);
            }
            rapidjson::Value stats(rapidjson::kObjectType);
            stats.AddMember("rules", rules, alloc);
            result.AddMember("domainRuleStats", stats, alloc);
        } else if (name == "telemetry") {
            const auto snap = flowTelemetry.healthSnapshot();
            rapidjson::Value tel(rapidjson::kObjectType);
            tel.AddMember("enabled", snap.enabled, alloc);
            tel.AddMember("consumerPresent", snap.consumerPresent, alloc);
            tel.AddMember("sessionId", snap.sessionId, alloc);
            tel.AddMember("slotBytes", snap.slotBytes, alloc);
            tel.AddMember("slotCount", snap.slotCount, alloc);
            tel.AddMember("recordsWritten", snap.recordsWritten, alloc);
            tel.AddMember("recordsDropped", snap.recordsDropped, alloc);
            tel.AddMember("lastDropReason",
                          makeString(flowTelemetryDropReasonStr(snap.lastDropReason), alloc), alloc);
            if (snap.lastError.has_value()) {
                tel.AddMember("lastError", makeString(*snap.lastError, alloc), alloc);
            }
            result.AddMember("telemetry", tel, alloc);
        }

        rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
        return ResponsePlan{.response = std::move(response)};
    }

    // METRICS.RESET
    if (name == "perf") {
        perfMetrics.reset();
        rapidjson::Document response = ControlVNext::makeOkResponse(id, nullptr);
        return ResponsePlan{.response = std::move(response)};
    }
    if (name == "reasons") {
        pktManager.resetReasonMetrics();
        rapidjson::Document response = ControlVNext::makeOkResponse(id, nullptr);
        return ResponsePlan{.response = std::move(response)};
    }
    if (name == "domainSources") {
        if (app != nullptr) {
            app->resetDomainPolicySources();
        } else {
            domManager.resetDomainPolicySources();
            appManager.resetDomainPolicySources();
        }
        rapidjson::Document response = ControlVNext::makeOkResponse(id, nullptr);
        return ResponsePlan{.response = std::move(response)};
    }
    if (name == "traffic") {
        if (app != nullptr) {
            app->resetTraffic();
        } else {
            const auto apps = appManager.snapshotByUid(std::nullopt);
            for (const auto &one : apps) {
                one->resetTraffic();
            }
        }
        rapidjson::Document response = ControlVNext::makeOkResponse(id, nullptr);
        return ResponsePlan{.response = std::move(response)};
    }
    if (name == "conntrack") {
        rapidjson::Document response = ControlVNext::makeErrorResponse(
            id, "INVALID_ARGUMENT", "conntrack does not support METRICS.RESET; use RESETALL");
        return ResponsePlan{.response = std::move(response)};
    }
    if (name == "domainRuleStats") {
        // Keep reset boundary easy to reason about vs concurrent DNS updates (which hold shared lock).
        const std::unique_lock<std::shared_mutex> g(mutexListeners);
        rulesManager.resetRuleHits();
        rapidjson::Document response = ControlVNext::makeOkResponse(id, nullptr);
        return ResponsePlan{.response = std::move(response)};
    }

    rapidjson::Document response = ControlVNext::makeErrorResponse(
        id, "INVALID_ARGUMENT", "unsupported metrics reset name: " + std::string(name));
    return ResponsePlan{.response = std::move(response)};
}

} // namespace ControlVNextSessionCommands

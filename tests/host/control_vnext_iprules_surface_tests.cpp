/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextCodec.hpp>
#include <ControlVNextSessionCommands.hpp>
#include <ControlVNextSession.hpp>

#include <AppManager.hpp>
#include <BlockingListManager.hpp>
#include <DomainManager.hpp>
#include <PacketManager.hpp>
#include <RulesManager.hpp>
#include <Settings.hpp>
#include <Streamable.hpp>
#include <sucre-snort.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// ---- Test-only Streamable + PacketManager seams ----
//
// The production PacketManager implementation depends on the full Streamable
// + SocketIO graph. vNext IPRULES surface tests only need pktManager.ipRules().

template <class Item>
Streamable<Item>::Streamable()
    : _saver("") {}

template <class Item>
Streamable<Item>::Streamable(const std::string &filename)
    : _saver(filename) {}

template <class Item>
Streamable<Item>::~Streamable() = default;

PacketManager::PacketManager() = default;
PacketManager::~PacketManager() = default;

// ---- Test-only AppManager implementation seam ----
//
// Mirror control_vnext_domain_surface_tests: in-memory selector registry sufficient
// for {uid} and {pkg,userId} resolution.

AppManager::AppManager() = default;
AppManager::~AppManager() = default;

const App::Ptr AppManager::make(const App::Uid uid) {
    {
        const std::shared_lock<std::shared_mutex> lock(_mutexByUid);
        if (auto it = _byUid.find(uid); it != _byUid.end()) {
            return it->second;
        }
    }

    const std::scoped_lock lock(_mutexByUid, _mutexByName);
    auto [it, inserted] = _byUid.emplace(uid, std::make_shared<App>(uid));
    const auto app = it->second;
    if (inserted) {
        _byName.emplace(app->name(), app);
    }
    return app;
}

const App::Ptr AppManager::find(const App::Uid uid) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByUid);
    auto it = _byUid.find(uid);
    return it != _byUid.end() ? it->second : nullptr;
}

const App::Ptr AppManager::findByName(const std::string &name, const uint32_t userId) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByUid);
    for (const auto &[uid, app] : _byUid) {
        if (uid / 100000 == userId && app->name() == name) {
            return app;
        }
    }
    return nullptr;
}

std::vector<App::Ptr> AppManager::snapshotByUid(const std::optional<uint32_t> userId) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByUid);
    std::vector<App::Ptr> out;
    out.reserve(_byUid.size());
    for (const auto &[_, app] : _byUid) {
        if (userId.has_value() && app->userId() != userId.value()) {
            continue;
        }
        out.push_back(app);
    }
    return out;
}

void AppManager::install(const App::Uid uid, const App::NamesVec &names) {
    const std::scoped_lock lock(_mutexByUid, _mutexByName);
    if (auto it = _byUid.find(uid); it != _byUid.end()) {
        _byName.erase(it->second->name());
        _byUid.erase(it);
    }

    std::shared_ptr<App> app;
    if (names.size() == 1) {
        app = std::make_shared<App>(uid, names[0]);
    } else {
        app = std::make_shared<App>(uid, names);
    }
    _byUid.emplace(uid, app);
    _byName.emplace(app->name(), app);
}

void AppManager::reset() {
    const std::scoped_lock lock(_mutexByUid, _mutexByName);
    _byUid.clear();
    _byName.clear();
}

// Provide the globals normally defined in src/sucre-snort.cpp.
Settings settings;
DomainManager domManager;
RulesManager rulesManager;
BlockingListManager blockingListManager;
AppManager appManager;
PacketManager pktManager;
std::shared_mutex mutexListeners;

namespace {

constexpr uint32_t kUid = 10123;
constexpr ControlVNextSession::Limits kLimits{.maxRequestBytes = 16 * 1024 * 1024,
                                              .maxResponseBytes = 16 * 1024 * 1024};

struct Rpc {
    static rapidjson::Document call(const uint32_t id, const std::string_view cmd,
                                    const rapidjson::Value &args) {
        rapidjson::Document req = ControlVNext::makeRequest(id, cmd, args);

        ControlVNext::RequestView view;
        const auto envErr = ControlVNext::parseRequestEnvelope(req, view);
        EXPECT_FALSE(envErr.has_value());
        if (envErr.has_value()) {
            return ControlVNext::makeErrorResponse(id, envErr->code, envErr->message);
        }

        auto plan = ControlVNextSessionCommands::handleIpRulesCommand(view, kLimits);
        EXPECT_TRUE(plan.has_value());
        if (!plan.has_value()) {
            return ControlVNext::makeErrorResponse(id, "UNSUPPORTED_COMMAND", "not handled by iprules handler");
        }
        return std::move(plan->response);
    }
};

rapidjson::Value makeRule(rapidjson::Document::AllocatorType &alloc, const char *clientRuleId,
                          const char *dstCidr, const char *family = "ipv4") {
    rapidjson::Value r(rapidjson::kObjectType);
    r.AddMember("clientRuleId", rapidjson::Value(clientRuleId, alloc), alloc);
    r.AddMember("action", rapidjson::Value("block", alloc), alloc);
    r.AddMember("priority", 10, alloc);
    r.AddMember("enabled", 1u, alloc);
    r.AddMember("enforce", 1u, alloc);
    r.AddMember("log", 0u, alloc);
    r.AddMember("family", rapidjson::Value(family, alloc), alloc);
    r.AddMember("dir", rapidjson::Value("out", alloc), alloc);
    r.AddMember("iface", rapidjson::Value("any", alloc), alloc);
    r.AddMember("ifindex", 0u, alloc);
    r.AddMember("proto", rapidjson::Value("tcp", alloc), alloc);

    rapidjson::Value ct(rapidjson::kObjectType);
    ct.AddMember("state", rapidjson::Value("any", alloc), alloc);
    ct.AddMember("direction", rapidjson::Value("any", alloc), alloc);
    r.AddMember("ct", ct, alloc);

    r.AddMember("src", rapidjson::Value("any", alloc), alloc);
    r.AddMember("dst", rapidjson::Value(dstCidr, alloc), alloc);
    r.AddMember("sport", rapidjson::Value("any", alloc), alloc);
    r.AddMember("dport", rapidjson::Value("443", alloc), alloc);
    return r;
}

class ControlVNextIpRulesSurfaceTest : public ::testing::Test {
protected:
    void SetUp() override {
        settings.reset();
        blockingListManager.reset();
        domManager.reset();
        rulesManager.reset();
        appManager.reset();
        pktManager.ipRules().resetAll();

        appManager.install(kUid, {"com.example"});
    }
};

TEST_F(ControlVNextIpRulesSurfaceTest, PreflightShapeAndTypes) {
    rapidjson::Document args(rapidjson::kObjectType);
    const rapidjson::Document resp = Rpc::call(/*id=*/1, "IPRULES.PREFLIGHT", args);

    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    ASSERT_TRUE(view.ok);
    ASSERT_NE(view.result, nullptr);

    const auto &result = *view.result;
    ASSERT_TRUE(result.HasMember("summary"));
    ASSERT_TRUE(result.HasMember("byFamily"));
    ASSERT_TRUE(result.HasMember("limits"));
    ASSERT_TRUE(result.HasMember("warnings"));
    ASSERT_TRUE(result.HasMember("violations"));

    const auto &summary = result["summary"];
    ASSERT_TRUE(summary.IsObject());
    EXPECT_TRUE(summary["rulesTotal"].IsUint64());
    EXPECT_TRUE(summary["rangeRulesTotal"].IsUint64());
    EXPECT_TRUE(summary["ctRulesTotal"].IsUint64());
    EXPECT_TRUE(summary["ctUidsTotal"].IsUint64());
    EXPECT_TRUE(summary["subtablesTotal"].IsUint64());
    EXPECT_TRUE(summary["maxSubtablesPerUid"].IsUint64());
    EXPECT_TRUE(summary["maxRangeRulesPerBucket"].IsUint64());

    const auto &byFamily = result["byFamily"];
    ASSERT_TRUE(byFamily.IsObject());
    ASSERT_TRUE(byFamily.HasMember("ipv4"));
    ASSERT_TRUE(byFamily.HasMember("ipv6"));
    ASSERT_TRUE(byFamily["ipv4"].IsObject());
    ASSERT_TRUE(byFamily["ipv6"].IsObject());
    for (const auto fam : {"ipv4", "ipv6"}) {
        const auto &s = byFamily[fam];
        EXPECT_TRUE(s["rulesTotal"].IsUint64());
        EXPECT_TRUE(s["rangeRulesTotal"].IsUint64());
        EXPECT_TRUE(s["ctRulesTotal"].IsUint64());
        EXPECT_TRUE(s["ctUidsTotal"].IsUint64());
        EXPECT_TRUE(s["subtablesTotal"].IsUint64());
        EXPECT_TRUE(s["maxSubtablesPerUid"].IsUint64());
        EXPECT_TRUE(s["maxRangeRulesPerBucket"].IsUint64());
    }

    const auto &limits = result["limits"];
    ASSERT_TRUE(limits.IsObject());
    ASSERT_TRUE(limits["recommended"].IsObject());
    ASSERT_TRUE(limits["hard"].IsObject());
    EXPECT_TRUE(limits["recommended"]["maxRulesTotal"].IsUint64());
    EXPECT_TRUE(limits["recommended"]["maxSubtablesPerUid"].IsUint64());
    EXPECT_TRUE(limits["recommended"]["maxRangeRulesPerBucket"].IsUint64());
    EXPECT_TRUE(limits["hard"]["maxRulesTotal"].IsUint64());
    EXPECT_TRUE(limits["hard"]["maxSubtablesPerUid"].IsUint64());
    EXPECT_TRUE(limits["hard"]["maxRangeRulesPerBucket"].IsUint64());

    EXPECT_TRUE(result["warnings"].IsArray());
    EXPECT_TRUE(result["violations"].IsArray());
}

TEST_F(ControlVNextIpRulesSurfaceTest, PrintSortedAndHasRequiredFields) {
    // Seed two rules via APPLY so matchKey + clientRuleId are fully populated.
    rapidjson::Document applyArgs(rapidjson::kObjectType);
    auto &alloc = applyArgs.GetAllocator();
    rapidjson::Value sel(rapidjson::kObjectType);
    sel.AddMember("uid", kUid, alloc);
    applyArgs.AddMember("app", sel, alloc);
    rapidjson::Value rules(rapidjson::kArrayType);
    rules.PushBack(makeRule(alloc, "r1", "any"), alloc);
    rules.PushBack(makeRule(alloc, "r2", "1.2.3.4/24"), alloc);
    applyArgs.AddMember("rules", rules, alloc);
    const rapidjson::Document applyResp = Rpc::call(/*id=*/2, "IPRULES.APPLY", applyArgs);
    ControlVNext::ResponseView applyView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(applyResp, applyView).has_value());
    ASSERT_TRUE(applyView.ok);

    rapidjson::Document printArgs(rapidjson::kObjectType);
    auto &pAlloc = printArgs.GetAllocator();
    rapidjson::Value app(rapidjson::kObjectType);
    app.AddMember("uid", kUid, pAlloc);
    printArgs.AddMember("app", app, pAlloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/3, "IPRULES.PRINT", printArgs);
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    ASSERT_TRUE(view.ok);
    ASSERT_NE(view.result, nullptr);

    const auto &result = *view.result;
    ASSERT_TRUE(result["uid"].IsUint());
    ASSERT_EQ(result["uid"].GetUint(), kUid);

    const auto &outRules = result["rules"];
    ASSERT_TRUE(outRules.IsArray());
    ASSERT_EQ(outRules.Size(), 2u);

    const auto &a = outRules[0];
    const auto &b = outRules[1];
    ASSERT_TRUE(a["ruleId"].IsUint());
    ASSERT_TRUE(b["ruleId"].IsUint());
    EXPECT_LT(a["ruleId"].GetUint(), b["ruleId"].GetUint());

    for (const auto &r : outRules.GetArray()) {
        ASSERT_TRUE(r.HasMember("clientRuleId"));
        ASSERT_TRUE(r["clientRuleId"].IsString());
        ASSERT_TRUE(r.HasMember("matchKey"));
        ASSERT_TRUE(r["matchKey"].IsString());
        ASSERT_TRUE(r.HasMember("family"));
        ASSERT_TRUE(r["family"].IsString());
        ASSERT_TRUE(r.HasMember("stats"));
        ASSERT_TRUE(r["stats"].IsObject());
        EXPECT_TRUE(r["stats"]["hitPackets"].IsUint64());
        EXPECT_TRUE(r["stats"]["hitBytes"].IsUint64());
        EXPECT_TRUE(r["stats"]["lastHitTsNs"].IsUint64());
        EXPECT_TRUE(r["stats"]["wouldHitPackets"].IsUint64());
        EXPECT_TRUE(r["stats"]["wouldHitBytes"].IsUint64());
        EXPECT_TRUE(r["stats"]["lastWouldHitTsNs"].IsUint64());
    }
}

TEST_F(ControlVNextIpRulesSurfaceTest, ApplyRejectsForbiddenFields) {
    const auto run = [&](const char *forbiddenKey) {
        rapidjson::Document applyArgs(rapidjson::kObjectType);
        auto &alloc = applyArgs.GetAllocator();
        rapidjson::Value sel(rapidjson::kObjectType);
        sel.AddMember("uid", kUid, alloc);
        applyArgs.AddMember("app", sel, alloc);

        rapidjson::Value rules(rapidjson::kArrayType);
        rapidjson::Value r = makeRule(alloc, "r1", "any");
        if (std::string_view(forbiddenKey) == "ruleId") {
            r.AddMember("ruleId", 0u, alloc);
        } else if (std::string_view(forbiddenKey) == "matchKey") {
            r.AddMember("matchKey", rapidjson::Value("mk2|...", alloc), alloc);
        } else if (std::string_view(forbiddenKey) == "stats") {
            r.AddMember("stats", rapidjson::Value(rapidjson::kObjectType), alloc);
        }
        rules.PushBack(r, alloc);
        applyArgs.AddMember("rules", rules, alloc);

        const rapidjson::Document resp = Rpc::call(/*id=*/10, "IPRULES.APPLY", applyArgs);
        ControlVNext::ResponseView view;
        ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
        ASSERT_FALSE(view.ok);
        ASSERT_NE(view.error, nullptr);
        EXPECT_STREQ((*view.error)["code"].GetString(), "INVALID_ARGUMENT");
    };

    run("ruleId");
    run("matchKey");
    run("stats");
}

TEST_F(ControlVNextIpRulesSurfaceTest, ApplyRejectsDuplicateMatchKeyWithConflictsShape) {
    rapidjson::Document applyArgs(rapidjson::kObjectType);
    auto &alloc = applyArgs.GetAllocator();
    rapidjson::Value sel(rapidjson::kObjectType);
    sel.AddMember("uid", kUid, alloc);
    applyArgs.AddMember("app", sel, alloc);

    rapidjson::Value rules(rapidjson::kArrayType);
    rules.PushBack(makeRule(alloc, "a", "1.2.3.4/24"), alloc);
    rules.PushBack(makeRule(alloc, "b", "1.2.3.4/24"), alloc); // same match dims => same matchKey
    applyArgs.AddMember("rules", rules, alloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/20, "IPRULES.APPLY", applyArgs);
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    ASSERT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "INVALID_ARGUMENT");
    ASSERT_TRUE(view.error->HasMember("conflicts"));
    ASSERT_TRUE((*view.error)["conflicts"].IsArray());
    ASSERT_GE((*view.error)["conflicts"].Size(), 1u);
    ASSERT_TRUE(view.error->HasMember("truncated"));
    EXPECT_TRUE((*view.error)["truncated"].IsBool());
}

TEST_F(ControlVNextIpRulesSurfaceTest, ApplySuccessReturnsMappingAndReusesRuleIdByClientRuleId) {
    rapidjson::Document applyArgs(rapidjson::kObjectType);
    auto &alloc = applyArgs.GetAllocator();
    rapidjson::Value sel(rapidjson::kObjectType);
    sel.AddMember("uid", kUid, alloc);
    applyArgs.AddMember("app", sel, alloc);

    rapidjson::Value rules(rapidjson::kArrayType);
    rules.PushBack(makeRule(alloc, "r1", "1.2.3.4/24"), alloc);
    applyArgs.AddMember("rules", rules, alloc);

    const rapidjson::Document resp1 = Rpc::call(/*id=*/30, "IPRULES.APPLY", applyArgs);
    ControlVNext::ResponseView v1;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp1, v1).has_value());
    ASSERT_TRUE(v1.ok);
    ASSERT_NE(v1.result, nullptr);
    ASSERT_TRUE(v1.result->HasMember("rules"));
    ASSERT_TRUE((*v1.result)["rules"].IsArray());
    ASSERT_EQ((*v1.result)["rules"].Size(), 1u);
    const auto &map1 = (*v1.result)["rules"][0];
    EXPECT_STREQ(map1["clientRuleId"].GetString(), "r1");
    ASSERT_TRUE(map1["ruleId"].IsUint());
    const uint32_t rid1 = map1["ruleId"].GetUint();
    EXPECT_EQ(rid1, 0u);
    ASSERT_TRUE(map1["matchKey"].IsString());
    const std::string_view mk1(map1["matchKey"].GetString());
    EXPECT_TRUE(mk1.find("mk2|family=ipv4|") != std::string_view::npos);
    EXPECT_TRUE(mk1.find("dst=1.2.3.0/24") != std::string_view::npos)
        << "CIDR must be canonicalized to network address in matchKey";

    // Apply again with same clientRuleId but different dst; ruleId must be reused.
    rapidjson::Document applyArgs2(rapidjson::kObjectType);
    auto &a2 = applyArgs2.GetAllocator();
    rapidjson::Value sel2(rapidjson::kObjectType);
    sel2.AddMember("uid", kUid, a2);
    applyArgs2.AddMember("app", sel2, a2);
    rapidjson::Value rules2(rapidjson::kArrayType);
    rules2.PushBack(makeRule(a2, "r1", "2.3.4.5/24"), a2);
    applyArgs2.AddMember("rules", rules2, a2);

    const rapidjson::Document resp2 = Rpc::call(/*id=*/31, "IPRULES.APPLY", applyArgs2);
    ControlVNext::ResponseView v2;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp2, v2).has_value());
    ASSERT_TRUE(v2.ok);
    ASSERT_NE(v2.result, nullptr);
    ASSERT_EQ((*v2.result)["rules"].Size(), 1u);
    const auto &map2 = (*v2.result)["rules"][0];
    ASSERT_TRUE(map2["ruleId"].IsUint());
    EXPECT_EQ(map2["ruleId"].GetUint(), rid1) << "ruleId must be stable for clientRuleId";
}

TEST_F(ControlVNextIpRulesSurfaceTest, ApplyIpv6RuleCanonicalizesCidrAndPrintsFamily) {
    rapidjson::Document applyArgs(rapidjson::kObjectType);
    auto &alloc = applyArgs.GetAllocator();
    rapidjson::Value sel(rapidjson::kObjectType);
    sel.AddMember("uid", kUid, alloc);
    applyArgs.AddMember("app", sel, alloc);

    rapidjson::Value rules(rapidjson::kArrayType);
    rules.PushBack(makeRule(alloc, "v6", "2001:db8::1/64", "ipv6"), alloc);
    applyArgs.AddMember("rules", rules, alloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/35, "IPRULES.APPLY", applyArgs);
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    ASSERT_TRUE(view.ok);
    ASSERT_NE(view.result, nullptr);
    ASSERT_TRUE((*view.result)["rules"].IsArray());
    ASSERT_EQ((*view.result)["rules"].Size(), 1u);
    const auto &map = (*view.result)["rules"][0];
    ASSERT_TRUE(map["matchKey"].IsString());
    const std::string_view mk(map["matchKey"].GetString());
    EXPECT_TRUE(mk.find("mk2|family=ipv6|") != std::string_view::npos);
    EXPECT_TRUE(mk.find("dst=2001:db8::/64") != std::string_view::npos)
        << "IPv6 CIDR must be canonicalized to network address in matchKey";

    // PRINT should reflect canonical CIDR and family.
    rapidjson::Document printArgs(rapidjson::kObjectType);
    auto &pAlloc = printArgs.GetAllocator();
    rapidjson::Value app(rapidjson::kObjectType);
    app.AddMember("uid", kUid, pAlloc);
    printArgs.AddMember("app", app, pAlloc);

    const rapidjson::Document printResp = Rpc::call(/*id=*/36, "IPRULES.PRINT", printArgs);
    ControlVNext::ResponseView pv;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(printResp, pv).has_value());
    ASSERT_TRUE(pv.ok);
    ASSERT_NE(pv.result, nullptr);
    ASSERT_TRUE((*pv.result)["rules"].IsArray());
    ASSERT_EQ((*pv.result)["rules"].Size(), 1u);
    const auto &r = (*pv.result)["rules"][0];
    ASSERT_TRUE(r["family"].IsString());
    EXPECT_STREQ(r["family"].GetString(), "ipv6");
    ASSERT_TRUE(r["dst"].IsString());
    EXPECT_STREQ(r["dst"].GetString(), "2001:db8::/64");
}

TEST_F(ControlVNextIpRulesSurfaceTest, ApplyPreflightFailureIncludesStructuredErrorPreflight) {
    rapidjson::Document applyArgs(rapidjson::kObjectType);
    auto &alloc = applyArgs.GetAllocator();
    rapidjson::Value sel(rapidjson::kObjectType);
    sel.AddMember("uid", kUid, alloc);
    applyArgs.AddMember("app", sel, alloc);

    // Exceed hard max rules total (5000) without triggering matchKey conflicts.
    rapidjson::Value rules(rapidjson::kArrayType);
    for (uint32_t i = 0; i < 5001; ++i) {
        const std::string id = "r" + std::to_string(i);
        const uint32_t a = (i >> 8) & 0xFF;
        const uint32_t b = i & 0xFF;
        const std::string dst =
            "10.0." + std::to_string(a) + "." + std::to_string(b) + "/32";
        rapidjson::Value r = makeRule(alloc, id.c_str(), dst.c_str());
        rules.PushBack(r, alloc);
    }
    applyArgs.AddMember("rules", rules, alloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/40, "IPRULES.APPLY", applyArgs);
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    ASSERT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "INVALID_ARGUMENT");
    ASSERT_TRUE(view.error->HasMember("preflight"));
    const auto &pre = (*view.error)["preflight"];
    ASSERT_TRUE(pre.IsObject());
    ASSERT_TRUE(pre.HasMember("summary"));
    ASSERT_TRUE(pre["summary"]["rulesTotal"].IsUint64());
    ASSERT_TRUE(pre.HasMember("limits"));
    ASSERT_TRUE(pre.HasMember("warnings"));
    ASSERT_TRUE(pre.HasMember("violations"));
}

} // namespace

/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextCodec.hpp>
#include <ControlVNextSessionCommands.hpp>
#include <ControlVNextSession.hpp>

#include <AppManager.hpp>
#include <DomainManager.hpp>
#include <PacketManager.hpp>
#include <PerfMetrics.hpp>
#include <RulesManager.hpp>
#include <Settings.hpp>
#include <FlowTelemetry.hpp>
#include <Streamable.hpp>
#include <sucre-snort.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

// ---- Test-only Streamable + PacketManager seams ----
//
// The production PacketManager implementation depends on the full Streamable + SocketIO graph.
// vNext metrics surface tests only need pktManager.{reasonMetricsSnapshot,resetReasonMetrics,
// conntrackMetricsSnapshot,ipRules()}.

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
// Mirror vNext domain/iprules surface tests: in-memory selector registry sufficient for {uid} and
// {pkg,userId} resolution, plus resetDomainPolicySources().

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

void AppManager::resetDomainPolicySources() {
    const std::shared_lock<std::shared_mutex> lock(_mutexByUid);
    for (const auto &[_, app] : _byUid) {
        app->resetDomainPolicySources();
    }
}

// Provide the globals normally defined in src/sucre-snort.cpp.
Settings settings;
RulesManager rulesManager;
DomainManager domManager;
AppManager appManager;
PacketManager pktManager;
PerfMetrics perfMetrics;
FlowTelemetry flowTelemetry;
std::shared_mutex mutexListeners;

namespace {

constexpr ControlVNextSession::Limits kLimits{.maxRequestBytes = 16 * 1024 * 1024,
                                              .maxResponseBytes = 16 * 1024 * 1024};

std::string makeTempDir() {
    const auto base = std::filesystem::temp_directory_path();
    std::string tmpl = (base / "sucre-snort-vnext-metrics.XXXXXX").string();
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    char *out = ::mkdtemp(buf.data());
    if (!out) {
        throw std::runtime_error("mkdtemp failed");
    }
    return std::string(out);
}

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

        auto plan = ControlVNextSessionCommands::handleMetricsCommand(view, kLimits);
        EXPECT_TRUE(plan.has_value());
        if (!plan.has_value()) {
            return ControlVNext::makeErrorResponse(id, "UNSUPPORTED_COMMAND", "not handled by metrics handler");
        }
        return std::move(plan->response);
    }
};

class ControlVNextMetricsSurfaceTest : public ::testing::Test {
protected:
    std::string tmpDir;

    void SetUp() override {
        tmpDir = makeTempDir();
        std::filesystem::create_directories(tmpDir);
        Settings::setSaveDirDomainListsOverrideForTesting(tmpDir);

        settings.reset();
        perfMetrics.resetAll();
        flowTelemetry.resetAll();
        domManager.reset();
        rulesManager.reset();
        appManager.reset();
        pktManager.ipRules().resetAll();
        pktManager.resetReasonMetrics();
    }

    void TearDown() override {
        Settings::setSaveDirDomainListsOverrideForTesting("");
        std::error_code ec;
        std::filesystem::remove_all(tmpDir, ec);
    }
};

TEST_F(ControlVNextMetricsSurfaceTest, GetRejectsUnknownArgsKey) {
    rapidjson::Document args(rapidjson::kObjectType);
    auto &alloc = args.GetAllocator();
    args.AddMember("name", rapidjson::Value("traffic", alloc), alloc);
    args.AddMember("x", 1, alloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/1, "METRICS.GET", args);

    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "SYNTAX_ERROR");
}

TEST_F(ControlVNextMetricsSurfaceTest, GetRejectsInvalidName) {
    rapidjson::Document args(rapidjson::kObjectType);
    auto &alloc = args.GetAllocator();
    args.AddMember("name", rapidjson::Value("nope", alloc), alloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/2, "METRICS.GET", args);

    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "INVALID_ARGUMENT");
}

TEST_F(ControlVNextMetricsSurfaceTest, GetRejectsAppForUnsupportedNames) {
    rapidjson::Document args(rapidjson::kObjectType);
    auto &alloc = args.GetAllocator();
    args.AddMember("name", rapidjson::Value("perf", alloc), alloc);
    rapidjson::Value app(rapidjson::kObjectType);
    app.AddMember("uid", 10123u, alloc);
    args.AddMember("app", app, alloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/3, "METRICS.GET", args);

    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "INVALID_ARGUMENT");
}

TEST_F(ControlVNextMetricsSurfaceTest, GetRejectsAppForDomainRuleStats) {
    rapidjson::Document args(rapidjson::kObjectType);
    auto &alloc = args.GetAllocator();
    args.AddMember("name", rapidjson::Value("domainRuleStats", alloc), alloc);
    rapidjson::Value app(rapidjson::kObjectType);
    app.AddMember("uid", 10123u, alloc);
    args.AddMember("app", app, alloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/30, "METRICS.GET", args);

    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "INVALID_ARGUMENT");
}

TEST_F(ControlVNextMetricsSurfaceTest, GetRejectsAppForTelemetry) {
    rapidjson::Document args(rapidjson::kObjectType);
    auto &alloc = args.GetAllocator();
    args.AddMember("name", rapidjson::Value("telemetry", alloc), alloc);
    rapidjson::Value app(rapidjson::kObjectType);
    app.AddMember("uid", 10123u, alloc);
    args.AddMember("app", app, alloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/31, "METRICS.GET", args);

    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "INVALID_ARGUMENT");
}

TEST_F(ControlVNextMetricsSurfaceTest, TelemetryStateIsExposed) {
    rapidjson::Document args(rapidjson::kObjectType);
    auto &alloc = args.GetAllocator();
    args.AddMember("name", rapidjson::Value("telemetry", alloc), alloc);

    // Default: no consumer.
    const rapidjson::Document resp0 = Rpc::call(/*id=*/32, "METRICS.GET", args);
    ControlVNext::ResponseView view0;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp0, view0).has_value());
    ASSERT_TRUE(view0.ok);
    ASSERT_NE(view0.result, nullptr);
    ASSERT_TRUE(view0.result->HasMember("telemetry"));
    const auto &tel0 = (*view0.result)["telemetry"];
    ASSERT_TRUE(tel0.IsObject());
    EXPECT_TRUE(tel0.HasMember("enabled"));
    EXPECT_TRUE(tel0.HasMember("consumerPresent"));
    EXPECT_TRUE(tel0.HasMember("sessionId"));
    EXPECT_TRUE(tel0.HasMember("slotBytes"));
    EXPECT_TRUE(tel0.HasMember("slotCount"));
    EXPECT_TRUE(tel0.HasMember("recordsWritten"));
    EXPECT_TRUE(tel0.HasMember("recordsDropped"));
    EXPECT_TRUE(tel0.HasMember("lastDropReason"));

    EXPECT_FALSE(tel0["enabled"].GetBool());
    EXPECT_FALSE(tel0["consumerPresent"].GetBool());

    // Enable a session and verify the state updates.
    FlowTelemetry::OpenResult openRes{};
    std::string openErr;
    ASSERT_TRUE(flowTelemetry.open(
        this, /*canPassFd=*/true, FlowTelemetry::Level::Flow, /*overrideCfg=*/std::nullopt, openRes, openErr))
        << openErr;
    ASSERT_GT(openRes.sessionId, 0u);

    const rapidjson::Document resp1 = Rpc::call(/*id=*/33, "METRICS.GET", args);
    ControlVNext::ResponseView view1;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp1, view1).has_value());
    ASSERT_TRUE(view1.ok);
    const auto &tel1 = (*view1.result)["telemetry"];
    EXPECT_TRUE(tel1["enabled"].GetBool());
    EXPECT_TRUE(tel1["consumerPresent"].GetBool());
    EXPECT_EQ(tel1["sessionId"].GetUint64(), openRes.sessionId);
    EXPECT_EQ(tel1["slotBytes"].GetUint(), openRes.slotBytes);
    EXPECT_EQ(tel1["slotCount"].GetUint(), openRes.slotCount);

    flowTelemetry.close(this);
    flowTelemetry.resetAll();
}

TEST_F(ControlVNextMetricsSurfaceTest, DomainRuleStatsShapeSortAndReset) {
    // Create a stable baseline with non-contiguous ruleIds to exercise ordering.
    rulesManager.upsertRuleWithId(/*ruleId=*/3, Rule::REGEX, ".*");
    rulesManager.upsertRuleWithId(/*ruleId=*/0, Rule::DOMAIN, "example.com");

    rapidjson::Document get(rapidjson::kObjectType);
    auto &gAlloc = get.GetAllocator();
    get.AddMember("name", rapidjson::Value("domainRuleStats", gAlloc), gAlloc);

    const rapidjson::Document resp0 = Rpc::call(/*id=*/31, "METRICS.GET", get);
    ControlVNext::ResponseView view0;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp0, view0).has_value());
    ASSERT_TRUE(view0.ok);
    ASSERT_NE(view0.result, nullptr);
    ASSERT_TRUE(view0.result->HasMember("domainRuleStats"));
    const auto &stats0 = (*view0.result)["domainRuleStats"];
    ASSERT_TRUE(stats0.IsObject());
    ASSERT_TRUE(stats0.HasMember("rules"));
    const auto &rules0 = stats0["rules"];
    ASSERT_TRUE(rules0.IsArray());
    ASSERT_EQ(rules0.Size(), 2u);
    EXPECT_EQ(rules0[0]["ruleId"].GetUint(), 0u);
    EXPECT_EQ(rules0[1]["ruleId"].GetUint(), 3u);
    EXPECT_TRUE(rules0[0].HasMember("allowHits"));
    EXPECT_TRUE(rules0[0].HasMember("blockHits"));

    // Simulate runtime hits.
    const auto r0 = rulesManager.findThreadSafe(0);
    const auto r3 = rulesManager.findThreadSafe(3);
    ASSERT_NE(r0, nullptr);
    ASSERT_NE(r3, nullptr);
    r0->observeAllowHit();
    r3->observeBlockHit();
    r3->observeBlockHit();

    const rapidjson::Document resp1 = Rpc::call(/*id=*/32, "METRICS.GET", get);
    ControlVNext::ResponseView view1;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp1, view1).has_value());
    ASSERT_TRUE(view1.ok);
    const auto &rules1 = (*view1.result)["domainRuleStats"]["rules"];
    ASSERT_EQ(rules1.Size(), 2u);
    EXPECT_EQ(rules1[0]["allowHits"].GetUint64(), 1u);
    EXPECT_EQ(rules1[0]["blockHits"].GetUint64(), 0u);
    EXPECT_EQ(rules1[1]["allowHits"].GetUint64(), 0u);
    EXPECT_EQ(rules1[1]["blockHits"].GetUint64(), 2u);

    // Reset and verify zero.
    rapidjson::Document reset(rapidjson::kObjectType);
    auto &rAlloc = reset.GetAllocator();
    reset.AddMember("name", rapidjson::Value("domainRuleStats", rAlloc), rAlloc);
    const rapidjson::Document resetResp = Rpc::call(/*id=*/33, "METRICS.RESET", reset);
    ControlVNext::ResponseView resetView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resetResp, resetView).has_value());
    ASSERT_TRUE(resetView.ok);

    const rapidjson::Document resp2 = Rpc::call(/*id=*/34, "METRICS.GET", get);
    ControlVNext::ResponseView view2;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp2, view2).has_value());
    ASSERT_TRUE(view2.ok);
    const auto &rules2 = (*view2.result)["domainRuleStats"]["rules"];
    ASSERT_EQ(rules2.Size(), 2u);
    EXPECT_EQ(rules2[0]["allowHits"].GetUint64(), 0u);
    EXPECT_EQ(rules2[0]["blockHits"].GetUint64(), 0u);
    EXPECT_EQ(rules2[1]["allowHits"].GetUint64(), 0u);
    EXPECT_EQ(rules2[1]["blockHits"].GetUint64(), 0u);

    // RESETALL clears baseline rules; domainRuleStats must reflect the cleared baseline.
    rulesManager.reset();
    const rapidjson::Document resp3 = Rpc::call(/*id=*/35, "METRICS.GET", get);
    ControlVNext::ResponseView view3;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp3, view3).has_value());
    ASSERT_TRUE(view3.ok);
    const auto &rules3 = (*view3.result)["domainRuleStats"]["rules"];
    ASSERT_TRUE(rules3.IsArray());
    EXPECT_EQ(rules3.Size(), 0u);
}

TEST_F(ControlVNextMetricsSurfaceTest, SelectorNotFoundReturnsCandidatesArray) {
    rapidjson::Document args(rapidjson::kObjectType);
    auto &alloc = args.GetAllocator();
    args.AddMember("name", rapidjson::Value("traffic", alloc), alloc);
    rapidjson::Value app(rapidjson::kObjectType);
    app.AddMember("uid", 999999u, alloc);
    args.AddMember("app", app, alloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/4, "METRICS.GET", args);

    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "SELECTOR_NOT_FOUND");
    ASSERT_TRUE(view.error->HasMember("candidates"));
    EXPECT_TRUE((*view.error)["candidates"].IsArray());
}

TEST_F(ControlVNextMetricsSurfaceTest, SelectorAmbiguousReturnsSortedCandidates) {
    const uint32_t uid1 = 10123;
    const uint32_t uid2 = 10124;
    appManager.install(uid2, {"com.example"});
    appManager.install(uid1, {"com.example"});

    rapidjson::Document args(rapidjson::kObjectType);
    auto &alloc = args.GetAllocator();
    args.AddMember("name", rapidjson::Value("traffic", alloc), alloc);
    rapidjson::Value sel(rapidjson::kObjectType);
    sel.AddMember("pkg", rapidjson::Value("com.example", alloc), alloc);
    sel.AddMember("userId", 0u, alloc);
    args.AddMember("app", sel, alloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/5, "METRICS.GET", args);

    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "SELECTOR_AMBIGUOUS");
    ASSERT_TRUE(view.error->HasMember("candidates"));
    const auto &candidates = (*view.error)["candidates"];
    ASSERT_TRUE(candidates.IsArray());
    ASSERT_EQ(candidates.Size(), 2u);
    EXPECT_EQ(candidates[0]["uid"].GetUint(), uid1);
    EXPECT_EQ(candidates[1]["uid"].GetUint(), uid2);
}

TEST_F(ControlVNextMetricsSurfaceTest, TrafficDeviceWideAndPerAppShapes) {
    const uint32_t uid1 = 10123;
    const uint32_t uid2 = 10124;
    appManager.install(uid1, {"com.app1"});
    appManager.install(uid2, {"com.app2"});

    const auto app1 = appManager.find(uid1);
    const auto app2 = appManager.find(uid2);
    ASSERT_NE(app1, nullptr);
    ASSERT_NE(app2, nullptr);

    app1->observeTrafficDns(false);
    app1->observeTrafficPacket(/*input=*/true, /*accepted=*/true, /*bytes=*/100);
    app2->observeTrafficDns(true);
    app2->observeTrafficPacket(/*input=*/false, /*accepted=*/false, /*bytes=*/200);

    rapidjson::Document args(rapidjson::kObjectType);
    auto &alloc = args.GetAllocator();
    args.AddMember("name", rapidjson::Value("traffic", alloc), alloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/6, "METRICS.GET", args);
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    ASSERT_TRUE(view.ok);
    ASSERT_NE(view.result, nullptr);

    const auto &traffic = (*view.result)["traffic"];
    ASSERT_TRUE(traffic.IsObject());
    EXPECT_EQ(traffic["dns"]["allow"].GetUint64(), 1u);
    EXPECT_EQ(traffic["dns"]["block"].GetUint64(), 1u);
    EXPECT_EQ(traffic["rxp"]["allow"].GetUint64(), 1u);
    EXPECT_EQ(traffic["rxb"]["allow"].GetUint64(), 100u);
    EXPECT_EQ(traffic["txp"]["block"].GetUint64(), 1u);
    EXPECT_EQ(traffic["txb"]["block"].GetUint64(), 200u);

    rapidjson::Document appArgs(rapidjson::kObjectType);
    auto &aAlloc = appArgs.GetAllocator();
    appArgs.AddMember("name", rapidjson::Value("traffic", aAlloc), aAlloc);
    rapidjson::Value sel(rapidjson::kObjectType);
    sel.AddMember("uid", uid1, aAlloc);
    appArgs.AddMember("app", sel, aAlloc);

    const rapidjson::Document appResp = Rpc::call(/*id=*/7, "METRICS.GET", appArgs);
    ControlVNext::ResponseView appView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(appResp, appView).has_value());
    ASSERT_TRUE(appView.ok);
    ASSERT_NE(appView.result, nullptr);
    EXPECT_EQ((*appView.result)["uid"].GetUint(), uid1);
    EXPECT_TRUE((*appView.result)["app"].IsString());
    ASSERT_TRUE((*appView.result).HasMember("traffic"));
}

TEST_F(ControlVNextMetricsSurfaceTest, TrafficResetSemanticsPerAppThenDeviceWide) {
    const uint32_t uid1 = 10123;
    const uint32_t uid2 = 10124;
    appManager.install(uid1, {"com.app1"});
    appManager.install(uid2, {"com.app2"});

    const auto app1 = appManager.find(uid1);
    const auto app2 = appManager.find(uid2);
    ASSERT_NE(app1, nullptr);
    ASSERT_NE(app2, nullptr);

    app1->observeTrafficDns(false);
    app2->observeTrafficDns(true);

    // Reset only app1.
    rapidjson::Document resetApp(rapidjson::kObjectType);
    auto &rAlloc = resetApp.GetAllocator();
    resetApp.AddMember("name", rapidjson::Value("traffic", rAlloc), rAlloc);
    rapidjson::Value sel1(rapidjson::kObjectType);
    sel1.AddMember("uid", uid1, rAlloc);
    resetApp.AddMember("app", sel1, rAlloc);

    const rapidjson::Document resetResp = Rpc::call(/*id=*/8, "METRICS.RESET", resetApp);
    ControlVNext::ResponseView resetView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resetResp, resetView).has_value());
    EXPECT_TRUE(resetView.ok);

    // app1 should be zero.
    rapidjson::Document get1(rapidjson::kObjectType);
    auto &g1Alloc = get1.GetAllocator();
    get1.AddMember("name", rapidjson::Value("traffic", g1Alloc), g1Alloc);
    rapidjson::Value gSel1(rapidjson::kObjectType);
    gSel1.AddMember("uid", uid1, g1Alloc);
    get1.AddMember("app", gSel1, g1Alloc);

    const rapidjson::Document get1Resp = Rpc::call(/*id=*/9, "METRICS.GET", get1);
    ControlVNext::ResponseView get1View;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(get1Resp, get1View).has_value());
    ASSERT_TRUE(get1View.ok);
    EXPECT_EQ((*get1View.result)["traffic"]["dns"]["allow"].GetUint64(), 0u);
    EXPECT_EQ((*get1View.result)["traffic"]["dns"]["block"].GetUint64(), 0u);

    // app2 should be unchanged.
    rapidjson::Document get2(rapidjson::kObjectType);
    auto &g2Alloc = get2.GetAllocator();
    get2.AddMember("name", rapidjson::Value("traffic", g2Alloc), g2Alloc);
    rapidjson::Value gSel2(rapidjson::kObjectType);
    gSel2.AddMember("uid", uid2, g2Alloc);
    get2.AddMember("app", gSel2, g2Alloc);

    const rapidjson::Document get2Resp = Rpc::call(/*id=*/10, "METRICS.GET", get2);
    ControlVNext::ResponseView get2View;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(get2Resp, get2View).has_value());
    ASSERT_TRUE(get2View.ok);
    EXPECT_EQ((*get2View.result)["traffic"]["dns"]["allow"].GetUint64(), 0u);
    EXPECT_EQ((*get2View.result)["traffic"]["dns"]["block"].GetUint64(), 1u);

    // Device-wide reset clears both.
    rapidjson::Document resetAll(rapidjson::kObjectType);
    auto &raAlloc = resetAll.GetAllocator();
    resetAll.AddMember("name", rapidjson::Value("traffic", raAlloc), raAlloc);
    const rapidjson::Document resetAllResp = Rpc::call(/*id=*/11, "METRICS.RESET", resetAll);
    ControlVNext::ResponseView resetAllView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resetAllResp, resetAllView).has_value());
    EXPECT_TRUE(resetAllView.ok);

    const rapidjson::Document get2Resp2 = Rpc::call(/*id=*/12, "METRICS.GET", get2);
    ControlVNext::ResponseView get2View2;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(get2Resp2, get2View2).has_value());
    ASSERT_TRUE(get2View2.ok);
    EXPECT_EQ((*get2View2.result)["traffic"]["dns"]["allow"].GetUint64(), 0u);
    EXPECT_EQ((*get2View2.result)["traffic"]["dns"]["block"].GetUint64(), 0u);
}

TEST_F(ControlVNextMetricsSurfaceTest, ConntrackShapeAndResetRejection) {
    rapidjson::Document args(rapidjson::kObjectType);
    auto &alloc = args.GetAllocator();
    args.AddMember("name", rapidjson::Value("conntrack", alloc), alloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/13, "METRICS.GET", args);
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    ASSERT_TRUE(view.ok);
    ASSERT_NE(view.result, nullptr);
    ASSERT_TRUE(view.result->HasMember("conntrack"));
    const auto &ct = (*view.result)["conntrack"];
    EXPECT_TRUE(ct.HasMember("totalEntries"));
    EXPECT_TRUE(ct.HasMember("creates"));
    EXPECT_TRUE(ct.HasMember("expiredRetires"));
    EXPECT_TRUE(ct.HasMember("overflowDrops"));
    EXPECT_TRUE(ct.HasMember("byFamily"));
    const auto &byFamily = ct["byFamily"];
    ASSERT_TRUE(byFamily.IsObject());
    ASSERT_TRUE(byFamily.HasMember("ipv4"));
    ASSERT_TRUE(byFamily.HasMember("ipv6"));
    for (const auto name : {"ipv4", "ipv6"}) {
        const auto &fam = byFamily[name];
        EXPECT_TRUE(fam.HasMember("totalEntries"));
        EXPECT_TRUE(fam.HasMember("creates"));
        EXPECT_TRUE(fam.HasMember("expiredRetires"));
        EXPECT_TRUE(fam.HasMember("overflowDrops"));
    }

    const rapidjson::Document resetResp = Rpc::call(/*id=*/14, "METRICS.RESET", args);
    ControlVNext::ResponseView resetView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resetResp, resetView).has_value());
    EXPECT_FALSE(resetView.ok);
    ASSERT_NE(resetView.error, nullptr);
    EXPECT_STREQ((*resetView.error)["code"].GetString(), "INVALID_ARGUMENT");
}

TEST_F(ControlVNextMetricsSurfaceTest, ResetRejectsUnknownArgsKey) {
    rapidjson::Document args(rapidjson::kObjectType);
    auto &alloc = args.GetAllocator();
    args.AddMember("name", rapidjson::Value("traffic", alloc), alloc);
    args.AddMember("x", 1, alloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/15, "METRICS.RESET", args);

    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "SYNTAX_ERROR");
}

TEST_F(ControlVNextMetricsSurfaceTest, PerfAndReasonsHaveStableWrappers) {
    rapidjson::Document perfArgs(rapidjson::kObjectType);
    auto &pAlloc = perfArgs.GetAllocator();
    perfArgs.AddMember("name", rapidjson::Value("perf", pAlloc), pAlloc);
    const rapidjson::Document perfResp = Rpc::call(/*id=*/16, "METRICS.GET", perfArgs);

    ControlVNext::ResponseView perfView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(perfResp, perfView).has_value());
    ASSERT_TRUE(perfView.ok);
    ASSERT_NE(perfView.result, nullptr);
    ASSERT_TRUE(perfView.result->HasMember("perf"));
    ASSERT_TRUE((*perfView.result)["perf"].HasMember("nfq_total_us"));
    ASSERT_TRUE((*perfView.result)["perf"].HasMember("dns_decision_us"));

    rapidjson::Document reasonsArgs(rapidjson::kObjectType);
    auto &rAlloc = reasonsArgs.GetAllocator();
    reasonsArgs.AddMember("name", rapidjson::Value("reasons", rAlloc), rAlloc);
    const rapidjson::Document reasonsResp = Rpc::call(/*id=*/17, "METRICS.GET", reasonsArgs);

    ControlVNext::ResponseView reasonsView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(reasonsResp, reasonsView).has_value());
    ASSERT_TRUE(reasonsView.ok);
    ASSERT_NE(reasonsView.result, nullptr);
    ASSERT_TRUE(reasonsView.result->HasMember("reasons"));
    ASSERT_TRUE((*reasonsView.result)["reasons"].IsObject());
    ASSERT_TRUE((*reasonsView.result)["reasons"].HasMember("ALLOW_DEFAULT"));
}

} // namespace

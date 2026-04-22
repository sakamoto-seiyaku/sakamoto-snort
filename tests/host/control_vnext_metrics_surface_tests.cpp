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


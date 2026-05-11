/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextCodec.hpp>
#include <ControlVNextSession.hpp>
#include <ControlVNextSessionCommands.hpp>

#include <AppManager.hpp>
#include <BlockingListManager.hpp>
#include <DomainManager.hpp>
#include <FlowTelemetry.hpp>
#include <PacketManager.hpp>
#include <PerfMetrics.hpp>
#include <RulesManager.hpp>
#include <Settings.hpp>
#include <Streamable.hpp>
#include <sucre-snort.hpp>

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

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
void PacketManager::refreshIfacesOnce() {}
uint8_t PacketManager::ifaceBit(const uint32_t /*iface*/) { return 0; }

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

Settings settings;
DomainManager domManager;
RulesManager rulesManager;
BlockingListManager blockingListManager;
AppManager appManager;
PacketManager pktManager;
PerfMetrics perfMetrics;
FlowTelemetry flowTelemetry;
std::shared_mutex mutexListeners;
std::mutex mutexControlMutations;

void snortResetAll() { settings.reset(); }

namespace {

constexpr ControlVNextSession::Limits kLimits{.maxRequestBytes = 16 * 1024 * 1024,
                                              .maxResponseBytes = 16 * 1024 * 1024};

class TempFile {
public:
    TempFile() {
        char tmpl[] = "/tmp/sucre-snort-vnext-config-XXXXXX";
        const int fd = mkstemp(tmpl);
        if (fd >= 0) {
            close(fd);
            path_ = tmpl;
        }
    }

    ~TempFile() {
        if (!path_.empty()) {
            std::remove(path_.c_str());
            std::remove((path_ + ".tmp").c_str());
        }
    }

    const std::string &path() const { return path_; }

private:
    std::string path_;
};

rapidjson::Document parseArgs(const std::string_view json) {
    rapidjson::Document args;
    args.Parse(json.data(), json.size());
    if (args.HasParseError() || !args.IsObject()) {
        throw std::runtime_error("test args JSON parse failed");
    }
    return args;
}

rapidjson::Document callDaemon(const uint32_t id, const std::string_view cmd,
                               const std::string_view argsJson) {
    rapidjson::Document args = parseArgs(argsJson);
    rapidjson::Document req = ControlVNext::makeRequest(id, cmd, args);

    ControlVNext::RequestView view;
    const auto envErr = ControlVNext::parseRequestEnvelope(req, view);
    EXPECT_FALSE(envErr.has_value());
    if (envErr.has_value()) {
        return ControlVNext::makeErrorResponse(id, envErr->code, envErr->message);
    }

    auto plan = ControlVNextSessionCommands::handleDaemonCommand(view, kLimits);
    EXPECT_TRUE(plan.has_value());
    if (!plan.has_value()) {
        return ControlVNext::makeErrorResponse(id, "UNSUPPORTED_COMMAND", "not handled by daemon handler");
    }
    return std::move(plan->response);
}

void expectOk(const rapidjson::Document &resp, const uint32_t id) {
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    EXPECT_EQ(view.id, id);
    EXPECT_TRUE(view.ok);
}

void expectInvalidArgument(const rapidjson::Document &resp, const uint32_t id) {
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    EXPECT_EQ(view.id, id);
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    ASSERT_TRUE(view.error->HasMember("code"));
    EXPECT_STREQ((*view.error)["code"].GetString(), "INVALID_ARGUMENT");
}

class ControlVNextDaemonConfigTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_FALSE(tmp.path().empty());
        settings.setSaveFileOverrideForTesting(tmp.path());
        settings.reset();
        settings.save();
        perfMetrics.resetAll();
        appManager.reset();
    }

    void TearDown() override { settings.setSaveFileOverrideForTesting(""); }

    TempFile tmp;
};

TEST_F(ControlVNextDaemonConfigTest, ConfigGetReturnsDefaultNfqueueTopology) {
    const rapidjson::Document resp =
        callDaemon(1, "CONFIG.GET", R"({"scope":"device","keys":["nfqueue.topology"]})");

    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    ASSERT_TRUE(view.ok);
    ASSERT_NE(view.result, nullptr);
    ASSERT_TRUE((*view.result).HasMember("values"));
    const auto &values = (*view.result)["values"];
    ASSERT_TRUE(values.HasMember("nfqueue.topology"));
    ASSERT_TRUE(values["nfqueue.topology"].IsString());
    EXPECT_STREQ(values["nfqueue.topology"].GetString(), "split-in-out");
}

TEST_F(ControlVNextDaemonConfigTest, ConfigSetAcceptsAndReportsSharedFlowPool) {
    expectOk(callDaemon(2, "CONFIG.SET",
                        R"({"scope":"device","set":{"nfqueue.topology":"shared-flow-pool"}})"),
             2);
    EXPECT_EQ(settings.nfqueueTopology(), NfqueueTopology::SharedFlowPool);

    const rapidjson::Document resp =
        callDaemon(3, "CONFIG.GET", R"({"scope":"device","keys":["nfqueue.topology"]})");

    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    ASSERT_TRUE(view.ok);
    const auto &values = (*view.result)["values"];
    ASSERT_TRUE(values.HasMember("nfqueue.topology"));
    EXPECT_STREQ(values["nfqueue.topology"].GetString(), "shared-flow-pool");
}

TEST_F(ControlVNextDaemonConfigTest, ConfigSetRejectsInvalidNfqueueTopologyValues) {
    expectInvalidArgument(
        callDaemon(4, "CONFIG.SET",
                   R"({"scope":"device","set":{"nfqueue.topology":"unsupported"}})"),
        4);
    expectInvalidArgument(
        callDaemon(5, "CONFIG.SET", R"({"scope":"device","set":{"nfqueue.topology":1}})"),
        5);
}

TEST_F(ControlVNextDaemonConfigTest, ConfigSetRejectsAppScopeNfqueueTopology) {
    appManager.install(10123, App::NamesVec{"com.example.app"});

    expectInvalidArgument(
        callDaemon(6, "CONFIG.SET",
                   R"({"scope":"app","app":{"uid":10123},"set":{"nfqueue.topology":"split-in-out"}})"),
        6);
}

} // namespace

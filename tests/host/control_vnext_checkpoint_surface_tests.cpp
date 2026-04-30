/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextCodec.hpp>
#include <ControlVNextSession.hpp>
#include <ControlVNextSessionCommands.hpp>
#include <PolicyCheckpoint.hpp>

#include <ActivityManager.hpp>
#include <AppManager.hpp>
#include <BlockingListManager.hpp>
#include <DomainManager.hpp>
#include <FlowTelemetry.hpp>
#include <PacketManager.hpp>
#include <RulesManager.hpp>
#include <Settings.hpp>
#include <sucre-snort.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <vector>

Settings settings;
RulesManager rulesManager;
DomainManager domManager;
BlockingListManager blockingListManager;
AppManager appManager;
ActivityManager activityManager;
PacketManager pktManager;
FlowTelemetry flowTelemetry;
std::shared_mutex mutexListeners;
std::mutex mutexControlMutations;

PolicyCheckpoint::Status snortCheckpointSave(const std::uint32_t slot,
                                             PolicyCheckpoint::SlotMetadata &metadata) {
    return PolicyCheckpoint::saveCurrentPolicyToSlot(slot, metadata);
}

PolicyCheckpoint::Status snortCheckpointClear(const std::uint32_t slot,
                                              PolicyCheckpoint::SlotMetadata &metadata) {
    return PolicyCheckpoint::clearSlot(slot, metadata);
}

PolicyCheckpoint::Status snortCheckpointRestore(const std::uint32_t slot,
                                                PolicyCheckpoint::SlotMetadata &metadata) {
    PolicyCheckpoint::Bundle bundle;
    if (auto st = PolicyCheckpoint::readSlot(slot, bundle, metadata); !st.ok) {
        return st;
    }
    PolicyCheckpoint::RestoreStaging staging;
    if (auto st = PolicyCheckpoint::stageBundleForRestore(bundle, staging); !st.ok) {
        return st;
    }
    return PolicyCheckpoint::restoreBundleToLivePolicy(bundle, staging);
}

namespace {

constexpr ControlVNextSession::Limits kLimits{.maxRequestBytes = 16 * 1024 * 1024,
                                              .maxResponseBytes = 16 * 1024 * 1024};

std::string makeTempDir() {
    const auto base = std::filesystem::temp_directory_path();
    std::string tmpl = (base / "sucre-snort-checkpoints.XXXXXX").string();
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    char *out = ::mkdtemp(buf.data());
    if (out == nullptr) {
        throw std::runtime_error("mkdtemp failed");
    }
    return std::string(out);
}

rapidjson::Document callCheckpoint(const std::uint32_t id, const std::string_view cmd,
                                   const rapidjson::Value &args) {
    rapidjson::Document req = ControlVNext::makeRequest(id, cmd, args);

    ControlVNext::RequestView view;
    const auto envErr = ControlVNext::parseRequestEnvelope(req, view);
    EXPECT_FALSE(envErr.has_value());
    if (envErr.has_value()) {
        return ControlVNext::makeErrorResponse(id, envErr->code, envErr->message);
    }

    auto plan = ControlVNextSessionCommands::handleCheckpointCommand(view, kLimits);
    EXPECT_TRUE(plan.has_value());
    if (!plan.has_value()) {
        return ControlVNext::makeErrorResponse(id, "UNSUPPORTED_COMMAND", "not handled");
    }
    return std::move(plan->response);
}

void expectErrorCode(const rapidjson::Document &resp, const char *code) {
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    ASSERT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    ASSERT_TRUE(view.error->HasMember("code"));
    EXPECT_STREQ((*view.error)["code"].GetString(), code);
}

void expectOk(const rapidjson::Document &resp) {
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    EXPECT_TRUE(view.ok);
}

void writeSlotFile(const std::uint32_t slot, const std::string &data) {
    const std::string path =
        Settings::saveDirPolicyCheckpointsPath() + "slot" + std::to_string(slot) + ".bundle";
    std::ofstream out(path, std::ios::out | std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(out.is_open());
    out << data;
    ASSERT_TRUE(out.good());
}

void writeTextFile(const std::string &path, const std::string &data) {
    std::ofstream out(path, std::ios::out | std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(out.is_open());
    out << data;
    ASSERT_TRUE(out.good());
}

std::string readTextFile(const std::string &path) {
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in.is_open()) {
        return {};
    }
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

PolicyCheckpoint::DomainListSnapshot makeCheckpointDomainList() {
    PolicyCheckpoint::DomainListSnapshot list;
    list.listId = "12345678-1234-1234-1234-123456789abc";
    list.color = Stats::BLACK;
    list.mask = Settings::standardListBit;
    list.enabled = true;
    list.url = "https://example.invalid/list.txt";
    list.name = "test";
    list.domains = {"new.example.com"};
    list.domainsCount = 1;
    return list;
}

class ControlVNextCheckpointSurfaceTest : public ::testing::Test {
protected:
    std::string tmpDir;

    void SetUp() override {
        tmpDir = makeTempDir();
        const std::string domainLists = tmpDir + "/domains_lists/";
        const std::string checkpoints = tmpDir + "/policy_checkpoints/";
        std::filesystem::create_directories(domainLists);
        std::filesystem::create_directories(checkpoints);

        Settings::setSaveDirDomainListsOverrideForTesting(domainLists);
        Settings::setSaveDirPolicyCheckpointsOverrideForTesting(checkpoints);

        settings.reset();
        blockingListManager.reset();
        appManager.reset();
        domManager.resetPolicyForCheckpointRestore();
        rulesManager.reset();
        pktManager.reset();
    }

    void TearDown() override {
        Settings::setSaveDirDomainListsOverrideForTesting("");
        Settings::setSaveDirPolicyCheckpointsOverrideForTesting("");
        std::error_code ec;
        std::filesystem::remove_all(tmpDir, ec);
    }
};

TEST_F(ControlVNextCheckpointSurfaceTest, ListReturnsExactlyThreeSortedSlots) {
    rapidjson::Document args(rapidjson::kObjectType);
    const rapidjson::Document resp = callCheckpoint(1, "CHECKPOINT.LIST", args);

    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    ASSERT_TRUE(view.ok);
    ASSERT_NE(view.result, nullptr);
    ASSERT_TRUE(view.result->HasMember("slots"));
    const auto &slots = (*view.result)["slots"];
    ASSERT_TRUE(slots.IsArray());
    ASSERT_EQ(slots.Size(), PolicyCheckpoint::kSlotCount);
    for (rapidjson::SizeType i = 0; i < slots.Size(); ++i) {
        ASSERT_TRUE(slots[i].HasMember("slot"));
        EXPECT_EQ(slots[i]["slot"].GetUint(), i);
        ASSERT_TRUE(slots[i].HasMember("present"));
        EXPECT_FALSE(slots[i]["present"].GetBool());
    }
}

TEST_F(ControlVNextCheckpointSurfaceTest, RejectsUnknownArgsAndBadSlotArgs) {
    rapidjson::Document unknown(rapidjson::kObjectType);
    unknown.AddMember("extra", 1, unknown.GetAllocator());
    expectErrorCode(callCheckpoint(2, "CHECKPOINT.LIST", unknown), "SYNTAX_ERROR");
    expectErrorCode(callCheckpoint(3, "CHECKPOINT.SAVE", unknown), "SYNTAX_ERROR");

    rapidjson::Document missing(rapidjson::kObjectType);
    expectErrorCode(callCheckpoint(4, "CHECKPOINT.SAVE", missing), "MISSING_ARGUMENT");

    rapidjson::Document invalid(rapidjson::kObjectType);
    invalid.AddMember("slot", 3, invalid.GetAllocator());
    expectErrorCode(callCheckpoint(5, "CHECKPOINT.SAVE", invalid), "INVALID_ARGUMENT");
}

TEST_F(ControlVNextCheckpointSurfaceTest, ClearEmptySlotIsIdempotent) {
    rapidjson::Document args(rapidjson::kObjectType);
    args.AddMember("slot", 1, args.GetAllocator());

    const rapidjson::Document resp = callCheckpoint(6, "CHECKPOINT.CLEAR", args);

    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    ASSERT_TRUE(view.ok);
    ASSERT_NE(view.result, nullptr);
    const auto &slot = (*view.result)["slot"];
    EXPECT_EQ(slot["slot"].GetUint(), 1u);
    EXPECT_FALSE(slot["present"].GetBool());
}

TEST_F(ControlVNextCheckpointSurfaceTest, SaveReturnsMetadataAndListShowsPresentSlot) {
    rapidjson::Document args(rapidjson::kObjectType);
    args.AddMember("slot", 2, args.GetAllocator());

    const rapidjson::Document saveResp = callCheckpoint(7, "CHECKPOINT.SAVE", args);
    ControlVNext::ResponseView saveView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(saveResp, saveView).has_value());
    ASSERT_TRUE(saveView.ok);
    ASSERT_NE(saveView.result, nullptr);
    const auto &savedSlot = (*saveView.result)["slot"];
    EXPECT_EQ(savedSlot["slot"].GetUint(), 2u);
    EXPECT_TRUE(savedSlot["present"].GetBool());
    EXPECT_EQ(savedSlot["formatVersion"].GetUint(), PolicyCheckpoint::kFormatVersion);
    EXPECT_GT(savedSlot["sizeBytes"].GetUint64(), 0u);
    EXPECT_GT(savedSlot["createdAt"].GetUint64(), 0u);

    rapidjson::Document empty(rapidjson::kObjectType);
    const rapidjson::Document listResp = callCheckpoint(8, "CHECKPOINT.LIST", empty);
    ControlVNext::ResponseView listView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(listResp, listView).has_value());
    ASSERT_TRUE(listView.ok);
    const auto &slots = (*listView.result)["slots"];
    ASSERT_EQ(slots.Size(), PolicyCheckpoint::kSlotCount);
    EXPECT_FALSE(slots[0]["present"].GetBool());
    EXPECT_FALSE(slots[1]["present"].GetBool());
    EXPECT_TRUE(slots[2]["present"].GetBool());
}

TEST_F(ControlVNextCheckpointSurfaceTest, RestoreMissingSlotReturnsNotFound) {
    rapidjson::Document args(rapidjson::kObjectType);
    args.AddMember("slot", 0, args.GetAllocator());

    expectErrorCode(callCheckpoint(9, "CHECKPOINT.RESTORE", args), "NOT_FOUND");
}

TEST_F(ControlVNextCheckpointSurfaceTest, RestoreValidSlotRestoresDevicePolicyConfig) {
    settings.applyCheckpointPolicyConfig(true, Settings::standardListBit | Settings::customListBit,
                                         0, false, false);

    rapidjson::Document args(rapidjson::kObjectType);
    args.AddMember("slot", 0, args.GetAllocator());
    expectOk(callCheckpoint(10, "CHECKPOINT.SAVE", args));

    settings.applyCheckpointPolicyConfig(false, Settings::standardListBit, 0, false, false);
    ASSERT_FALSE(settings.blockEnabled());

    const rapidjson::Document restoreResp = callCheckpoint(11, "CHECKPOINT.RESTORE", args);
    expectOk(restoreResp);
    EXPECT_TRUE(settings.blockEnabled());
    EXPECT_EQ(settings.blockMask(), Settings::standardListBit | Settings::customListBit);
}

TEST_F(ControlVNextCheckpointSurfaceTest, RestoreValidSlotPublishesDomainListContents) {
    PolicyCheckpoint::Bundle bundle = PolicyCheckpoint::captureLivePolicy();
    const auto list = makeCheckpointDomainList();
    bundle.domainLists.push_back(list);

    std::string encoded;
    ASSERT_TRUE(PolicyCheckpoint::encodeBundle(bundle, encoded).ok);
    writeSlotFile(0, encoded);

    rapidjson::Document args(rapidjson::kObjectType);
    args.AddMember("slot", 0, args.GetAllocator());
    expectOk(callCheckpoint(12, "CHECKPOINT.RESTORE", args));

    EXPECT_EQ(readTextFile(Settings::saveDirDomainListsPath() + list.listId), "new.example.com\n");
    const auto lists = blockingListManager.listsSnapshot();
    ASSERT_EQ(lists.size(), 1u);
    EXPECT_EQ(lists[0].getId(), list.listId);
    EXPECT_EQ(lists[0].getDomainsCount(), 1u);
}

TEST_F(ControlVNextCheckpointSurfaceTest, InvalidStagedDomainReferenceDoesNotMutateLiveState) {
    settings.applyCheckpointPolicyConfig(true, Settings::standardListBit | Settings::customListBit,
                                         0, false, false);
    PolicyCheckpoint::Bundle bundle = PolicyCheckpoint::captureLivePolicy();
    std::string encoded;
    ASSERT_TRUE(PolicyCheckpoint::encodeBundle(bundle, encoded).ok);

    const std::string from = "\"blockEnabled\":true";
    const std::string to = "\"blockEnabled\":false";
    const auto blockPos = encoded.find(from);
    ASSERT_NE(blockPos, std::string::npos);
    encoded.replace(blockPos, from.size(), to);

    const std::string refsFrom = "\"allowRuleIds\":[]";
    const std::string refsTo = "\"allowRuleIds\":[999]";
    const auto refsPos = encoded.find(refsFrom);
    ASSERT_NE(refsPos, std::string::npos);
    encoded.replace(refsPos, refsFrom.size(), refsTo);
    writeSlotFile(0, encoded);

    rapidjson::Document args(rapidjson::kObjectType);
    args.AddMember("slot", 0, args.GetAllocator());
    expectErrorCode(callCheckpoint(13, "CHECKPOINT.RESTORE", args), "INVALID_ARGUMENT");
    EXPECT_TRUE(settings.blockEnabled());
}

TEST_F(ControlVNextCheckpointSurfaceTest, MissingStagedDomainListDirRollsBackWithoutMutation) {
    settings.applyCheckpointPolicyConfig(true, Settings::standardListBit | Settings::customListBit,
                                         0, false, false);

    PolicyCheckpoint::Bundle bundle = PolicyCheckpoint::captureLivePolicy();
    bundle.deviceConfig.blockEnabled = false;
    const auto list = makeCheckpointDomainList();
    bundle.domainLists.push_back(list);

    PolicyCheckpoint::SlotMetadata savedMeta;
    ASSERT_TRUE(PolicyCheckpoint::saveCurrentPolicyToSlot(0, savedMeta).ok);

    const std::string finalPath = Settings::saveDirDomainListsPath() + list.listId;
    writeTextFile(finalPath, "old.example.com\n");

    PolicyCheckpoint::RestoreStaging staging;
    ASSERT_TRUE(PolicyCheckpoint::stageBundleForRestore(bundle, staging).ok);
    EXPECT_EQ(readTextFile(finalPath), "old.example.com\n");
    EXPECT_EQ(readTextFile(staging.domainListsStageDir + "/" + list.listId), "new.example.com\n");

    std::error_code ec;
    std::filesystem::remove_all(staging.domainListsStageDir, ec);
    ASSERT_FALSE(ec);

    const auto status = PolicyCheckpoint::restoreBundleToLivePolicy(bundle, staging);
    EXPECT_FALSE(status.ok);
    EXPECT_TRUE(settings.blockEnabled());
    EXPECT_EQ(readTextFile(finalPath), "old.example.com\n");

    PolicyCheckpoint::Bundle slotBundle;
    PolicyCheckpoint::SlotMetadata restoredMeta;
    EXPECT_TRUE(PolicyCheckpoint::readSlot(0, slotBundle, restoredMeta).ok);
    EXPECT_TRUE(restoredMeta.present);
}

TEST_F(ControlVNextCheckpointSurfaceTest, SerializerRejectsCorruptAndUnsupportedBundles) {
    PolicyCheckpoint::Bundle bundle = PolicyCheckpoint::captureLivePolicy();
    auto list = makeCheckpointDomainList();
    list.domains = {"example.com"};
    bundle.domainLists.push_back(std::move(list));
    std::string encoded;
    ASSERT_TRUE(PolicyCheckpoint::encodeBundle(bundle, encoded).ok);

    PolicyCheckpoint::Bundle decoded;
    EXPECT_TRUE(PolicyCheckpoint::decodeBundle(encoded, decoded).ok);

    std::string unsupported = encoded;
    const std::string versionFrom = "\"formatVersion\":1";
    const std::string versionTo = "\"formatVersion\":999";
    const auto versionPos = unsupported.find(versionFrom);
    ASSERT_NE(versionPos, std::string::npos);
    unsupported.replace(versionPos, versionFrom.size(), versionTo);
    EXPECT_FALSE(PolicyCheckpoint::decodeBundle(unsupported, decoded).ok);

    std::string duplicateSections = encoded;
    const std::string sectionsKey = "\"sections\":";
    const auto sectionsPos = duplicateSections.find(sectionsKey);
    ASSERT_NE(sectionsPos, std::string::npos);
    duplicateSections.insert(sectionsPos, "\"sections\":{},");
    EXPECT_FALSE(PolicyCheckpoint::decodeBundle(duplicateSections, decoded).ok);

    EXPECT_FALSE(PolicyCheckpoint::decodeBundle(encoded.substr(0, encoded.size() / 2), decoded).ok);

    std::string badCount = encoded;
    const std::string countFrom = "\"domainsCount\":1";
    if (const auto countPos = badCount.find(countFrom); countPos != std::string::npos) {
        badCount.replace(countPos, countFrom.size(), "\"domainsCount\":2");
        EXPECT_FALSE(PolicyCheckpoint::decodeBundle(badCount, decoded).ok);
    }

    std::string overCap;
    overCap.resize(static_cast<std::size_t>(PolicyCheckpoint::kMaxSlotBytes + 1), 'x');
    const auto overCapStatus = PolicyCheckpoint::decodeBundle(overCap, decoded);
    EXPECT_FALSE(overCapStatus.ok);
    EXPECT_EQ(overCapStatus.code, "CAPACITY_EXCEEDED");
}

} // namespace

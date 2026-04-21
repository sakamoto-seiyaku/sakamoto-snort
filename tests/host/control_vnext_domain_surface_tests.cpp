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
#include <RulesManager.hpp>
#include <Settings.hpp>
#include <sucre-snort.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <limits>
#include <limits.h>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

// ---- Test-only AppManager implementation seam ----
//
// The production AppManager implementation depends on ActivityManager + streaming
// infrastructure. For vNext domain-surface unit tests we only need a minimal
// in-memory selector registry to satisfy {uid} / {pkg,userId} lookups.

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
std::shared_mutex mutexListeners;

namespace {

constexpr ControlVNextSession::Limits kLimits{.maxRequestBytes = 16 * 1024 * 1024,
                                              .maxResponseBytes = 16 * 1024 * 1024};

std::string makeTempDir() {
    const auto base = std::filesystem::temp_directory_path();
    std::string tmpl = (base / "sucre-snort-domains.XXXXXX").string();
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

        auto plan = ControlVNextSessionCommands::handleDomainCommand(view, kLimits);
        EXPECT_TRUE(plan.has_value());
        if (!plan.has_value()) {
            return ControlVNext::makeErrorResponse(id, "UNSUPPORTED_COMMAND", "not handled by domain handler");
        }
        return std::move(plan->response);
    }

    static rapidjson::Document callDoc(rapidjson::Document &req) {
        ControlVNext::RequestView view;
        const auto envErr = ControlVNext::parseRequestEnvelope(req, view);
        EXPECT_FALSE(envErr.has_value());
        if (envErr.has_value()) {
            return ControlVNext::makeErrorResponse(view.id, envErr->code, envErr->message);
        }

        auto plan = ControlVNextSessionCommands::handleDomainCommand(view, kLimits);
        EXPECT_TRUE(plan.has_value());
        if (!plan.has_value()) {
            return ControlVNext::makeErrorResponse(view.id, "UNSUPPORTED_COMMAND", "not handled by domain handler");
        }
        return std::move(plan->response);
    }
};

class ControlVNextDomainSurfaceTest : public ::testing::Test {
protected:
    std::string tmpDir;

    void SetUp() override {
        tmpDir = makeTempDir();
        std::filesystem::create_directories(tmpDir);
        Settings::setSaveDirDomainListsOverrideForTesting(tmpDir);

        settings.reset();
        blockingListManager.reset();
        appManager.reset();
        domManager.reset();
        rulesManager.reset();
    }

    void TearDown() override {
        Settings::setSaveDirDomainListsOverrideForTesting("");
        std::error_code ec;
        std::filesystem::remove_all(tmpDir, ec);
    }
};

TEST_F(ControlVNextDomainSurfaceTest, DomainRulesGetSortedShape) {
    rulesManager.upsertRuleWithId(10, Rule::DOMAIN, "example.com");
    rulesManager.upsertRuleWithId(2, Rule::REGEX, ".*google.*");

    rapidjson::Document args(rapidjson::kObjectType);
    const rapidjson::Document resp = Rpc::call(/*id=*/1, "DOMAINRULES.GET", args);

    ControlVNext::ResponseView view;
    const auto envErr = ControlVNext::parseResponseEnvelope(resp, view);
    ASSERT_FALSE(envErr.has_value());
    ASSERT_TRUE(view.ok);
    ASSERT_NE(view.result, nullptr);
    ASSERT_TRUE(view.result->HasMember("rules"));
    const auto &rules = (*view.result)["rules"];
    ASSERT_TRUE(rules.IsArray());
    ASSERT_EQ(rules.Size(), 2u);

    ASSERT_TRUE(rules[0].HasMember("ruleId"));
    ASSERT_TRUE(rules[0]["ruleId"].IsUint());
    ASSERT_TRUE(rules[0].HasMember("type"));
    ASSERT_TRUE(rules[0]["type"].IsString());
    ASSERT_TRUE(rules[0].HasMember("pattern"));
    ASSERT_TRUE(rules[0]["pattern"].IsString());

    EXPECT_EQ(rules[0]["ruleId"].GetUint(), 2u);
    EXPECT_STREQ(rules[0]["type"].GetString(), "regex");
    EXPECT_STREQ(rules[0]["pattern"].GetString(), ".*google.*");

    EXPECT_EQ(rules[1]["ruleId"].GetUint(), 10u);
    EXPECT_STREQ(rules[1]["type"].GetString(), "domain");
    EXPECT_STREQ(rules[1]["pattern"].GetString(), "example.com");
}

TEST_F(ControlVNextDomainSurfaceTest, DomainRulesApplyAssignsRuleIdAndEchoesSorted) {
    rapidjson::Document args(rapidjson::kObjectType);
    auto &alloc = args.GetAllocator();

    rapidjson::Value rules(rapidjson::kArrayType);
    {
        rapidjson::Value r(rapidjson::kObjectType);
        r.AddMember("type", rapidjson::Value("domain", alloc), alloc);
        r.AddMember("pattern", rapidjson::Value("example.com", alloc), alloc);
        rules.PushBack(r, alloc);
    }
    {
        rapidjson::Value r(rapidjson::kObjectType);
        r.AddMember("type", rapidjson::Value("regex", alloc), alloc);
        r.AddMember("pattern", rapidjson::Value(".*google.*", alloc), alloc);
        rules.PushBack(r, alloc);
    }
    args.AddMember("rules", rules, alloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/2, "DOMAINRULES.APPLY", args);

    ControlVNext::ResponseView view;
    const auto envErr = ControlVNext::parseResponseEnvelope(resp, view);
    ASSERT_FALSE(envErr.has_value());
    ASSERT_TRUE(view.ok);
    ASSERT_NE(view.result, nullptr);
    const auto &outRules = (*view.result)["rules"];
    ASSERT_TRUE(outRules.IsArray());
    ASSERT_EQ(outRules.Size(), 2u);

    ASSERT_TRUE(outRules[0]["ruleId"].IsUint());
    ASSERT_TRUE(outRules[1]["ruleId"].IsUint());
    EXPECT_LT(outRules[0]["ruleId"].GetUint(), outRules[1]["ruleId"].GetUint());

    // First rule should be assigned 0 after reset().
    EXPECT_EQ(outRules[0]["ruleId"].GetUint(), 0u);
    EXPECT_STREQ(outRules[0]["type"].GetString(), "domain");
    EXPECT_STREQ(outRules[0]["pattern"].GetString(), "example.com");

    EXPECT_EQ(outRules[1]["ruleId"].GetUint(), 1u);
    EXPECT_STREQ(outRules[1]["type"].GetString(), "regex");
    EXPECT_STREQ(outRules[1]["pattern"].GetString(), ".*google.*");
}

TEST_F(ControlVNextDomainSurfaceTest, DomainRulesApplyRejectsInvalidRegexAndIsAtomic) {
    rapidjson::Document args(rapidjson::kObjectType);
    auto &alloc = args.GetAllocator();

    rapidjson::Value rules(rapidjson::kArrayType);
    rapidjson::Value r(rapidjson::kObjectType);
    r.AddMember("type", rapidjson::Value("domain", alloc), alloc);
    r.AddMember("pattern", rapidjson::Value("[", alloc), alloc);
    rules.PushBack(r, alloc);
    args.AddMember("rules", rules, alloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/3, "DOMAINRULES.APPLY", args);

    ControlVNext::ResponseView view;
    const auto envErr = ControlVNext::parseResponseEnvelope(resp, view);
    ASSERT_FALSE(envErr.has_value());
    ASSERT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "INVALID_ARGUMENT");

    rapidjson::Document emptyArgs(rapidjson::kObjectType);
    const rapidjson::Document getResp = Rpc::call(/*id=*/4, "DOMAINRULES.GET", emptyArgs);
    ControlVNext::ResponseView getView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(getResp, getView).has_value());
    ASSERT_TRUE(getView.ok);
    ASSERT_NE(getView.result, nullptr);
    ASSERT_TRUE((*getView.result)["rules"].IsArray());
    EXPECT_EQ((*getView.result)["rules"].Size(), 0u);
}

TEST_F(ControlVNextDomainSurfaceTest, DomainRulesApplyRejectsRemovalWithConflicts) {
    const uint32_t rid = rulesManager.addRule(Rule::DOMAIN, "example.com");
    rulesManager.addCustom(rid, Stats::WHITE, true);

    const auto app = std::make_shared<App>(12345, "com.example");
    rulesManager.addCustom(app, rid, Stats::BLACK, true);

    rapidjson::Document args(rapidjson::kObjectType);
    auto &alloc = args.GetAllocator();
    rapidjson::Value rules(rapidjson::kArrayType); // empty baseline -> attempts to remove rid
    args.AddMember("rules", rules, alloc);

    const rapidjson::Document resp = Rpc::call(/*id=*/5, "DOMAINRULES.APPLY", args);

    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    ASSERT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "INVALID_ARGUMENT");
    ASSERT_TRUE(view.error->HasMember("conflicts"));
    const auto &conflicts = (*view.error)["conflicts"];
    ASSERT_TRUE(conflicts.IsArray());
    ASSERT_GE(conflicts.Size(), 1u);

    const auto &c0 = conflicts[0];
    ASSERT_TRUE(c0.IsObject());
    EXPECT_EQ(c0["ruleId"].GetUint(), rid);
    ASSERT_TRUE(c0.HasMember("refs"));
    const auto &refs = c0["refs"];
    ASSERT_TRUE(refs.IsArray());

    bool sawDevice = false;
    bool sawApp = false;
    for (const auto &ref : refs.GetArray()) {
        ASSERT_TRUE(ref.HasMember("scope"));
        const std::string_view scope(ref["scope"].GetString(), ref["scope"].GetStringLength());
        if (scope == "device") {
            sawDevice = true;
        } else if (scope == "app") {
            ASSERT_TRUE(ref.HasMember("app"));
            ASSERT_TRUE(ref["app"].HasMember("uid"));
            EXPECT_EQ(ref["app"]["uid"].GetUint(), 12345u);
            sawApp = true;
        }
    }
    EXPECT_TRUE(sawDevice);
    EXPECT_TRUE(sawApp);

    // Atomicity: baseline should remain unchanged.
    rapidjson::Document emptyArgs(rapidjson::kObjectType);
    const rapidjson::Document getResp = Rpc::call(/*id=*/6, "DOMAINRULES.GET", emptyArgs);
    ControlVNext::ResponseView getView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(getResp, getView).has_value());
    ASSERT_TRUE(getView.ok);
    const auto &rulesOut = (*getView.result)["rules"];
    ASSERT_TRUE(rulesOut.IsArray());
    ASSERT_EQ(rulesOut.Size(), 1u);
    EXPECT_EQ(rulesOut[0]["ruleId"].GetUint(), rid);
}

TEST_F(ControlVNextDomainSurfaceTest, DomainPolicyGetApplyAckOnlyAndSelectorErrors) {
    const uint32_t rid = rulesManager.addRule(Rule::DOMAIN, "example.com");

    // Ack-only device apply.
    rapidjson::Document applyArgs(rapidjson::kObjectType);
    auto &alloc = applyArgs.GetAllocator();
    applyArgs.AddMember("scope", rapidjson::Value("device", alloc), alloc);

    rapidjson::Value allow(rapidjson::kObjectType);
    rapidjson::Value block(rapidjson::kObjectType);
    {
        rapidjson::Value domains(rapidjson::kArrayType);
        domains.PushBack(rapidjson::Value("ok.com", alloc), alloc);
        allow.AddMember("domains", domains, alloc);
        rapidjson::Value ruleIds(rapidjson::kArrayType);
        ruleIds.PushBack(rid, alloc);
        allow.AddMember("ruleIds", ruleIds, alloc);
    }
    {
        rapidjson::Value domains(rapidjson::kArrayType);
        domains.PushBack(rapidjson::Value("bad.com", alloc), alloc);
        block.AddMember("domains", domains, alloc);
        rapidjson::Value ruleIds(rapidjson::kArrayType);
        block.AddMember("ruleIds", ruleIds, alloc);
    }

    rapidjson::Value policy(rapidjson::kObjectType);
    policy.AddMember("allow", allow, alloc);
    policy.AddMember("block", block, alloc);
    applyArgs.AddMember("policy", policy, alloc);

    const rapidjson::Document applyResp = Rpc::call(/*id=*/10, "DOMAINPOLICY.APPLY", applyArgs);
    ControlVNext::ResponseView applyView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(applyResp, applyView).has_value());
    ASSERT_TRUE(applyView.ok);
    EXPECT_EQ(applyView.result, nullptr) << "DOMAINPOLICY.APPLY must be ack-only";

    // Device GET reflects policy.
    rapidjson::Document getArgs(rapidjson::kObjectType);
    getArgs.AddMember("scope", rapidjson::Value("device", getArgs.GetAllocator()),
                      getArgs.GetAllocator());
    const rapidjson::Document getResp = Rpc::call(/*id=*/11, "DOMAINPOLICY.GET", getArgs);
    ControlVNext::ResponseView getView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(getResp, getView).has_value());
    ASSERT_TRUE(getView.ok);
    ASSERT_NE(getView.result, nullptr);
    const auto &policyOut = (*getView.result)["policy"];
    ASSERT_TRUE(policyOut.IsObject());
    ASSERT_TRUE(policyOut["allow"]["ruleIds"].IsArray());
    EXPECT_EQ(policyOut["allow"]["ruleIds"].Size(), 1u);
    EXPECT_EQ(policyOut["allow"]["ruleIds"][0].GetUint(), rid);

    // Selector error: uid not found.
    rapidjson::Document appGetArgs(rapidjson::kObjectType);
    auto &aAlloc = appGetArgs.GetAllocator();
    appGetArgs.AddMember("scope", rapidjson::Value("app", aAlloc), aAlloc);
    rapidjson::Value appSel(rapidjson::kObjectType);
    appSel.AddMember("uid", 424242u, aAlloc);
    appGetArgs.AddMember("app", appSel, aAlloc);

    const rapidjson::Document selResp = Rpc::call(/*id=*/12, "DOMAINPOLICY.GET", appGetArgs);
    ControlVNext::ResponseView selView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(selResp, selView).has_value());
    ASSERT_FALSE(selView.ok);
    ASSERT_NE(selView.error, nullptr);
    EXPECT_STREQ((*selView.error)["code"].GetString(), "SELECTOR_NOT_FOUND");
    ASSERT_TRUE(selView.error->HasMember("candidates"));
    EXPECT_TRUE((*selView.error)["candidates"].IsArray());

    // Invalid ruleId rejection.
    rapidjson::Document badApply(rapidjson::kObjectType);
    auto &bAlloc = badApply.GetAllocator();
    badApply.AddMember("scope", rapidjson::Value("device", bAlloc), bAlloc);
    rapidjson::Value badPolicy(rapidjson::kObjectType);
    rapidjson::Value badAllow(rapidjson::kObjectType);
    rapidjson::Value badBlock(rapidjson::kObjectType);
    badAllow.AddMember("domains", rapidjson::Value(rapidjson::kArrayType), bAlloc);
    {
        rapidjson::Value ruleIds(rapidjson::kArrayType);
        ruleIds.PushBack(999u, bAlloc);
        badAllow.AddMember("ruleIds", ruleIds, bAlloc);
    }
    badBlock.AddMember("domains", rapidjson::Value(rapidjson::kArrayType), bAlloc);
    badBlock.AddMember("ruleIds", rapidjson::Value(rapidjson::kArrayType), bAlloc);
    badPolicy.AddMember("allow", badAllow, bAlloc);
    badPolicy.AddMember("block", badBlock, bAlloc);
    badApply.AddMember("policy", badPolicy, bAlloc);

    const rapidjson::Document badResp = Rpc::call(/*id=*/13, "DOMAINPOLICY.APPLY", badApply);
    ControlVNext::ResponseView badView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(badResp, badView).has_value());
    ASSERT_FALSE(badView.ok);
    ASSERT_NE(badView.error, nullptr);
    EXPECT_STREQ((*badView.error)["code"].GetString(), "INVALID_ARGUMENT");
}

TEST_F(ControlVNextDomainSurfaceTest, DomainListsGetApplySortPatchAndRemoveNotFound) {
    const std::string listAllow = "00000000-0000-0000-0000-000000000001";
    const std::string listBlock = "00000000-0000-0000-0000-000000000002";
    const std::string unknown = "00000000-0000-0000-0000-00000000ffff";

    // Create two lists.
    rapidjson::Document apply(rapidjson::kObjectType);
    auto &alloc = apply.GetAllocator();
    rapidjson::Value upsert(rapidjson::kArrayType);
    auto addList = [&](const std::string &id, const char *kind, const char *url, const char *name) {
        rapidjson::Value item(rapidjson::kObjectType);
        item.AddMember("listId", rapidjson::Value(id.c_str(), alloc), alloc);
        item.AddMember("listKind", rapidjson::Value(kind, alloc), alloc);
        item.AddMember("mask", 1u, alloc);
        item.AddMember("enabled", 0u, alloc);
        item.AddMember("url", rapidjson::Value(url, alloc), alloc);
        item.AddMember("name", rapidjson::Value(name, alloc), alloc);
        item.AddMember("updatedAt", rapidjson::Value("2026-01-01_00:00:00", alloc), alloc);
        item.AddMember("etag", rapidjson::Value("etag0", alloc), alloc);
        item.AddMember("outdated", 1u, alloc);
        item.AddMember("domainsCount", 0u, alloc);
        upsert.PushBack(item, alloc);
    };
    addList(listAllow, "allow", "https://allow", "Allow");
    addList(listBlock, "block", "https://block", "Block");
    apply.AddMember("upsert", upsert, alloc);

    const rapidjson::Document createResp = Rpc::call(/*id=*/20, "DOMAINLISTS.APPLY", apply);
    ControlVNext::ResponseView createView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(createResp, createView).has_value());
    ASSERT_TRUE(createView.ok);

    // Patch: update allow-list name only; url must be preserved.
    rapidjson::Document patch(rapidjson::kObjectType);
    auto &pAlloc = patch.GetAllocator();
    rapidjson::Value upsert2(rapidjson::kArrayType);
    {
        rapidjson::Value item(rapidjson::kObjectType);
        item.AddMember("listId", rapidjson::Value(listAllow.c_str(), pAlloc), pAlloc);
        item.AddMember("listKind", rapidjson::Value("allow", pAlloc), pAlloc);
        item.AddMember("mask", 1u, pAlloc);
        item.AddMember("enabled", 0u, pAlloc);
        item.AddMember("name", rapidjson::Value("Allow2", pAlloc), pAlloc);
        upsert2.PushBack(item, pAlloc);
    }
    patch.AddMember("upsert", upsert2, pAlloc);

    const rapidjson::Document patchResp = Rpc::call(/*id=*/21, "DOMAINLISTS.APPLY", patch);
    ControlVNext::ResponseView patchView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(patchResp, patchView).has_value());
    ASSERT_TRUE(patchView.ok);

    // Remove unknown id should not fail, must appear in notFound[].
    rapidjson::Document rm(rapidjson::kObjectType);
    auto &rAlloc = rm.GetAllocator();
    rapidjson::Value remove(rapidjson::kArrayType);
    remove.PushBack(rapidjson::Value(unknown.c_str(), rAlloc), rAlloc);
    rm.AddMember("remove", remove, rAlloc);

    const rapidjson::Document rmResp = Rpc::call(/*id=*/22, "DOMAINLISTS.APPLY", rm);
    ControlVNext::ResponseView rmView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(rmResp, rmView).has_value());
    ASSERT_TRUE(rmView.ok);
    ASSERT_NE(rmView.result, nullptr);
    ASSERT_TRUE((*rmView.result)["notFound"].IsArray());
    ASSERT_EQ((*rmView.result)["notFound"].Size(), 1u);
    EXPECT_STREQ((*rmView.result)["notFound"][0].GetString(), unknown.c_str());

    // GET: sorted by kind then id (string order: allow before block).
    rapidjson::Document emptyArgs(rapidjson::kObjectType);
    const rapidjson::Document getResp = Rpc::call(/*id=*/23, "DOMAINLISTS.GET", emptyArgs);
    ControlVNext::ResponseView getView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(getResp, getView).has_value());
    ASSERT_TRUE(getView.ok);
    ASSERT_NE(getView.result, nullptr);
    const auto &lists = (*getView.result)["lists"];
    ASSERT_TRUE(lists.IsArray());
    ASSERT_EQ(lists.Size(), 2u);
    EXPECT_STREQ(lists[0]["listKind"].GetString(), "allow");
    EXPECT_STREQ(lists[0]["listId"].GetString(), listAllow.c_str());
    EXPECT_STREQ(lists[1]["listKind"].GetString(), "block");
    EXPECT_STREQ(lists[1]["listId"].GetString(), listBlock.c_str());

    // Patch semantics: url preserved; name updated.
    EXPECT_STREQ(lists[0]["url"].GetString(), "https://allow");
    EXPECT_STREQ(lists[0]["name"].GetString(), "Allow2");
}

TEST_F(ControlVNextDomainSurfaceTest, DomainListsImportRejectsOversizedWithLimits) {
    constexpr uint32_t maxImportBytes = 16u * 1024u * 1024u;

    const std::string listId = "00000000-0000-0000-0000-000000000000";
    const std::string domain(HOST_NAME_MAX, 'a');
    const uint32_t per = static_cast<uint32_t>(domain.size());
    ASSERT_GT(per, 0u);

    // Need sum(domain.size()) > maxImportBytes.
    const uint32_t count = maxImportBytes / per + 1u;

    rapidjson::Document req(rapidjson::kObjectType);
    auto &alloc = req.GetAllocator();
    req.AddMember("id", 30u, alloc);
    req.AddMember("cmd", rapidjson::Value("DOMAINLISTS.IMPORT", alloc), alloc);

    rapidjson::Value args(rapidjson::kObjectType);
    args.AddMember("listId", rapidjson::Value(listId.c_str(), alloc), alloc);
    args.AddMember("listKind", rapidjson::Value("block", alloc), alloc);
    args.AddMember("mask", 1u, alloc);
    args.AddMember("clear", 1u, alloc);

    rapidjson::Value domains(rapidjson::kArrayType);
    domains.Reserve(count, alloc);
    for (uint32_t i = 0; i < count; ++i) {
        domains.PushBack(
            rapidjson::Value(rapidjson::StringRef(domain.data(),
                                                  static_cast<rapidjson::SizeType>(domain.size()))),
            alloc);
    }
    args.AddMember("domains", domains, alloc);
    req.AddMember("args", args, alloc);

    const rapidjson::Document resp = Rpc::callDoc(req);
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    ASSERT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "INVALID_ARGUMENT");
    ASSERT_TRUE(view.error->HasMember("limits"));
    const auto &limits = (*view.error)["limits"];
    ASSERT_TRUE(limits.IsObject());
    EXPECT_EQ(limits["maxImportDomains"].GetUint(), 1000000u);
    EXPECT_EQ(limits["maxImportBytes"].GetUint(), maxImportBytes);
}

TEST_F(ControlVNextDomainSurfaceTest, DomainListsImportUpdatesDomainsCountOnly) {
    const std::string listId = "11111111-1111-1111-1111-111111111111";

    // Create list with metadata fields set.
    rapidjson::Document apply(rapidjson::kObjectType);
    auto &alloc = apply.GetAllocator();
    rapidjson::Value upsert(rapidjson::kArrayType);
    {
        rapidjson::Value item(rapidjson::kObjectType);
        item.AddMember("listId", rapidjson::Value(listId.c_str(), alloc), alloc);
        item.AddMember("listKind", rapidjson::Value("block", alloc), alloc);
        item.AddMember("mask", 1u, alloc);
        item.AddMember("enabled", 0u, alloc);
        item.AddMember("url", rapidjson::Value("https://example/list", alloc), alloc);
        item.AddMember("name", rapidjson::Value("Example", alloc), alloc);
        item.AddMember("updatedAt", rapidjson::Value("2026-01-01_00:00:00", alloc), alloc);
        item.AddMember("etag", rapidjson::Value("etagX", alloc), alloc);
        item.AddMember("outdated", 0u, alloc);
        item.AddMember("domainsCount", 0u, alloc);
        upsert.PushBack(item, alloc);
    }
    apply.AddMember("upsert", upsert, alloc);
    const rapidjson::Document createResp = Rpc::call(/*id=*/40, "DOMAINLISTS.APPLY", apply);
    ControlVNext::ResponseView createView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(createResp, createView).has_value());
    ASSERT_TRUE(createView.ok);

    // Import two domains; should update only domainsCount.
    rapidjson::Document imp(rapidjson::kObjectType);
    auto &iAlloc = imp.GetAllocator();
    imp.AddMember("listId", rapidjson::Value(listId.c_str(), iAlloc), iAlloc);
    imp.AddMember("listKind", rapidjson::Value("block", iAlloc), iAlloc);
    imp.AddMember("mask", 1u, iAlloc);
    imp.AddMember("clear", 1u, iAlloc);
    rapidjson::Value domains(rapidjson::kArrayType);
    domains.PushBack(rapidjson::Value("a.com", iAlloc), iAlloc);
    domains.PushBack(rapidjson::Value("b.com", iAlloc), iAlloc);
    imp.AddMember("domains", domains, iAlloc);

    const rapidjson::Document impResp = Rpc::call(/*id=*/41, "DOMAINLISTS.IMPORT", imp);
    ControlVNext::ResponseView impView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(impResp, impView).has_value());
    ASSERT_TRUE(impView.ok);
    ASSERT_NE(impView.result, nullptr);
    EXPECT_EQ((*impView.result)["imported"].GetUint(), 2u);

    rapidjson::Document emptyArgs(rapidjson::kObjectType);
    const rapidjson::Document getResp = Rpc::call(/*id=*/42, "DOMAINLISTS.GET", emptyArgs);
    ControlVNext::ResponseView getView;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(getResp, getView).has_value());
    ASSERT_TRUE(getView.ok);
    const auto &lists = (*getView.result)["lists"];
    ASSERT_TRUE(lists.IsArray());

    const rapidjson::Value *found = nullptr;
    for (const auto &item : lists.GetArray()) {
        if (item["listId"].IsString() && listId == item["listId"].GetString()) {
            found = &item;
            break;
        }
    }
    ASSERT_NE(found, nullptr);
    EXPECT_EQ((*found)["domainsCount"].GetUint(), 2u);

    // Subscription metadata preserved.
    EXPECT_STREQ((*found)["url"].GetString(), "https://example/list");
    EXPECT_STREQ((*found)["name"].GetString(), "Example");
    EXPECT_STREQ((*found)["updatedAt"].GetString(), "2026-01-01_00:00:00");
    EXPECT_STREQ((*found)["etag"].GetString(), "etagX");
    EXPECT_EQ((*found)["outdated"].GetUint(), 0u);
}

} // namespace

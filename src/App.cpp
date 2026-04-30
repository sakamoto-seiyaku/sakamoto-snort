/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sstream>
#include <string_view>
#include <utility>
#include <RulesManager.hpp>
#include <Settings.hpp>
#include <App.hpp>
#include <Settings.hpp>
#include <mutex>

namespace {

namespace Explain = ControlVNextStreamExplain;

[[nodiscard]] std::string dnsScopeStr(const DomainPolicySource source) {
    switch (source) {
    case DomainPolicySource::CUSTOM_WHITELIST:
    case DomainPolicySource::CUSTOM_BLACKLIST:
    case DomainPolicySource::CUSTOM_RULE_WHITE:
    case DomainPolicySource::CUSTOM_RULE_BLACK:
        return "APP";
    case DomainPolicySource::DOMAIN_DEVICE_WIDE_AUTHORIZED:
    case DomainPolicySource::DOMAIN_DEVICE_WIDE_BLOCKED:
        return "DEVICE_WIDE";
    case DomainPolicySource::MASK_FALLBACK:
        return "FALLBACK";
    }
    return "FALLBACK";
}

void fillRuleIds(Explain::DnsStageSnapshot &stage) {
    stage.ruleIds.reserve(stage.ruleSnapshots.size());
    for (const auto &snapshot : stage.ruleSnapshots) {
        stage.ruleIds.push_back(snapshot.ruleId);
    }
}

} // namespace

App::App(const Uid uid, const NamesVec &names)
    : App(uid, settings.systemAppPrefix + std::to_string(uid), names,
          Settings::userSaveDirSystem(uid / 100000) + std::to_string(uid),
          settings.standardListBit + settings.customListBit, 0, true) {}

App::App(const Uid uid, const std::string &name)
    : App(uid, name, NamesVec(), Settings::userSaveDirPackages(uid / 100000) + name,
          settings.blockMask(), settings.blockIface(),
          settings.blockMask() & settings.customListBit) {}

App::App(const Uid uid, const std::string &name, const NamesVec &names,
         const std::string &&saveFile, const std::uint8_t blockMask, const std::uint8_t blockIface,
         const bool useCustomList)
    : _saver(saveFile)
    , _uid(uid)
    , _name(name)
    , _names(names)
    , _nameSnap(std::make_shared<const std::string>(name))
    , _blockMask(blockMask)
    , _blockIface(blockIface)
    , _useCustomList(useCustomList) {}

bool App::isAnonymous() const {
    const std::shared_lock<std::shared_mutex> lock(_mutexMeta);
    return _name.rfind(settings.systemAppPrefix, 0) == 0;
}

bool App::upgradeName(const std::string &newName) {
    const std::unique_lock<std::shared_mutex> lock(_mutexMeta);
    if (_name.rfind(settings.systemAppPrefix, 0) != 0) {
        return false;  // Already named, no upgrade needed
    }

    // Get old and new save file paths
    const uint32_t userId = _uid / 100000;
    Settings::ensureUserDirs(userId);
    std::string oldPath = Settings::userSaveDirSystem(userId) + std::to_string(_uid);
    std::string newPath = Settings::userSaveDirPackages(userId) + newName;

    // Rename save file if it exists
    std::rename(oldPath.c_str(), newPath.c_str());

    // Update internal state
    _name = newName;
    _names.clear();
    _saver = Saver(newPath);
    // Publish the new name for lock-free readers (stream output paths).
    std::atomic_store_explicit(&_nameSnap, std::make_shared<const std::string>(_name),
                              std::memory_order_release);
    _saved = false;

    LOG(INFO) << "App upgraded from anonymous to " << newName << " (uid=" << _uid << ")";
    return true;
}

bool App::upgradeName(const NamesVec &newNames) {
    if (newNames.empty()) {
        return false;
    }
    return upgradeName(newNames[0]);
}

bool App::hasData(const Stats::View view) { return _stats.hasData(view); }

bool App::hasData(const Stats::Color cs, const Stats::View view) {
    const std::shared_lock<std::shared_mutex> lock(mutex(cs));
    for (auto &[domain, stats] : domStats(cs)) {
        if (stats.hasData(view)) {
            return true;
        }
    }
    return false;
}

const std::pair<bool, Stats::Color> App::blocked(const Domain::Ptr &domain) {
    if (domain == nullptr || !settings.blockEnabled()) {
        return {false, Stats::GREY};
    }
    const auto cs = domain->color();
    if (_useCustomList) {
        if (_customWhitelist.exists(domain)) {
            return {false, cs};
        }
        if (_customBlacklist.exists(domain)) {
            return {true, cs};
        }
        if (_whiteRules.match(domain)) {
            return {false, cs};
        }
        if (_blackRules.match(domain)) {
            return {true, cs};
        }
        if (domManager.authorized(domain)) {
            return {false, cs};
        }
        if (domManager.blocked(domain)) {
            return {true, cs};
        }
    }
    return {_blockMask & domain->blockMask(), cs};
}

App::BlockedWithSource App::blockedWithSource(const Domain::Ptr &domain) {
    if (domain == nullptr || !settings.blockEnabled()) {
        return {.blocked = false, .color = Stats::GREY, .policySource = DomainPolicySource::MASK_FALLBACK};
    }

    const auto cs = domain->color();
    if (_useCustomList) {
        if (_customWhitelist.exists(domain)) {
            return {.blocked = false, .color = cs, .policySource = DomainPolicySource::CUSTOM_WHITELIST};
        }
        if (_customBlacklist.exists(domain)) {
            return {.blocked = true, .color = cs, .policySource = DomainPolicySource::CUSTOM_BLACKLIST};
        }
        if (_whiteRules.match(domain)) {
            return {.blocked = false, .color = cs, .policySource = DomainPolicySource::CUSTOM_RULE_WHITE};
        }
        if (_blackRules.match(domain)) {
            return {.blocked = true, .color = cs, .policySource = DomainPolicySource::CUSTOM_RULE_BLACK};
        }
        if (domManager.authorized(domain)) {
            return {.blocked = false,
                    .color = cs,
                    .policySource = DomainPolicySource::DOMAIN_DEVICE_WIDE_AUTHORIZED};
        }
        if (domManager.blocked(domain)) {
            return {.blocked = true, .color = cs, .policySource = DomainPolicySource::DOMAIN_DEVICE_WIDE_BLOCKED};
        }
    }

    const bool blocked = _blockMask & domain->blockMask();
    return {.blocked = blocked, .color = cs, .policySource = DomainPolicySource::MASK_FALLBACK};
}

App::BlockedWithSourceAndRuleId App::blockedWithSourceAndRuleId(const Domain::Ptr &domain) {
    if (domain == nullptr || !settings.blockEnabled()) {
        return {.blocked = false,
                .color = Stats::GREY,
                .policySource = DomainPolicySource::MASK_FALLBACK,
                .ruleId = std::nullopt};
    }

    const auto cs = domain->color();
    if (_useCustomList) {
        if (_customWhitelist.exists(domain)) {
            return {.blocked = false,
                    .color = cs,
                    .policySource = DomainPolicySource::CUSTOM_WHITELIST,
                    .ruleId = std::nullopt};
        }
        if (_customBlacklist.exists(domain)) {
            return {.blocked = true,
                    .color = cs,
                    .policySource = DomainPolicySource::CUSTOM_BLACKLIST,
                    .ruleId = std::nullopt};
        }

        if (_whiteRules.match(domain)) {
            return {.blocked = false,
                    .color = cs,
                    .policySource = DomainPolicySource::CUSTOM_RULE_WHITE,
                    .ruleId = _whiteRules.matchFirstRuleId(domain)};
        }
        if (_blackRules.match(domain)) {
            return {.blocked = true,
                    .color = cs,
                    .policySource = DomainPolicySource::CUSTOM_RULE_BLACK,
                    .ruleId = _blackRules.matchFirstRuleId(domain)};
        }

        if (domManager.authorized(domain)) {
            return {.blocked = false,
                    .color = cs,
                    .policySource = DomainPolicySource::DOMAIN_DEVICE_WIDE_AUTHORIZED,
                    .ruleId = domManager.authorizedRuleId(domain)};
        }
        if (domManager.blocked(domain)) {
            return {.blocked = true,
                    .color = cs,
                    .policySource = DomainPolicySource::DOMAIN_DEVICE_WIDE_BLOCKED,
                    .ruleId = domManager.blockedRuleId(domain)};
        }
    }

    const bool blocked = _blockMask & domain->blockMask();
    return {.blocked = blocked,
            .color = cs,
            .policySource = DomainPolicySource::MASK_FALLBACK,
            .ruleId = std::nullopt};
}

App::DomainPolicyDebugSnapshot
App::evaluateDomainPolicyDebug(const Domain::Ptr &domain, const bool blockEnabled,
                               const bool tracked, const bool getBlackIPs) {
    DomainPolicyDebugSnapshot result{};
    result.color = (domain != nullptr && blockEnabled) ? domain->color() : Stats::GREY;
    result.useCustomList = _useCustomList.load(std::memory_order_relaxed);
    result.domMask = domain != nullptr ? static_cast<std::uint32_t>(domain->blockMask()) : 0u;
    result.appMask = static_cast<std::uint32_t>(_blockMask.load(std::memory_order_relaxed));

    Explain::DnsExplainSnapshot explain{};
    explain.inputs = Explain::DnsInputs{
        .blockEnabled = blockEnabled,
        .tracked = tracked,
        .domainCustomEnabled = result.useCustomList,
        .useCustomList = result.useCustomList,
        .domain = domain != nullptr ? domain->name() : std::string(),
        .domMask = result.domMask,
        .appMask = result.appMask,
    };

    bool shortCircuited = false;
    const auto setDecision = [&](const bool blocked, const DomainPolicySource source,
                                 const std::optional<std::uint32_t> ruleId) {
        result.blocked = blocked;
        result.policySource = source;
        result.ruleId = ruleId;
    };
    const auto firstRuleId = [](const Explain::DnsStageSnapshot &stage)
        -> std::optional<std::uint32_t> {
        if (stage.ruleSnapshots.empty()) {
            return std::nullopt;
        }
        return stage.ruleSnapshots.front().ruleId;
    };
    const auto appendStage = [&](Explain::DnsStageSnapshot stage) {
        if (!stage.enabled) {
            stage.evaluated = false;
            stage.skipReason = std::string(Explain::kSkipDisabled);
        } else if (shortCircuited) {
            stage.evaluated = false;
            stage.matched = false;
            stage.winner = false;
            stage.outcome = "none";
            stage.skipReason = std::string(Explain::kSkipShortCircuited);
        }
        if (stage.winner) {
            shortCircuited = true;
        }
        explain.stages.push_back(std::move(stage));
    };

    const bool customStageEnabled = blockEnabled && result.useCustomList;
    const auto makeListStage = [&](const std::string_view name, const Stats::Color color,
                                   const std::string &scope, const std::string &action,
                                   const DomainPolicySource winSource,
                                   const bool deviceWide, const bool blocked) {
        Explain::DnsStageSnapshot stage{};
        stage.name = std::string(name);
        stage.enabled = customStageEnabled;
        if (stage.enabled && !shortCircuited) {
            stage.evaluated = true;
            stage.listEntrySnapshots =
                deviceWide ? domManager.matchingCustomListExplainSnapshots(domain, color, scope, action)
                           : customList(color).matchingExplainSnapshots(domain, scope, action);
            stage.matched = !stage.listEntrySnapshots.empty();
            stage.outcome = stage.matched ? action : "none";
            stage.winner = stage.matched;
            if (stage.winner) {
                setDecision(blocked, winSource, std::nullopt);
            }
        }
        appendStage(std::move(stage));
    };

    const auto makeRuleStage = [&](const std::string_view name, const Stats::Color color,
                                   const std::string &scope, const std::string &action,
                                   const DomainPolicySource winSource,
                                   const bool deviceWide, const bool blocked) {
        Explain::DnsStageSnapshot stage{};
        stage.name = std::string(name);
        stage.enabled = customStageEnabled;
        if (stage.enabled && !shortCircuited) {
            stage.evaluated = true;
            stage.ruleSnapshots =
                deviceWide ? domManager.matchingCustomRuleExplainSnapshots(
                                 domain, color, scope, action, std::nullopt, stage.truncated,
                                 stage.omittedCandidateCount)
                           : customRules(color).matchingExplainSnapshots(
                                 domain, scope, action, std::nullopt, stage.truncated,
                                 stage.omittedCandidateCount);
            fillRuleIds(stage);
            stage.matched = !stage.ruleSnapshots.empty();
            stage.outcome = stage.matched ? action : "none";
            stage.winner = stage.matched;
            if (stage.winner) {
                setDecision(blocked, winSource, firstRuleId(stage));
            }
        }
        appendStage(std::move(stage));
    };

    makeListStage(Explain::kDnsStageAppAllowList, Stats::WHITE, "APP", "allow",
                  DomainPolicySource::CUSTOM_WHITELIST, false, false);
    makeListStage(Explain::kDnsStageAppBlockList, Stats::BLACK, "APP", "block",
                  DomainPolicySource::CUSTOM_BLACKLIST, false, true);
    makeRuleStage(Explain::kDnsStageAppAllowRules, Stats::WHITE, "APP", "allow",
                  DomainPolicySource::CUSTOM_RULE_WHITE, false, false);
    makeRuleStage(Explain::kDnsStageAppBlockRules, Stats::BLACK, "APP", "block",
                  DomainPolicySource::CUSTOM_RULE_BLACK, false, true);

    Explain::DnsStageSnapshot deviceAllow{};
    deviceAllow.name = std::string(Explain::kDnsStageDeviceAllow);
    deviceAllow.enabled = customStageEnabled;
    if (deviceAllow.enabled && !shortCircuited) {
        deviceAllow.evaluated = true;
        deviceAllow.listEntrySnapshots =
            domManager.matchingCustomListExplainSnapshots(domain, Stats::WHITE, "DEVICE_WIDE", "allow");
        deviceAllow.ruleSnapshots = domManager.matchingCustomRuleExplainSnapshots(
            domain, Stats::WHITE, "DEVICE_WIDE", "allow", std::nullopt,
            deviceAllow.truncated, deviceAllow.omittedCandidateCount);
        fillRuleIds(deviceAllow);
        deviceAllow.matched = !deviceAllow.listEntrySnapshots.empty() || !deviceAllow.ruleSnapshots.empty();
        deviceAllow.outcome = deviceAllow.matched ? "allow" : "none";
        deviceAllow.winner = deviceAllow.matched;
        if (deviceAllow.winner) {
            setDecision(false, DomainPolicySource::DOMAIN_DEVICE_WIDE_AUTHORIZED,
                        deviceAllow.listEntrySnapshots.empty() ? firstRuleId(deviceAllow) : std::nullopt);
        }
    }
    appendStage(std::move(deviceAllow));

    Explain::DnsStageSnapshot deviceBlock{};
    deviceBlock.name = std::string(Explain::kDnsStageDeviceBlock);
    deviceBlock.enabled = customStageEnabled;
    if (deviceBlock.enabled && !shortCircuited) {
        deviceBlock.evaluated = true;
        deviceBlock.listEntrySnapshots =
            domManager.matchingCustomListExplainSnapshots(domain, Stats::BLACK, "DEVICE_WIDE", "block");
        deviceBlock.ruleSnapshots = domManager.matchingCustomRuleExplainSnapshots(
            domain, Stats::BLACK, "DEVICE_WIDE", "block", std::nullopt,
            deviceBlock.truncated, deviceBlock.omittedCandidateCount);
        fillRuleIds(deviceBlock);
        deviceBlock.matched = !deviceBlock.listEntrySnapshots.empty() || !deviceBlock.ruleSnapshots.empty();
        deviceBlock.outcome = deviceBlock.matched ? "block" : "none";
        deviceBlock.winner = deviceBlock.matched;
        if (deviceBlock.winner) {
            setDecision(true, DomainPolicySource::DOMAIN_DEVICE_WIDE_BLOCKED,
                        deviceBlock.listEntrySnapshots.empty() ? firstRuleId(deviceBlock) : std::nullopt);
        }
    }
    appendStage(std::move(deviceBlock));

    Explain::DnsStageSnapshot maskFallback{};
    maskFallback.name = std::string(Explain::kDnsStageMaskFallback);
    maskFallback.enabled = blockEnabled;
    if (maskFallback.enabled && !shortCircuited) {
        const std::uint32_t effectiveMask = result.appMask & result.domMask;
        maskFallback.evaluated = true;
        maskFallback.matched = true;
        maskFallback.outcome = effectiveMask != 0 ? "block" : "allow";
        maskFallback.winner = true;
        maskFallback.maskFallback = Explain::DnsMaskEvidence{
            .domMask = result.domMask,
            .appMask = result.appMask,
            .effectiveMask = effectiveMask,
            .blocked = effectiveMask != 0,
        };
        setDecision(effectiveMask != 0, DomainPolicySource::MASK_FALLBACK, std::nullopt);
    }
    appendStage(std::move(maskFallback));

    result.getips = !result.blocked || getBlackIPs;
    explain.final = Explain::DnsFinal{
        .blocked = result.blocked,
        .getips = result.getips,
        .policySource = result.policySource,
        .scope = dnsScopeStr(result.policySource),
        .ruleId = result.ruleId,
    };
    result.explain = std::move(explain);
    return result;
}

void App::updateStats(const Domain::Ptr &domain, const Stats::Type ts, const Stats::Color cs,
                      const Stats::Block bs, const uint64_t val) {
    _saved = false;
    _stats.update(ts, cs, bs, val);
    domain->updateStats(ts, bs, val);
    auto &ds = domStats(cs);
    {
        const std::shared_lock<std::shared_mutex> lock(mutex(cs));
        if (auto it = ds.find(domain); it != ds.end()) {
            return it->second.update(ts, bs, val);
        }
    }
    const std::lock_guard lock(mutex(cs));
    return ds.try_emplace(domain).first->second.update(ts, bs, val);
}

void App::addCustomDomain(const std::string &name, const Stats::Color color) {
    _saved = false;
    const Domain::Ptr domain = domManager.make(std::move(name));
    customList(color).add(domain);
}

void App::removeCustomDomain(const std::string &name, const Stats::Color color) {
    _saved = false;
    if (const auto domain = domManager.find(std::move(name))) {
        customList(color).remove(domain);
    }
}

void App::printCustomDomains(std::ostream &out, const Stats::Color color) {
    customList(color).print(out);
}

std::vector<std::string> App::snapshotCustomDomains(const Stats::Color color) const {
    return customList(color).snapshotNames();
}

void App::addCustomRule(const Rule::Ptr rule, const bool compile, const Stats::Color color) {
    _saved = false;
    customRules(color).add(rule, compile);
}

void App::removeCustomRule(const Rule::Ptr rule, const bool compile, const Stats::Color color) {
    _saved = false;
    customRules(color).remove(rule, compile);
}

std::vector<Rule::Id> App::snapshotCustomRuleIds(const Stats::Color color) const {
    return customRules(color).snapshotRuleIds();
}

void App::buildCustomRules(const Stats::Color color) { customRules(color).build(); }

void App::printCustomRules(std::ostream &out, const Stats::Color color) {
    customRules(color).print(out);
}

void App::reset(const Stats::View view) {
    _saved = false;
    _stats.reset(view);
    for (auto &[map, mutex] : _domStats) {
        const std::lock_guard lock(mutex);
        if (view == Stats::ALL) {
            map.clear();
        } else {
            for (auto &[domain, stats] : map) {
                stats.reset(view);
            }
        }
    }
}

void App::removeFile() {
    const std::unique_lock<std::shared_mutex> lock(_mutexMeta);
    _saved = false;
    _saver.remove();
}

void App::save() {
    const std::shared_lock<std::shared_mutex> metaLock(_mutexMeta);
    if (!_saved || !_blackRules.saved() || !_whiteRules.saved()) {
        Settings::ensureUserDirs(_uid / 100000);
        _saver.save([&] {
            _saver.write<uint8_t>(_blockMask);
            _stats.save(_saver);
            for (auto &[map, mutex] : _domStats) {
                const std::shared_lock<std::shared_mutex> lock(mutex);
                _saver.write<uint32_t>(map.size());
                for (const auto &[domain, stats] : map) {
                    _saver.write(domain->name());
                    stats.save(_saver);
                }
            }
            _saver.write<bool>(_tracked);
            _customBlacklist.save(_saver);
            _customWhitelist.save(_saver);
            _saver.write<bool>(_useCustomList);
            _saver.write<uint8_t>(_blockMask);
            _saver.write<uint8_t>(_blockIface);
            _blackRules.save(_saver);
            _whiteRules.save(_saver);
        });
        _saved = true;
    }
}

void App::restore(const App::Ptr &app) {
    const std::shared_lock<std::shared_mutex> metaLock(_mutexMeta);
    _saver.restore([&] {
        _blockMask = _saver.read<uint8_t>();
        _blockMask = Settings::normalizeAppBlockMask(_blockMask);
        _stats.restore(_saver);
        // Protect per-color domain stats maps during restore (coarse-grained)
        for (auto &[map, mutex] : _domStats) {
            const std::lock_guard lock(mutex);
            uint32_t nb = _saver.read<uint32_t>();
            for (uint32_t i = 0; i < nb; ++i) {
                std::string name;
                _saver.readDomName(name);
                map.try_emplace(domManager.make(std::move(name))).first->second.restore(_saver);
            }
        }
        _tracked = _saver.read<bool>();
        _customBlacklist.restore(_saver);
        _customWhitelist.restore(_saver);
        _useCustomList = _saver.read<bool>();
        _blockMask = _saver.read<uint8_t>();
        _blockMask = Settings::normalizeAppBlockMask(_blockMask);
        _blockIface = _saver.read<uint8_t>();
        rulesManager.restoreCustomRules(_saver, app, Stats::BLACK);
        rulesManager.restoreCustomRules(_saver, app, Stats::WHITE);
    });
}

void App::print(std::ostream &out) {
    const auto names = this->names();
    print(out, [&](App &) {
        if (names.size() > 1) {
            out << "," << JSF("allNames") << "[";
            bool first = true;
            for (const auto &name : names) {
                when(first, out << ",");
                out << JSS(name);
            }
            out << "]";
        }
    });
}

void App::print(std::ostream &out, const PrintFun &&print) {
    out << "{" << JSF("name") << JSS(name()) << "," << JSF("uid") << _uid << "," << JSF("userId")
        << userId() << "," << JSF("appId") << appId() << "," << JSF("blocked")
        << static_cast<uint32_t>(_blockMask) << "," << JSF("blockIface")
        << static_cast<uint32_t>(_blockIface) << "," << JSF("tracked") << JSB(_tracked) << ","
        << JSF("useCustomList") << JSB(_useCustomList);
    print(*this);
    out << "}";
}

void App::printCustomLists(std::ostream &out) {
    out << "{" << JSF("blacklist");
    _customBlacklist.print(out);
    out << "," << JSF("whitelist");
    _customWhitelist.print(out);
    out << "}";
}

void App::migrateV4V5(AppStats &globStats) {

    auto migrate = [&](Stats::Color cs) {
        for (auto it = domStats(cs).begin(); it != domStats(cs).end();) {
            auto &[domain, stats] = *it;
            auto newcs = domain->color();
            if (cs != newcs) {
                auto &newStats = domStats(newcs).try_emplace(domain).first->second;
                newStats.migrateV4V5(stats);
                _stats.migrateV4V5(stats, static_cast<Stats::Color>(cs), newcs);
                globStats.migrateV4V5(stats, static_cast<Stats::Color>(cs), newcs);
                it = domStats(cs).erase(it);
            } else {
                ++it;
            }
        }
    };

    migrate(Stats::WHITE);
    migrate(Stats::BLACK);
}

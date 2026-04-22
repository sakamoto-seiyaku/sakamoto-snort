/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <atomic>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <vector>

#include <AppStats.hpp>
#include <DomainManager.hpp>
#include <CustomRules.hpp>
#include <DomainPolicySources.hpp>
#include <DomainPolicySourcesMetrics.hpp>
#include <IpRulesCapsCache.hpp>
#include <Settings.hpp>
#include <TrafficCounters.hpp>

class App {
public:
    using Ptr = std::shared_ptr<App>;
    using Uid = uint32_t;
    using NamesVec = std::vector<std::string>;

private:
    using DomStatsMap = std::unordered_map<Domain::Ptr, DomainStats>;
    using PrintFun = std::function<void(App &app)>;

public:
    struct BlockedWithSource {
        bool blocked = false;
        Stats::Color color = Stats::GREY;
        DomainPolicySource policySource = DomainPolicySource::MASK_FALLBACK;
    };

private:
    Saver _saver;
    mutable std::shared_mutex _mutexMeta; // protects _saver/_name/_names during anonymous->named upgrade

    const Uid _uid;
    std::string _name;       // Non-const to allow anonymous→named upgrade
    NamesVec _names;         // Non-const to allow anonymous→named upgrade
    // Immutable snapshot of name for lock-free reads in high-volume streaming code paths.
    std::shared_ptr<const std::string> _nameSnap;
    std::atomic_bool _saved = false;
    AppStats _stats;
    std::pair<DomStatsMap, std::shared_mutex> _domStats[Stats::nbColors - 1];
    std::atomic_bool _tracked = false;
    std::atomic_uint8_t _blockMask;
    std::atomic_uint8_t _blockIface;
    std::atomic_bool _useCustomList;
    IpRulesCapsCache _ipRulesCaps;

    CustomList _customBlacklist;
    CustomList _customWhitelist;
    CustomRules _blackRules;
    CustomRules _whiteRules;

    DomainPolicySourcesCounters _domainSourcesCounters;
    TrafficCounters _trafficCounters;

public:
    App(const Uid uid, const NamesVec &names = NamesVec());

    App(const Uid uid, const std::string &name);

    App(const App &) = delete;

    std::string name() const {
        const std::shared_lock<std::shared_mutex> lock(_mutexMeta);
        return _name;
    }

    // Lock-free snapshot; prefer for packet/DNS streaming output to avoid per-item string copies.
    std::shared_ptr<const std::string> nameSnapshot() const {
        return std::atomic_load_explicit(&_nameSnap, std::memory_order_acquire);
    }

    NamesVec names() const {
        const std::shared_lock<std::shared_mutex> lock(_mutexMeta);
        return _names;
    }

    // Returns true if this app has an anonymous name (e.g., "system_12345")
    bool isAnonymous() const;

    // Upgrade from anonymous to named app - only succeeds if currently anonymous
    // Returns true if upgrade was performed, false if already named
    // Also handles save file rename for persistence
    bool upgradeName(const std::string &newName);
    bool upgradeName(const NamesVec &newNames);

    Uid uid() const { return _uid; }

    Uid userId() const { return _uid / 100000; }

    Uid appId() const { return _uid % 100000; }

    uint8_t blockMask() const { return _blockMask; }

    void blockMask(const uint8_t blockMask) {
        _saved = false;
        _blockMask = Settings::normalizeAppBlockMask(blockMask);
    }

    uint8_t blockIface() const { return _blockIface; }

    void blockIface(const uint8_t blockIface) {
        _saved = false;
        _blockIface = blockIface;
    }

    bool tracked() const { return _tracked; }

    void tracked(const bool tracked) {
        _saved = false;
        _tracked = tracked;
    }

    void useCustomList(const bool useCustomList) {
        _saved = false;
        _useCustomList = useCustomList;
    }

    bool useCustomList() const { return _useCustomList; }

    // Hot-path helper: cached per-UID IPRULES capability gates (amortized by rulesEpoch).
    //
    // Returns std::nullopt if cache is stale for the provided rulesEpoch.
    std::optional<bool> ipRulesUsesCtIfFresh(const std::uint64_t rulesEpoch) const noexcept {
        return _ipRulesCaps.usesCtIfFresh(rulesEpoch);
    }

    void setIpRulesUsesCtCache(const std::uint64_t rulesEpoch, const bool usesCt) noexcept {
        _ipRulesCaps.setUsesCt(rulesEpoch, usesCt);
    }

    bool hasData(const Stats::View view);

    bool hasData(const Stats::Color cs, const Stats::View view);

    const std::pair<bool, Stats::Color> blocked(const Domain::Ptr &domain);

    BlockedWithSource blockedWithSource(const Domain::Ptr &domain);

    void observeDomainPolicySource(const DomainPolicySource source, const bool blocked) noexcept {
        _domainSourcesCounters.observe(source, blocked);
    }

    void resetDomainPolicySources() noexcept { _domainSourcesCounters.reset(); }

    DomainPolicySourcesSnapshot domainPolicySourcesSnapshot() const noexcept {
        return _domainSourcesCounters.snapshot();
    }

    void observeTrafficDns(const bool blocked) noexcept { _trafficCounters.observeDns(blocked); }

    void observeTrafficPacket(const bool input, const bool accepted, const std::uint64_t bytes) noexcept {
        _trafficCounters.observePacket(input, accepted, bytes);
    }

    void resetTraffic() noexcept { _trafficCounters.reset(); }

    TrafficSnapshot trafficSnapshot() const noexcept { return _trafficCounters.snapshot(); }

    void updateStats(const Domain::Ptr &domain, const Stats::Type ts, const Stats::Color cs,
                     const Stats::Block bs, const uint64_t val);

    void addCustomDomain(const std::string &name, const Stats::Color color);

    void removeCustomDomain(const std::string &name, const Stats::Color color);

    void printCustomDomains(std::ostream &out, const Stats::Color color);

    // Snapshot custom allow/block domains. Order is unspecified (caller may sort if needed).
    std::vector<std::string> snapshotCustomDomains(const Stats::Color color) const;

    void addCustomRule(const Rule::Ptr rule, const bool compile, const Stats::Color color);

    void removeCustomRule(const Rule::Ptr rule, const bool compile, const Stats::Color color);

    // Snapshot custom allow/block ruleIds. Order is unspecified (caller may sort if needed).
    std::vector<Rule::Id> snapshotCustomRuleIds(const Stats::Color color) const;

    void buildCustomRules(const Stats::Color color);

    void printCustomRules(std::ostream &out, const Stats::Color color);

    void reset(const Stats::View vs);

    void save();

    void restore(const App::Ptr &app);

    void removeFile();

    void print(std::ostream &out);

    template <class... Args> void printAppStats(std::ostream &out, const Args... args);

    template <class... Args> void printAppNotif(std::ostream &out);

    template <class... Args> void printDomainStats(std::ostream &out, const Args... args);

    template <class... TypeStats>
    void printDomains(std::ostream &out, const Stats::Color cs, const Stats::View view,
                      const TypeStats... ts);

    void printCustomLists(std::ostream &out);

    void migrateV4V5(AppStats &globStats);

private:
    CustomList &customList(const Stats::Color color) {
        return color == Stats::BLACK ? _customBlacklist : _customWhitelist;
    }

    const CustomList &customList(const Stats::Color color) const {
        return color == Stats::BLACK ? _customBlacklist : _customWhitelist;
    }

    CustomRules &customRules(const Stats::Color color) {
        return color == Stats::BLACK ? _blackRules : _whiteRules;
    }

    const CustomRules &customRules(const Stats::Color color) const {
        return color == Stats::BLACK ? _blackRules : _whiteRules;
    }

    App(const Uid uid, const std::string &name, const NamesVec &names, const std::string &&saveFile,
        const std::uint8_t blockMask, const std::uint8_t blockIface, const bool useCustomList);

    DomStatsMap &domStats(const size_t cs) { return _domStats[cs - 1].first; }

    std::shared_mutex &mutex(const Stats::Color cs) { return _domStats[cs - 1].second; }

    void print(std::ostream &out, const PrintFun &&print);
};

template <class... Args> void App::printAppStats(std::ostream &out, const Args... args) {
    print(out, [&](App &app) {
        out << "," << JSF("stats");
        app._stats.print(out, args...);
    });
}

template <class... Args> void App::printAppNotif(std::ostream &out) {
    print(out, [&](App &app) {
        out << "," << JSF("stats");
        app._stats.print(out);
    });
}

template <class... Args> void App::printDomainStats(std::ostream &out, const Args... args) {
    print(out, [&](App &app) {
        out << "," << JSF("domains");
        app.printDomains(out, args...);
    });
}

template <class... TypeStats>
void App::printDomains(std::ostream &out, const Stats::Color cs, const Stats::View view,
                       const TypeStats... ts) {
    out << "[";
    bool first = true;
    // Hold read lock for the full traversal to prevent iterator invalidation while iterating.
    const std::shared_lock<std::shared_mutex> lock(mutex(cs));
    auto &map = domStats(cs);
    for (auto &[domain, stats] : map) {
        if (stats.hasData(view)) {
            when(first, out << ",");
            domain->print(out, stats, view, ts...);
        }
    }
    out << "]";
}

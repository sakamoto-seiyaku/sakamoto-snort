/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sstream>
#include <RulesManager.hpp>
#include <Settings.hpp>
#include <App.hpp>
#include <Settings.hpp>

App::App(const Uid uid, const NamesVec &names)
    : App(uid, settings.systemAppPrefix + std::to_string(uid), names,
          settings.saveDirSystem + std::to_string(uid),
          settings.standardListBit + settings.customListBit, 0, true) {}

App::App(const Uid uid, const std::string &name)
    : App(uid, name, NamesVec(), settings.saveDirPackages + name, settings.blockMask(),
          settings.blockIface(), settings.blockMask() & settings.customListBit) {}

App::App(const Uid uid, const std::string &name, const NamesVec &names,
         const std::string &&saveFile, const std::uint8_t blockMask, const std::uint8_t blockIface,
         const bool useCustomList)
    : _saver(saveFile)
    , _uid(uid)
    , _name(name)
    , _names(names)
    , _blockMask(blockMask)
    , _blockIface(blockIface)
    , _useCustomList(useCustomList) {}

bool App::hasData(const Stats::View view) { return _stats.hasData(view); }

bool App::hasData(const Stats::Color cs, const Stats::View view) {
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

void App::updateStats(const Domain::Ptr &domain, const Stats::Type ts, const Stats::Color cs,
                      const Stats::Block bs, const uint64_t val) {
    _saved = false;
    _stats.update(ts, cs, bs, val);
    domain->updateStats(ts, bs, val);
    auto &ds = domStats(cs);
    {
        const std::shared_lock_guard lock(mutex(cs));
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

void App::addCustomRule(const Rule::Ptr rule, const bool compile, const Stats::Color color) {
    _saved = false;
    customRules(color).add(rule, compile);
}

void App::removeCustomRule(const Rule::Ptr rule, const bool compile, const Stats::Color color) {
    _saved = false;
    customRules(color).remove(rule, compile);
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
    _saved = false;
    _saver.remove();
}

void App::save() {
    if (!_saved || !_blackRules.saved() || !_whiteRules.saved()) {
        _saver.save([&] {
            _saver.write<uint8_t>(_blockMask);
            _stats.save(_saver);
            for (auto &[map, mutex] : _domStats) {
                const std::shared_lock_guard lock(mutex);
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
    _saver.restore([&] {
        _blockMask = _saver.read<uint8_t>();
        _stats.restore(_saver);
        for (auto &[map, _] : _domStats) {
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
        _blockIface = _saver.read<uint8_t>();
        rulesManager.restoreCustomRules(_saver, app, Stats::BLACK);
        rulesManager.restoreCustomRules(_saver, app, Stats::WHITE);
    });
}

void App::print(std::ostream &out) {
    print(out, [&](App &app) {
        if (_names.size() > 1) {
            out << "," << JSF("allNames") << "[";
            bool first = true;
            for (const auto &name : _names) {
                when(first, out << ",");
                out << JSS(name);
            }
            out << "]";
        }
    });
}

void App::print(std::ostream &out, const PrintFun &&print) {
    out << "{" << JSF("name") << JSS(_name) << "," << JSF("uid") << _uid << "," << JSF("blocked")
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

/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <csignal>
#include <unistd.h>
#include <thread>

#include <iode-snort.hpp>
#include <Timer.hpp>
#include <Settings.hpp>
#include <DefaultAppsManager.hpp>
#include <PacketListener.hpp>
#include <PackageListener.hpp>
#include <ActivityManager.hpp>
#include <DnsListener.hpp>
#include <RulesManager.hpp>
#include <Control.hpp>
#include <Rule.hpp>
#include <BlockingListManager.hpp>

Settings settings;
DefaultAppsManager defAppManager;
RulesManager rulesManager;
DomainManager domManager;
BlockingListManager blockingListManager;
AppManager appManager;
HostManager hostManager;
PackageListener pkgListener;
ActivityManager activityManager;
DnsListener dnsListener;
PacketManager pktManager;
PacketListener<IPv4> pktListener4;
PacketListener<IPv6> pktListener6;
Control control;

std::shared_mutex mutexListeners;

static void snort();

int main() {
    try {
        snort();
    } catch (const std::runtime_error &e) {
        LOG(ERROR) << "Fatal Exception: " << e.what();
        return EXIT_FAILURE;
    }
}

static void snort() {
    Timer::set("total", "Total time");
    settings.start();
    {
        const std::lock_guard lock(mutexListeners);
        Timer::set("defapps", "Default apps init time");
        defAppManager.start();
        Timer::get("defapps");
        std::thread threads[]{std::thread([&] {
                                  Timer::set("packages", "Packages init time");
                                  pkgListener.start();
                                  Timer::get("packages");
                                  Timer::set("restore", "Data restoration time");
                                  blockingListManager.restore();
                                  rulesManager.restore();
                                  domManager.restore();
                                  appManager.restore();
                                  dnsListener.restore();
                                  Timer::get("restore");
                              }),
                              std::thread([&] {
                                  Timer::set("lists", "Domain lists init time");
                                  domManager.start(blockingListManager.getLists());
                                  Timer::get("lists");
                              }),
                              std::thread([&] {
                                  Timer::set("dns", "DNS listener init time");
                                  dnsListener.start();
                                  Timer::get("dns");
                              }),
                              std::thread([&] {
                                  Timer::set("iptables", "Iptables (ipv4) init time");
                                  pktListener4.start();
                                  Timer::get("iptables");
                              }),
                              std::thread([&] {
                                  Timer::set("ip6tables", "Iptables (ipv6) init time");
                                  pktListener6.start();
                                  Timer::get("ip6tables");
                              }),
                              std::thread([&] {
                                  Timer::set("control", "Control init time");
                                  control.start();
                                  Timer::get("control");
                              })};
        for (auto &thread : threads) {
            thread.join();
        }
        domManager.fixDomainsColors();
        if (settings.savedVersion() < 7) {
            appManager.migrateV4V5();
        }
    }

    Timer::get("total", "Total init time");
    const auto quit = [](int signal) {
        const std::lock_guard lock(mutexListeners);
        snortSave(true);
    };
    std::signal(SIGINT, quit);
    std::signal(SIGTERM, quit);
    std::signal(SIGPIPE, SIG_IGN);

    // rulesManager.add(Rule::REGEX, ".*google.*");
    // rulesManager.addCustom(0, Stats::BLACK);
    // rulesManager.add(Rule::WILDCARD, "*google.fr");
    // rulesManager.addCustom(1, Stats::WHITE);

    // domManager.addRule(Rule::WILDCARD, "*google.fr", Stats::WHITE);
    // domManager.addRule(Rule::REGEX, ".*\\.facebook.com", Stats::BLACK);
    // domManager.addRule(Rule::REGEX, ".*.facebook.fr", Stats::BLACK);

    for (;;) {
        {
            const std::lock_guard lock(mutexListeners);
            snortSave();
        }
        std::this_thread::sleep_for(settings.saveInterval);
    }
}

void snortSave(bool quit) {
    Timer::set("save", "Data backup time");
    settings.save();
    blockingListManager.save();
    rulesManager.save();
    domManager.save();
    appManager.save();
    dnsListener.save();
    Timer::get("save");
    if (quit) {
        std::exit(EXIT_SUCCESS);
    }
}

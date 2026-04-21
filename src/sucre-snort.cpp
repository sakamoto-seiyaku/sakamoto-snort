/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <csignal>
#include <unistd.h>
#include <thread>
#include <mutex>

#include <sucre-snort.hpp>
#include <Timer.hpp>
#include <Settings.hpp>
#include <PerfMetrics.hpp>
#include <PacketListener.hpp>
#include <PackageListener.hpp>
#include <ActivityManager.hpp>
#include <DnsListener.hpp>
#include <RulesManager.hpp>
#include <Control.hpp>
#include <ControlVNext.hpp>
#include <Rule.hpp>
#include <BlockingListManager.hpp>

Settings settings;
RulesManager rulesManager;
DomainManager domManager;
BlockingListManager blockingListManager;
AppManager appManager;
HostManager hostManager;
PackageListener pkgListener;
ActivityManager activityManager;
DnsListener dnsListener;
PacketManager pktManager;
PerfMetrics perfMetrics;
PacketListener<IPv4> pktListener4;
PacketListener<IPv6> pktListener6;
Control control;
ControlVNext controlVNext;

std::shared_mutex mutexListeners;

// Fix #12: use an async-signal-safe handler that only sets a flag
static volatile sig_atomic_t g_quit_flag = 0;
static void on_term_signal(int) { g_quit_flag = 1; }

// snortSave() can be called from multiple threads (periodic loop, RESETALL). Guard the
// full save pipeline to avoid concurrent Saver tmp/rename races and module data races.
static std::mutex g_snortSaveMutex;

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
                                  pktManager.restore();
                                  Timer::get("restore");
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
                              }),
                              std::thread([&] {
                                  Timer::set("control-vnext", "Control vNext init time");
                                  controlVNext.start();
                                  Timer::get("control-vnext");
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
    // Prime interface snapshot once to avoid cold-miss refresh on the hot path.
    pktManager.refreshIfacesOnce();
    std::signal(SIGINT, on_term_signal);
    std::signal(SIGTERM, on_term_signal);
    std::signal(SIGPIPE, SIG_IGN);

    // rulesManager.add(Rule::REGEX, ".*google.*");
    // rulesManager.addCustom(0, Stats::BLACK);
    // rulesManager.add(Rule::WILDCARD, "*google.fr");
    // rulesManager.addCustom(1, Stats::WHITE);

    // domManager.addRule(Rule::WILDCARD, "*google.fr", Stats::WHITE);
    // domManager.addRule(Rule::REGEX, ".*\\.facebook.com", Stats::BLACK);
    // domManager.addRule(Rule::REGEX, ".*.facebook.fr", Stats::BLACK);

    for (;;) {
        // Periodic save no longer freezes the world with a global lock. Each module's save()
        // is internally synchronized; cross-module snapshot consistency is eventual and sufficient.
        if (g_quit_flag) {
            snortSave(true); // will std::exit
        } else {
            snortSave();
        }
        // Very low frequency passive refresh (best-effort); does not block hot path.
        pktManager.refreshIfacesPassive();
        if (g_quit_flag) {
            // In case snortSave(true) returns (shouldn't), break to stop loop.
            break;
        }
        std::this_thread::sleep_for(settings.saveInterval);
    }
}

void snortSave(bool quit) {
    const std::lock_guard<std::mutex> lock(g_snortSaveMutex);
    Timer::set("save", "Data backup time");
    settings.save();
    blockingListManager.save();
    rulesManager.save();
    domManager.save();
    appManager.save();
    dnsListener.save();
    pktManager.save();
    Timer::get("save");
    if (quit) {
        std::exit(EXIT_SUCCESS);
    }
}

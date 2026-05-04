/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sys/socket.h>
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
#include <ControlVNextStreamManager.hpp>
#include <FlowTelemetry.hpp>
#include <PolicyCheckpoint.hpp>
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
FlowTelemetry flowTelemetry;

static std::mutex g_snortSaveResetMutex;

static void snort();
static void snortSaveLocked();

int main() {
    snortConfigureProcessSignals();
    try {
        snort();
    } catch (const std::runtime_error &e) {
        LOG(ERROR) << "Fatal Exception: " << e.what();
        return EXIT_FAILURE;
    }
}

static void snort() {
    snortStartSignalWaiter();
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
        snortSave();
        // Very low frequency passive refresh (best-effort); does not block hot path.
        pktManager.refreshIfacesPassive();
        if (snortShutdownRequested()) {
            break;
        }
        if (snortWaitForShutdownFor(
                std::chrono::duration_cast<std::chrono::milliseconds>(settings.saveInterval))) {
            break;
        }
    }
    snortSave();
}

void snortSave(bool quit) {
    if (quit) {
        snortRequestShutdown();
        return;
    }
    const std::lock_guard<std::mutex> lock(g_snortSaveResetMutex);
    snortSaveLocked();
}

std::uint32_t snortExportTelemetryDisabledEnds() noexcept {
    return pktManager.exportTelemetryDisabledEnds();
}

void snortResetAll() {
    const std::lock_guard<std::mutex> saveResetLock(g_snortSaveResetMutex);
    const std::lock_guard<std::mutex> controlMutationLock(mutexControlMutations);
    const std::lock_guard listenersLock(mutexListeners);

    snortBeginResetEpoch();
    controlVNextStream.resetAll();
    (void)pktManager.exportTelemetryDisabledEnds();
    flowTelemetry.resetAll();
    (void)::unlink(settings.saveDnsStream.c_str());

    perfMetrics.resetAll();
    settings.reset();
    Settings::clearSaveTreeForResetAll();
    appManager.reset();
    activityManager.reset();
    domManager.reset();
    blockingListManager.reset();
    rulesManager.reset();
    pktManager.reset();
    hostManager.reset();
    dnsListener.reset();
    pkgListener.reset();
    snortSaveLocked();
    snortEndResetEpoch();
}

PolicyCheckpoint::Status snortCheckpointSave(const std::uint32_t slot,
                                             PolicyCheckpoint::SlotMetadata &metadata) {
    const std::lock_guard<std::mutex> saveResetLock(g_snortSaveResetMutex);
    const std::lock_guard<std::mutex> controlMutationLock(mutexControlMutations);
    return PolicyCheckpoint::saveCurrentPolicyToSlot(slot, metadata);
}

PolicyCheckpoint::Status snortCheckpointClear(const std::uint32_t slot,
                                              PolicyCheckpoint::SlotMetadata &metadata) {
    const std::lock_guard<std::mutex> saveResetLock(g_snortSaveResetMutex);
    const std::lock_guard<std::mutex> controlMutationLock(mutexControlMutations);
    return PolicyCheckpoint::clearSlot(slot, metadata);
}

PolicyCheckpoint::Status snortCheckpointRestore(const std::uint32_t slot,
                                                PolicyCheckpoint::SlotMetadata &metadata) {
    const std::lock_guard<std::mutex> saveResetLock(g_snortSaveResetMutex);
    const std::lock_guard<std::mutex> controlMutationLock(mutexControlMutations);

    PolicyCheckpoint::Bundle bundle;
    if (auto st = PolicyCheckpoint::readSlot(slot, bundle, metadata); !st.ok) {
        return st;
    }
    PolicyCheckpoint::RestoreStaging staging;
    if (auto st = PolicyCheckpoint::stageBundleForRestore(bundle, staging); !st.ok) {
        return st;
    }

    const std::lock_guard listenersLock(mutexListeners);

    struct ResetEpochGuard {
        ResetEpochGuard() { snortBeginResetEpoch(); }
        ~ResetEpochGuard() { snortEndResetEpoch(); }
    } resetEpochGuard;

    if (auto st = PolicyCheckpoint::restoreBundleToLivePolicy(bundle, staging); !st.ok) {
        return st;
    }

    controlVNextStream.resetAll();
    (void)pktManager.exportTelemetryDisabledEnds();
    flowTelemetry.resetAll();
    (void)::unlink(settings.saveDnsStream.c_str());

    perfMetrics.reset();
    appManager.resetCheckpointRuntimeMetrics();
    domManager.resetDomainPolicySources();
    domManager.resetRuntimeAssociationsForCheckpoint();
    rulesManager.resetRuleHits();
    pktManager.resetCheckpointRuntimeEpoch();
    hostManager.reset();
    dnsListener.reset();
    snortSaveLocked();
    return PolicyCheckpoint::Status{.ok = true};
}

static void snortSaveLocked() {
    Timer::set("save", "Data backup time");
    settings.save();
    blockingListManager.save();
    rulesManager.save();
    domManager.save();
    appManager.save();
    dnsListener.save();
    pktManager.save();
    Timer::get("save");
}

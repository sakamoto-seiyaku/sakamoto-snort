/*
 * Copyright 2019 - 2022, iodé Technologies
 *
 * This file is part of the iode-snort project.
 *
 * iode-snort is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * iode-snort is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with iode-snort. If not, see <https://www.gnu.org/licenses/>.
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
#include <DnsListener.hpp>
#include <Control.hpp>

Settings settings;
DefaultAppsManager defAppManager;
DomainManager domManager;
AppManager appManager;
HostManager hostManager;
PackageListener pkgListener;
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
    } catch (std::runtime_error e) {
        LOG(ERROR) << "Fatal Exception: " << e.what();
        return EXIT_FAILURE;
    }
}

static void snort() {
    Timer::set("total", "Total time");
    settings.start();
    {
        const std::lock_guard lock(mutexListeners);
        std::thread threads[]{std::thread([&] {
                                  Timer::set("lists", "Domain lists init time");
                                  domManager.start();
                                  Timer::get("lists");
                              }),
                              std::thread([&] {
                                  Timer::set("packages", "Packages init time");
                                  pkgListener.start();
                                  Timer::get("packages");
                                  Timer::set("restore", "Data restoration time");
                                  domManager.restore();
                                  appManager.restore();
                                  dnsListener.restore();
                                  Timer::get("restore");
                              }),
                              std::thread([&] {
                                  Timer::set("defapps", "Default apps init time");
                                  defAppManager.start();
                                  Timer::get("defapps");
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
    }

    Timer::get("total", "Total init time");
    const auto quit = [](int signal) {
        const std::lock_guard lock(mutexListeners);
        snortSave(true);
    };
    std::signal(SIGINT, quit);
    std::signal(SIGTERM, quit);
    std::signal(SIGPIPE, SIG_IGN);

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
    domManager.save();
    appManager.save();
    dnsListener.save();
    Timer::get("save");
    if (quit) {
        std::exit(EXIT_SUCCESS);
    }
}

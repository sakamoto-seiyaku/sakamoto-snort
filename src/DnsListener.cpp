/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <cutils/sockets.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <thread>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <utility>

#include <DnsListener.hpp>
#include <ControlVNextStreamManager.hpp>
#include <PerfMetrics.hpp>
#include <RulesManager.hpp>

DnsListener::DnsListener()
    : Streamable<DnsRequest>(settings.saveDnsStream) {}

DnsListener::~DnsListener() {}

void DnsListener::start() {
    std::thread([this] {
        try {
            server();
        } catch (const std::exception &e) {
            LOG(FATAL) << "DnsListener server failed: " << e.what();
        } catch (...) {
            LOG(FATAL) << "DnsListener server failed: unknown exception";
        }
    }).detach();
}

void DnsListener::server() {
    int inherited = android_get_control_socket(settings.netdSocketPath);

    // Production path: init.rc provides the RESERVED socket; use inherited FD as-is.
    if (inherited >= 1) {
        if (const int one = 1; setsockopt(inherited, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
            const int err = errno;
            LOG(ERROR) << __FUNCTION__ << " - Socket setsockopt failed: " << std::strerror(err);
            throw std::runtime_error("netd socket setsockopt error");
        }
        if (listen(inherited, settings.controlClients) == -1) {
            const int err = errno;
            LOG(ERROR) << __FUNCTION__ << " - Socket listen failed: " << std::strerror(err);
            throw std::runtime_error("netd socket listen error");
        }
        for (;;) {
            if (const int sockClient = accept(inherited, nullptr, nullptr); sockClient == -1) {
                LOG(ERROR) << __FUNCTION__ << " - dnslistener accept error";
            } else if (auto budget = snortTryAcquireSessionBudget(SnortSessionBudgetKind::Dns);
                       !budget) {
                LOG(WARNING) << __FUNCTION__ << " - DNS client budget exhausted";
                close(sockClient);
            } else {
                std::thread([this, sockClient, budget = std::move(budget)]() mutable {
                    clientRun(sockClient);
                }).detach();
            }
        }
    }

    // DEV fallback: create both filesystem and abstract sockets to maximize compatibility.
    const std::string socketPath = "/dev/socket/sucre-snort-netd";
    LOG(INFO) << __FUNCTION__
              << " - Netd socket not inherited from init, creating fallback at "
              << socketPath << " and @sucre-snort-netd";

    // 1) Filesystem namespace: /dev/socket/sucre-snort-netd
    unlink(socketPath.c_str());
    int devSocket = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (devSocket < 0) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__ << " - Failed to create /dev fallback socket: " << std::strerror(err);
        throw std::runtime_error("netd socket control error: failed to create /dev fallback socket");
    }
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);
    if (bind(devSocket, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__ << " - Failed to bind /dev fallback socket: " << std::strerror(err);
        close(devSocket);
        throw std::runtime_error("netd socket control error: failed to bind /dev fallback socket");
    }
    // DEV: Relax permissions so non-root clients (e.g. DnsResolver) can connect.
    if (chmod(socketPath.c_str(), 0666) < 0) {
        const int err = errno;
        LOG(WARNING) << __FUNCTION__ << " - Failed to set /dev netd socket permissions: " << std::strerror(err);
        // Continue anyway; abstract socket below may still provide connectivity.
    }
    if (const int one = 1; setsockopt(devSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__ << " - /dev socket setsockopt failed: " << std::strerror(err);
        close(devSocket);
        throw std::runtime_error("netd socket setsockopt error");
    }

    // 2) Abstract namespace: @sucre-snort-netd (no filesystem permission issues)
    int abstractSocket = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (abstractSocket < 0) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__ << " - Failed to create abstract fallback socket: " << std::strerror(err);
        close(devSocket);
        throw std::runtime_error("netd socket control error: failed to create abstract fallback socket");
    }
    sockaddr_un addrAbstract{};
    addrAbstract.sun_family = AF_UNIX;
    addrAbstract.sun_path[0] = '\0';
    // Name = settings.netdSocketPath ("sucre-snort-netd") at offset 1
    strncpy(addrAbstract.sun_path + 1, settings.netdSocketPath, sizeof(addrAbstract.sun_path) - 1);
    const size_t nameLen = strnlen(settings.netdSocketPath, sizeof(addrAbstract.sun_path) - 1);
    const socklen_t addrLen = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + nameLen);
    if (bind(abstractSocket, reinterpret_cast<const sockaddr*>(&addrAbstract), addrLen) < 0) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__ << " - Failed to bind abstract fallback socket: " << std::strerror(err);
        close(devSocket);
        close(abstractSocket);
        throw std::runtime_error("netd socket control error: failed to bind abstract fallback socket");
    }
    if (const int one = 1; setsockopt(abstractSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__ << " - abstract socket setsockopt failed: " << std::strerror(err);
        close(devSocket);
        close(abstractSocket);
        throw std::runtime_error("netd socket setsockopt error");
    }

    if (listen(devSocket, settings.controlClients) == -1) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__ << " - /dev socket listen failed: " << std::strerror(err);
        close(devSocket);
        close(abstractSocket);
        throw std::runtime_error("netd socket listen error");
    }
    if (listen(abstractSocket, settings.controlClients) == -1) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__ << __FUNCTION__ << " - abstract socket listen failed: " << std::strerror(err);
        close(devSocket);
        close(abstractSocket);
        throw std::runtime_error("netd socket listen error");
    }

    LOG(INFO) << __FUNCTION__ << " - Fallback netd sockets created on FDs " << devSocket
              << " (/dev) and " << abstractSocket << " (@abstract)";

    // Accept on abstract in a helper thread; main thread serves the /dev socket.
    std::thread([this, abstractSocket] {
        for (;;) {
            if (const int sockClient = accept(abstractSocket, nullptr, nullptr); sockClient == -1) {
                LOG(ERROR) << __FUNCTION__ << " - dnslistener abstract accept error";
            } else if (auto budget = snortTryAcquireSessionBudget(SnortSessionBudgetKind::Dns);
                       !budget) {
                LOG(WARNING) << __FUNCTION__ << " - DNS client budget exhausted";
                close(sockClient);
            } else {
                std::thread([this, sockClient, budget = std::move(budget)]() mutable {
                    clientRun(sockClient);
                }).detach();
            }
        }
    }).detach();

    for (;;) {
        if (const int sockClient = accept(devSocket, nullptr, nullptr); sockClient == -1) {
            LOG(ERROR) << __FUNCTION__ << " - dnslistener accept error";
        } else if (auto budget = snortTryAcquireSessionBudget(SnortSessionBudgetKind::Dns); !budget) {
            LOG(WARNING) << __FUNCTION__ << " - DNS client budget exhausted";
            close(sockClient);
        } else {
            std::thread([this, sockClient, budget = std::move(budget)]() mutable {
                clientRun(sockClient);
            }).detach();
        }
    }
}

void DnsListener::clientRun(const int socket) {
    // Never hold the global listeners lock across blocking I/O. We only take it briefly
    // around critical sections that must quiesce during resetall.
    // Soften stuck clients: set a small read timeout to avoid indefinitely hanging threads.
    {
        const timeval tv{.tv_sec = 0, .tv_usec = 250000}; // 250 ms
        (void)setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    try {
        uint32_t len;
        clientRead(socket, &len, sizeof(len), "len read error");
        if (len < 3 || len > HOST_NAME_MAX) {
            throw "domain name invalid";
        }
        // Avoid VLA; read into std::string buffer and trim optional NUL terminator
        std::string host;
        host.resize(len);
        clientRead(socket, host.data(), len, "domain read error");
        if (!host.empty() && host.back() == '\0') {
            host.pop_back();
        }
        App::Uid uid;
        clientRead(socket, &uid, sizeof(uid), "uid read error");

        const bool measure = perfMetrics.enabled();
        uint64_t startUs = 0;
        if (measure) {
            startUs = PerfMetrics::nowUs();
        }

        // Decision must observe a consistent snapshot vs resetall. Keep the lock window tiny.
        bool blocked = false;
        Stats::Color cs = Stats::GREY;
        bool verdict = true;
        bool getips = false;
        DomainPolicySource policySource = DomainPolicySource::MASK_FALLBACK;
        bool useCustomList = false;
        uint32_t domMask = 0;
        uint32_t appMask = 0;
        App::Ptr app;
        Domain::Ptr domain;
        std::uint64_t resetEpoch = 0;
        std::optional<std::uint32_t> ruleId;

        for (;;) {
            resetEpoch = snortResetEpoch();
            if (!snortResetEpochIsStable(resetEpoch)) {
                const std::shared_lock<std::shared_mutex> g(mutexListeners);
                continue;
            }

            const auto foundApp = appManager.find(uid);
            const auto preparedApp = foundApp ? App::Ptr{} : appManager.prepare(uid);

            const std::shared_lock<std::shared_mutex> g(mutexListeners);
            if (!snortResetEpochStillCurrent(resetEpoch)) {
                continue;
            }

            app = appManager.publishPrepared(uid, preparedApp);
            if (!app) {
                continue;
            }
            domain = domManager.make(std::string(host));

            if (settings.blockEnabled() && app->tracked()) {
                const auto bcsr = app->blockedWithSourceAndRuleId(domain);
                blocked = bcsr.blocked;
                cs = bcsr.color;
                policySource = bcsr.policySource;
                ruleId = bcsr.ruleId;
            } else {
                const auto bcs = app->blockedWithSource(domain);
                blocked = bcs.blocked;
                cs = bcs.color;
                policySource = bcs.policySource;
                ruleId.reset();
            }
            verdict = !blocked;
            getips = verdict || settings.getBlackIPs();
            useCustomList = app->useCustomList();
            domMask = static_cast<uint32_t>(domain->blockMask());
            appMask = static_cast<uint32_t>(app->blockMask());

            if (settings.blockEnabled()) {
                // B-layer counters: DNS-request-based DomainPolicy attribution.
                domManager.observeDomainPolicySource(policySource, blocked);
                app->observeDomainPolicySource(policySource, blocked);
                app->observeTrafficDns(blocked);
            }

            if (settings.blockEnabled()) {
                if (app->tracked()) {
                    if (ruleId.has_value()) {
                        if (const auto rule = rulesManager.findThreadSafe(*ruleId); rule != nullptr) {
                            blocked ? rule->observeBlockHit() : rule->observeAllowHit();
                        }
                    }
                    timespec ts{};
                    timespec_get(&ts, TIME_UTC);
                    ControlVNextStreamManager::DnsEvent ev{
                        .timestamp = ts,
                        .uid = app->uid(),
                        .userId = app->userId(),
                        .app = app->nameSnapshot(),
                        .domain = domain,
                        .domMask = domMask,
                        .appMask = appMask,
                        .blocked = blocked,
                        .getips = getips,
                        .useCustomList = useCustomList,
                        .policySource = policySource,
                        .ruleId = ruleId,
                    };
                    controlVNextStream.observeDnsTracked(std::move(ev));
                } else {
                    controlVNextStream.observeDnsSuppressed(blocked);
                }
            }
            break;
        }
        clientWrite(socket, &verdict, sizeof(verdict), "verdict write error");
        clientWrite(socket, &getips, sizeof(getips), "getips write error");

        if (measure) {
            const uint64_t endUs = PerfMetrics::nowUs();
            perfMetrics.observeDnsDecisionUs(endUs - startUs);
        }

        if (getips) {
            {
                const std::shared_lock<std::shared_mutex> g(mutexListeners);
                if (snortResetEpochStillCurrent(resetEpoch)) {
                    domManager.removeIPs(domain);
                }
            }
            int family = -1;
            do {
                clientRead(socket, &family, sizeof(family), "family read error");
                if (family == AF_INET) {
                    Address<IPv4> ip([=](uint8_t *address, const uint32_t l) {
                        clientRead(socket, address, l, "ip read error");
                    });
                    const std::shared_lock<std::shared_mutex> g(mutexListeners);
                    if (snortResetEpochStillCurrent(resetEpoch)) {
                        domManager.addIPBoth(domain, ip);
                    }
                } else if (family == AF_INET6) {
                    Address<IPv6> ip([=](uint8_t *address, const uint32_t l) {
                        clientRead(socket, address, l, "ip read error");
                    });
                    const std::shared_lock<std::shared_mutex> g(mutexListeners);
                    if (snortResetEpochStillCurrent(resetEpoch)) {
                        domManager.addIPBoth(domain, ip);
                    }
                }
            } while (family != -1);
        }
        {
            const std::shared_lock<std::shared_mutex> g(mutexListeners);
            if (snortResetEpochStillCurrent(resetEpoch) && settings.blockEnabled() &&
                app->tracked()) {
                appManager.updateStats(domain, app, blocked, cs, Stats::DNS, 1);
                stream(std::make_shared<DnsRequest>(app, domain, cs, blocked));
            }
        }
    } catch (const char *error) {
        LOG(ERROR) << __FUNCTION__ << " - " << error;
    } catch (const std::exception &e) {
        LOG(ERROR) << __FUNCTION__ << " - dnslistener client exception: " << e.what();
    } catch (...) {
        LOG(ERROR) << __FUNCTION__ << " - dnslistener client exception: unknown";
    }
    close(socket);
}

template <class IP> void DnsListener::readIP(const int socket, const Domain::Ptr &domain) {
    // Unused after refactor; kept for ABI compatibility if needed. The new code reads the IP
    // without holding the global lock, then publishes under a tiny lock in clientRun.
    Address<IP> ip([=](uint8_t *address, const uint32_t len) {
        clientRead(socket, address, len, "ip read error");
    });
    const std::shared_lock<std::shared_mutex> g(mutexListeners);
    domManager.addIPBoth(domain, ip);
}

void DnsListener::clientRead(const int socket, void *data, const uint32_t len, const char *error) {
    if (read(socket, data, len) != static_cast<ssize_t>(len)) {
        throw error;
    }
}

void DnsListener::clientWrite(const int socket, const void *data, const uint32_t len,
                              const char *error) {
    if (!snortWriteAllWithDeadline(socket, data, len, snortDnsSendDeadline)) {
        throw error;
    }
}

void DnsListener::save() { Streamable<DnsRequest>::save(); }

void DnsListener::restore() { Streamable<DnsRequest>::restore(); }

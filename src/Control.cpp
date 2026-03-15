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
#include <arpa/inet.h>
#include <net/if.h>
#include <thread>
#include <vector>
#include <charconv>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <fstream>
#include <optional>
#include <system_error>
#include <sucre-snort.hpp>
#include <PackageListener.hpp>
#include <ActivityManager.hpp>
#include <DnsListener.hpp>
#include <HostManager.hpp>
#include <PacketManager.hpp>
#include <RulesManager.hpp>
#include <Settings.hpp>
#include <Rule.hpp>
#include <Control.hpp>
#include <PerfMetrics.hpp>
#include <BlockingListManager.hpp>
#include <BlockingList.hpp>

struct {
    std::string s;
    Stats::View v;
} views[Stats::nbViews]{{".0", Stats::DAY0}, {".1", Stats::DAY1}, {".2", Stats::DAY2},
                        {".3", Stats::DAY3}, {".4", Stats::DAY4}, {".5", Stats::DAY5},
                        {".6", Stats::DAY6}, {".W", Stats::WEEK}, {".A", Stats::ALL}};

struct {
    std::string s;
    Stats::Type t;
} types[Stats::nbTypes]{{"DNS", Stats::DNS},
                        {"RXP", Stats::RXP},
                        {"RXB", Stats::RXB},
                        {"TXP", Stats::TXP},
                        {"TXB", Stats::TXB}};

struct {
    std::string s;
    Stats::Color c;
} colors[Stats::nbColors - 1]{
    {"BLACK", Stats::BLACK}, {"WHITE", Stats::WHITE}, {"GREY", Stats::GREY}};

template <class Fun, class... Args>
Control::CmdFun Control::make(const Fun &&fun, const Args... fargs) {
    return std::bind(fun, this, std::placeholders::_1, fargs...);
}

Control::Control() {
    _cmds.emplace("HELLO", make(&Control::cmdHello));
    _cmds.emplace("HELP", make(&Control::cmdHelp));
    _cmds.emplace("QUIT", make(&Control::cmdQuit));
    _cmds.emplace("DEV.SHUTDOWN", make(&Control::cmdDevShutdown));
    _cmds.emplace("PASSWORD", make(&Control::cmdPassword));
    _cmds.emplace("PASSSTATE", make(&Control::cmdPassState));
    _cmds.emplace("RESETALL", make(&Control::cmdResetAll));
    _cmds.emplace("PERFMETRICS", make(&Control::cmdPerfmetrics));
    _cmds.emplace("METRICS.PERF", make(&Control::cmdMetricsPerf));
    _cmds.emplace("METRICS.PERF.RESET", make(&Control::cmdMetricsPerfReset));
    _cmds.emplace("METRICS.REASONS", make(&Control::cmdMetricsReasons));
    _cmds.emplace("METRICS.REASONS.RESET", make(&Control::cmdMetricsReasonsReset));
    _cmds.emplace("IPRULES", make(&Control::cmdIpRules));
    _cmds.emplace("IPRULES.ADD", make(&Control::cmdIpRulesAdd));
    _cmds.emplace("IPRULES.UPDATE", make(&Control::cmdIpRulesUpdate));
    _cmds.emplace("IPRULES.REMOVE", make(&Control::cmdIpRulesRemove));
    _cmds.emplace("IPRULES.ENABLE", make(&Control::cmdIpRulesEnable));
    _cmds.emplace("IPRULES.PRINT", make(&Control::cmdIpRulesPrint));
    _cmds.emplace("IPRULES.PREFLIGHT", make(&Control::cmdIpRulesPreflight));
    _cmds.emplace("IFACES.PRINT", make(&Control::cmdIfacesPrint));
    _cmds.emplace("APP.NAME", make(&Control::cmdAppsByName));
    _cmds.emplace("APP.UID", make(&Control::cmdAppsByUid));
    _cmds.emplace("APP.CUSTOMLISTS", make(&Control::cmdAppCustomLists));
    _cmds.emplace("BLOCK", make(&Control::cmdBlock));
    _cmds.emplace("BLOCKIPLEAKS", make(&Control::cmdBlockIPLeaks));
    _cmds.emplace("MAXAGEIP", make(&Control::cmdMaxAgeIP));
    _cmds.emplace("GETBLACKIPS", make(&Control::cmdGetBlackIPs));
    _cmds.emplace("BLOCKMASK", make(&Control::cmdBlockMask));
    _cmds.emplace("BLOCKMASKDEF", make(&Control::cmdBlockMaskDef));
    _cmds.emplace("BLOCKIFACE", make(&Control::cmdBlockIface));
    _cmds.emplace("BLOCKIFACEDEF", make(&Control::cmdBlockIfaceDef));
    _cmds.emplace("TRACK", make(&Control::cmdTrack, true));
    _cmds.emplace("UNTRACK", make(&Control::cmdTrack, false));
    _cmds.emplace("RDNS.SET", make(&Control::cmdReverseDnsOn));
    _cmds.emplace("RDNS.UNSET", make(&Control::cmdReverseDnsOff));
    _cmds.emplace("DNSSTREAM.START", make(&Control::cmdStartDnsStream));
    _cmds.emplace("DNSSTREAM.STOP", make(&Control::cmdStopDnsStream));
    _cmds.emplace("PKTSTREAM.START", make(&Control::cmdStartPktStream));
    _cmds.emplace("PKTSTREAM.STOP", make(&Control::cmdStopPktStream));
    _cmds.emplace("ACTIVITYSTREAM.START", make(&Control::cmdStartActivityStream));
    _cmds.emplace("ACTIVITYSTREAM.STOP", make(&Control::cmdStopActivityStream));
    _cmds.emplace("HOSTS", make(&Control::cmdHosts));
    _cmds.emplace("HOSTS.NAME", make(&Control::cmdHostsByName));
    _cmds.emplace("TOPACTIVITY", make(&Control::cmdTopActivity));
    _cmds.emplace("CUSTOMLIST.ON", make(&Control::cmdUseCustomList, true));
    _cmds.emplace("CUSTOMLIST.OFF", make(&Control::cmdUseCustomList, false));
    _cmds.emplace("BLACKLIST.ADD", make(&Control::cmdAddCustomDomain, Stats::BLACK));
    _cmds.emplace("WHITELIST.ADD", make(&Control::cmdAddCustomDomain, Stats::WHITE));
    _cmds.emplace("BLACKLIST.REMOVE", make(&Control::cmdRemoveCustomDomain, Stats::BLACK));
    _cmds.emplace("WHITELIST.REMOVE", make(&Control::cmdRemoveCustomDomain, Stats::WHITE));
    _cmds.emplace("BLACKLIST.PRINT", make(&Control::cmdPrintCustomList, Stats::BLACK));
    _cmds.emplace("WHITELIST.PRINT", make(&Control::cmdPrintCustomList, Stats::WHITE));
    _cmds.emplace("RULES.ADD", make(&Control::cmdAddRule));
    _cmds.emplace("RULES.REMOVE", make(&Control::cmdRemoveRule));
    _cmds.emplace("RULES.UPDATElist", make(&Control::cmdUpdateRule));
    // Backward-compatible alias with normalized name
    _cmds.emplace("RULES.UPDATE", make(&Control::cmdUpdateRule));
    _cmds.emplace("RULES.PRINT", make(&Control::cmdPrintRules));
    _cmds.emplace("BLACKRULES.ADD", make(&Control::cmdAddCustomRule, Stats::BLACK));
    _cmds.emplace("WHITERULES.ADD", make(&Control::cmdAddCustomRule, Stats::WHITE));
    _cmds.emplace("BLACKRULES.REMOVE", make(&Control::cmdRemoveCustomRule, Stats::BLACK));
    _cmds.emplace("WHITERULES.REMOVE", make(&Control::cmdRemoveCustomRule, Stats::WHITE));
    _cmds.emplace("BLACKRULES.PRINT", make(&Control::cmdPrintCustomRules, Stats::BLACK));
    _cmds.emplace("WHITERULES.PRINT", make(&Control::cmdPrintCustomRules, Stats::WHITE));
    _cmds.emplace("BLOCKLIST.BLACK.ADD", make(&Control::cmdAddBlockingList, Stats::BLACK));
    _cmds.emplace("BLOCKLIST.WHITE.ADD", make(&Control::cmdAddBlockingList, Stats::WHITE));
    _cmds.emplace("BLOCKLIST.BLACK.UPDATE", make(&Control::cmdUpdateBlockingList, Stats::BLACK));
    _cmds.emplace("BLOCKLIST.WHITE.UPDATE", make(&Control::cmdUpdateBlockingList, Stats::WHITE));
    _cmds.emplace("BLOCKLIST.BLACK.OUTDATE", make(&Control::cmdOutdateBlockingList, Stats::BLACK));
    _cmds.emplace("BLOCKLIST.WHITE.OUTDATE", make(&Control::cmdOutdateBlockingList, Stats::WHITE));
    _cmds.emplace("BLOCKLIST.BLACK.REMOVE", make(&Control::cmdRemoveBlockingList, Stats::BLACK));
    _cmds.emplace("BLOCKLIST.WHITE.REMOVE", make(&Control::cmdRemoveBlockingList, Stats::WHITE));
    _cmds.emplace("BLOCKLIST.BLACK.ENABLE", make(&Control::cmdEnableBlockingList, Stats::BLACK));
    _cmds.emplace("BLOCKLIST.WHITE.ENABLE", make(&Control::cmdEnableBlockingList, Stats::WHITE));
    _cmds.emplace("BLOCKLIST.BLACK.DISABLE", make(&Control::cmdDisableBlockingList, Stats::BLACK));
    _cmds.emplace("BLOCKLIST.WHITE.DISABLE", make(&Control::cmdDisableBlockingList, Stats::WHITE));
    _cmds.emplace("BLOCKLIST.PRINT", make(&Control::cmdPrintBlockingLists));
    _cmds.emplace("BLOCKLIST.CLEAR", make(&Control::cmdClearBlockingLists));
    _cmds.emplace("BLOCKLIST.SAVE", make(&Control::cmdSaveBlockingLists));
    _cmds.emplace("DOMAIN.BLACK.ADD.MANY", make(&Control::cmdAddManyDomains, Stats::BLACK));
    _cmds.emplace("DOMAIN.WHITE.ADD.MANY", make(&Control::cmdAddManyDomains, Stats::WHITE));
    _cmds.emplace("DOMAIN.BLACK.COUNT", make(&Control::cmdDomainsCount, Stats::BLACK));
    _cmds.emplace("DOMAIN.WHITE.COUNT", make(&Control::cmdDomainsCount, Stats::WHITE));
    _cmds.emplace("DOMAIN.BLACK.PRINT", make(&Control::cmdDomainsPrint, Stats::BLACK));
    _cmds.emplace("DOMAIN.WHITE.PRINT", make(&Control::cmdDomainsPrint, Stats::WHITE));

    for (size_t vs = 0; vs < Stats::nbViews; ++vs) {
        const auto &view = views[vs];
        _cmds.emplace(std::string("ALL") + view.s, make(&Control::cmdStatsTotal<>, view.v));
        _cmds.emplace(std::string("APP") + view.s, make(&Control::cmdStatsApp<>, view.v));
        _cmds.emplace(std::string("APP.RESET") + view.s, make(&Control::cmdResetApp, view.v));
        _cmds.emplace(std::string("DOMAINS") + view.s,
                      make(&Control::cmdBlackDomainsStats, view.v));
        for (size_t ts = 0; ts < Stats::nbTypes; ++ts) {
            const auto &type = types[ts];
            _cmds.emplace(type.s + view.s,
                          make(&Control::cmdStatsTotal<Stats::Type>, view.v, type.t));
            _cmds.emplace(std::string("APP.") + type.s + view.s,
                          make(&Control::cmdStatsApp<Stats::Type>, view.v, type.t));
        }
        for (size_t cs = 0; cs < Stats::nbColors - 1; ++cs) {
            const auto &color = colors[cs];
            _cmds.emplace(color.s + view.s, make(&Control::cmdDomainlist<>, color.c, view.v));
            _cmds.emplace(color.s + ".APP" + view.s,
                          make(&Control::cmdDomainlistApp<>, color.c, view.v));
            for (size_t ts = 0; ts < Stats::nbTypes; ++ts) {
                const auto &type = types[ts];
                _cmds.emplace(color.s + "." + type.s + view.s,
                              make(&Control::cmdDomainlist<Stats::Type>, color.c, view.v, type.t));
                _cmds.emplace(
                    color.s + ".APP." + type.s + view.s,
                    make(&Control::cmdDomainlistApp<Stats::Type>, color.c, view.v, type.t));
            }
        }
    }
}

Control::~Control() {}

void Control::start() {
    std::thread([this] { unixServer(); }).detach();
    if (settings.inetControl()) {
        std::thread([this] { inetServer(); }).detach();
    }
}

void Control::unixServer() {
    int unixSocket = android_get_control_socket(settings.controlSocketPath);

    // Production path: init.rc created the RESERVED socket under /dev/socket/.
    // In that case we simply inherit the FD from init and do not touch any paths,
    // to stay fully compatible with the original KSU module behaviour.
    if (unixSocket >= 1) {
        if (listen(unixSocket, settings.controlClients) == -1) {
            const int err = errno;
            LOG(ERROR) << __FUNCTION__ << " - Socket listen failed: " << std::strerror(err);
            throw std::runtime_error("control unix socket listen error");
        }

        for (;;) {
            if (const int sockClient = accept(unixSocket, nullptr, nullptr); sockClient < 0) {
                LOG(ERROR) << __FUNCTION__ << " - unix socket accept error";
            } else {
                std::thread([this, sockClient] { clientLoop(sockClient); }).detach();
            }
        }
    }

    // Fallback path: running under DEV mode (started via adb / service.sh),
    // no init-created socket is available. To keep full compatibility with:
    //   1) Framework / new clients using /dev/socket/sucre-snort-control (RESERVED)
    //   2) Existing APP builds using the legacy abstract @sucre-snort-control
    // we expose both a filesystem socket and an abstract socket, and route all
    // connections through the same clientLoop() implementation.

    // 1. /dev/socket/sucre-snort-control (filesystem namespace)
    const std::string socketPath = "/dev/socket/sucre-snort-control";
    LOG(INFO) << __FUNCTION__
              << " - Control socket not inherited from init, creating fallback at "
              << socketPath << " and @sucre-snort-control";

    // Clean up any existing socket file left by previous runs.
    unlink(socketPath.c_str());

    int devSocket = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (devSocket < 0) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__
                   << " - Failed to create fallback /dev socket: " << std::strerror(err);
        throw std::runtime_error(
            "control unix socket error: failed to create /dev fallback socket");
    }

    sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(devSocket, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__
                   << " - Failed to bind fallback /dev socket: " << std::strerror(err);
        close(devSocket);
        throw std::runtime_error(
            "control unix socket error: failed to bind /dev fallback socket");
    }

    // Match init.rc: socket sucre-snort-control stream 0666 root root
    if (chmod(socketPath.c_str(), 0666) < 0) {
        const int err = errno;
        LOG(WARNING) << __FUNCTION__
                     << " - Failed to set /dev socket permissions: " << std::strerror(err);
        // Continue anyway, permissions might still work.
    }

    // 2. @sucre-snort-control (abstract namespace)
    // This keeps compatibility with existing APP builds which connect to the
    // abstract address "@sucre-snort-control".
    int abstractSocket = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (abstractSocket < 0) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__
                   << " - Failed to create abstract fallback socket: " << std::strerror(err);
        close(devSocket);
        throw std::runtime_error(
            "control unix socket error: failed to create abstract fallback socket");
    }

    sockaddr_un addrAbstract;
    memset(&addrAbstract, 0, sizeof(addrAbstract));
    addrAbstract.sun_family = AF_UNIX;
    // Abstract namespace: first byte of sun_path is '\0', name starts at offset 1.
    addrAbstract.sun_path[0] = '\0';
    strncpy(addrAbstract.sun_path + 1, settings.controlSocketPath,
            sizeof(addrAbstract.sun_path) - 1);

    // Compute exact sockaddr length for abstract namespace: header + NUL + nameLen
    const size_t nameLen = strnlen(settings.controlSocketPath,
                                   sizeof(addrAbstract.sun_path) - 1);
    const socklen_t addrLen = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + nameLen);
    if (bind(abstractSocket, reinterpret_cast<const sockaddr*>(&addrAbstract), addrLen) < 0) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__
                   << " - Failed to bind abstract fallback socket: " << std::strerror(err);
        close(devSocket);
        close(abstractSocket);
        throw std::runtime_error(
            "control unix socket error: failed to bind abstract fallback socket");
    }

    if (listen(devSocket, settings.controlClients) == -1) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__
                   << " - /dev socket listen failed: " << std::strerror(err);
        close(devSocket);
        close(abstractSocket);
        throw std::runtime_error("control unix socket listen error");
    }

    if (listen(abstractSocket, settings.controlClients) == -1) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__
                   << " - abstract socket listen failed: " << std::strerror(err);
        close(devSocket);
        close(abstractSocket);
        throw std::runtime_error("control unix socket listen error");
    }

    LOG(INFO) << __FUNCTION__ << " - Fallback sockets created successfully on FDs "
              << devSocket << " (/dev) and " << abstractSocket << " (@abstract)";

    // Handle abstract clients in a helper thread so that the main unixServer()
    // thread can continue to serve the /dev socket. Both entry points reuse
    // the same clientLoop() implementation.
    std::thread([this, abstractSocket] {
        for (;;) {
            if (const int sockClient = accept(abstractSocket, nullptr, nullptr);
                sockClient < 0) {
                LOG(ERROR) << __FUNCTION__ << " - unix abstract socket accept error";
            } else {
                std::thread([this, sockClient] { clientLoop(sockClient); }).detach();
            }
        }
    }).detach();

    for (;;) {
        if (const int sockClient = accept(devSocket, nullptr, nullptr); sockClient < 0) {
            LOG(ERROR) << __FUNCTION__ << " - unix socket accept error";
        } else {
            std::thread([this, sockClient] { clientLoop(sockClient); }).detach();
        }
    }
}

void Control::inetServer() {
    int inetSocket = -1;
    sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(settings.controlPort);
    addr.sin_family = AF_INET;

    try {
        if ((inetSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
            throw "inet socket create error";
        }
        if (int reuse = 1;
            setsockopt(inetSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
            throw "inet socket setsockopt failed";
        }
        for (uint32_t i = 0; i < settings.controlBindTrials; ++i) {
            if (bind(inetSocket, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            } else
                goto binded;
        }
        throw "inet socket bind error";
    binded:
        if (listen(inetSocket, settings.controlClients) != 0) {
            throw "inet socket listen error";
        }
        for (;;) {
            if (const int sockClient = accept(inetSocket, nullptr, nullptr); sockClient < 0) {
                throw "inet socket accept error";
            } else {
                std::thread([this, sockClient] { clientLoop(sockClient); }).detach();
            }
        }
    } catch (const char *error) {
        LOG(ERROR) << __FUNCTION__ << " - " << error;
        if (inetSocket >= 0) {
            close(inetSocket);
        }
    }
}

void Control::clientLoop(const int sockClient) const {
    SocketIO::Ptr _sockio = std::make_shared<SocketIO>(sockClient);
    // Reset per-thread state for this client connection.
    quit = false;
    devShutdown = false;
    activeStreams = 0;

    // Apply a receive timeout so that completely idle non-stream clients
    // do not keep a thread and socket forever. 15 minutes is chosen to
    // be well above any realistic interactive use.
    {
        const timeval tv{.tv_sec = 15 * 60, .tv_usec = 0};
        if (setsockopt(sockClient, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            const int err = errno;
            LOG(ERROR) << __FUNCTION__ << " - control socket SO_RCVTIMEO error: "
                       << std::strerror(err);
            // Continue without timeout in this rare case; behavior falls back
            // to the previous infinite-blocking semantics on this connection.
        }
    }

    const auto &resetall = _cmds.find("RESETALL");
    // Avoid large stack buffer: use heap-backed buffer sized from settings.
    std::vector<char> buffer(settings.controlCmdLen);
    const ssize_t maxRead = static_cast<ssize_t>(settings.controlCmdLen) - 1; // reserve 1 for NUL
    for (;;) {
        const ssize_t len = read(sockClient, buffer.data(), maxRead);
        if (len > 0) {
            buffer[static_cast<size_t>(len)] = '\0';
            if (len == maxRead) {
                // Input truncated; avoid processing potentially incomplete command
                LOG(ERROR) << __FUNCTION__ << " - control string too long " << len << " "
                           << buffer.data();
                break;
            }
            std::stringstream cmdLine(buffer.data());
            std::string cmd;
            std::stringstream out;
            bool pretty = false;
            cmdLine >> cmd;
            cmdLine.seekg(cmd.size());
            if (cmd.size() > 0 && cmd.back() == '!') {
                pretty = true;
                cmd.pop_back();
            }
            if (cmd.size() == 0) {
                ack(out);
            } else if (auto it = _cmds.find(cmd); it != _cmds.end()) {
                const auto applyCmd = [&] { it->second({_sockio, pretty, out, cmdLine}); };
                if (it == resetall) {
                    const std::lock_guard lock(mutexListeners);
                    applyCmd();
                } else {
                    const std::shared_lock<std::shared_mutex> lock(mutexListeners);
                    applyCmd();
                }
            } else {
                LOG(ERROR) << __FUNCTION__ << " - invalid command: '" << cmd << "'";
                nack(out);
            }
            if (!_sockio->print(out, pretty)) {
                LOG(ERROR) << __FUNCTION__ << " - control socket write error";
                break;
            }
            if (devShutdown) {
                snortSave(true); // will std::exit
            }
            if (quit) {
                break;
            }
        } else if (len == 0) {
            // Peer closed the connection.
            break;
        } else {
            const int err = errno;
            if (err == EINTR) {
                // Interrupted by signal, retry read.
                continue;
            }
            if (err == EAGAIN || err == EWOULDBLOCK) {
                if (activeStreams == 0) {
                    // No active streams on this control connection and no data
                    // received within the timeout window: treat as idle and close.
                    LOG(WARNING) << __FUNCTION__ << " - idle control client timeout, closing";
                    break;
                }
                // There is at least one active stream on this connection. It is expected
                // that the client may only receive data and not send further commands.
                // However, if we also observe that nothing has been written to this
                // socket for a full timeout window, we treat it as a dead stream and
                // close the connection to avoid leaking a stuck thread.
                const std::time_t now = std::time(nullptr);
                const std::time_t lastWrite = _sockio->lastWrite();
                if (lastWrite == 0 || now - lastWrite >= 15 * 60) {
                    LOG(WARNING) << __FUNCTION__
                                 << " - idle streaming control client timeout, closing";
                    break;
                }
                // Recent writes are observed on this socket; keep waiting for potential
                // future commands and do not close based on read timeout alone.
                continue;
            }
            LOG(ERROR) << __FUNCTION__ << " - control socket read error: " << std::strerror(err);
            break;
        }
    }
    close(sockClient);
}

namespace {
bool tryParseUint32(const std::string &token, uint32_t &out) {
    if (token.empty()) {
        return false;
    }
    uint32_t value = 0;
    const char *begin = token.data();
    const char *end = begin + token.size();
    const auto [ptr, ec] = std::from_chars(begin, end, value);
    if (ec != std::errc() || ptr != end) {
        return false;
    }
    out = value;
    return true;
}
} // namespace

auto Control::readCmdArgs(std::stringstream &args) {
    std::string arg;
    std::vector<CmdArg> vecArgs;
    while (args >> arg) {
        uint32_t num = 0;
        if (tryParseUint32(arg, num)) {
            vecArgs.emplace_back(arg, num);
        } else if (arg == "true" || arg == "false") {
            vecArgs.emplace_back((arg == "true"));
        } else {
            vecArgs.emplace_back(arg);
        }
    }
    if (vecArgs.empty()) {
        vecArgs.emplace_back();
    }
    return vecArgs;
}

auto Control::readCmdArg(std::stringstream &args) { return readCmdArgs(args)[0]; }

Control::CmdArg Control::readSingleArg(std::stringstream &args) {
    std::string token;
    if (!(args >> token)) {
        return CmdArg(); // NONE
    }
    // INT (uint32), parse safely without exceptions.
    uint32_t num = 0;
    if (tryParseUint32(token, num)) {
        return CmdArg(token, num);
    }
    // Check for boolean
    if (token == "true" || token == "false") {
        return CmdArg(token == "true");
    }
    // Otherwise STR
    return CmdArg(token);
}

Control::ParsedAppArg Control::readAppArg(std::stringstream &args, const bool allowBareUserId) {
    CmdArg arg = readSingleArg(args);

    if (arg.type == CmdArg::NONE) {
        return ParsedAppArg();
    }

    // Special case: pure USER <userId> filter (no explicit app)
    if (arg.type == CmdArg::STR && arg.string == "USER") {
        CmdArg userArg = readSingleArg(args);
        if (userArg.type == CmdArg::INT) {
            // Represent as "no app selected, but with a user filter"
            return ParsedAppArg(CmdArg(), userArg.number, true);
        }
        // Malformed USER clause - treat as no-selection with no user filter
        return ParsedAppArg();
    }

    if (arg.type == CmdArg::INT) {
        // INT: userId is derived from UID (uid / 100000)
        uint32_t userId = arg.number / 100000;
        return ParsedAppArg(arg, userId, false);
    }

    if (arg.type == CmdArg::STR) {
        // STR: check for optional "USER <userId>" clause, or (optionally) bare <userId>
        uint32_t userId = 0;
        bool hasUserClause = false;

        auto pos = args.tellg();
        std::string keyword;
        if (args >> keyword) {
            if (keyword == "USER") {
                uint32_t userIdArg;
                if (args >> userIdArg) {
                    userId = userIdArg;
                    hasUserClause = true;
                } else {
                    // "USER" without a number - restore position
                    args.clear();
                    args.seekg(pos);
                }
            } else if (allowBareUserId &&
                       std::all_of(keyword.begin(), keyword.end(), [](char ch) {
                           return std::isdigit(static_cast<unsigned char>(ch));
                       })) {
                // "<str> <userId>" form for commands that do not accept extra integer params
                userId = static_cast<uint32_t>(std::stoi(keyword));
                hasUserClause = true;
            } else {
                // Not a USER clause and not a bare userId we should consume - restore position
                args.clear();
                args.seekg(pos);
            }
        }
        return ParsedAppArg(arg, userId, hasUserClause);
    }

    // BOOL or other - just return as-is
    return ParsedAppArg(arg, 0, false);
}

const App::Ptr Control::arg2app(const CmdArg &arg) {
    if (arg.type == CmdArg::INT) {
        return appManager.find(arg.number);
    } else if (arg.type == CmdArg::STR) {
        return appManager.find(arg.string);
    }
    return nullptr;
}

const App::Ptr Control::arg2app(const ParsedAppArg &parg) {
    if (parg.arg.type == CmdArg::INT) {
        // INT: complete Linux UID, find by UID directly
        return appManager.find(parg.arg.number);
    } else if (parg.arg.type == CmdArg::STR) {
        // STR: package name with userId (either from USER clause or default 0)
        return appManager.findByName(parg.arg.string, parg.userId);
    }
    return nullptr;
}

const App::Ptr Control::arg2appWithUser(const CmdArg &arg, std::stringstream &args) {
    if (arg.type == CmdArg::INT) {
        // INT: treated as complete Linux UID
        return appManager.find(arg.number);
    } else if (arg.type == CmdArg::STR) {
        // STR: package name, check for optional "USER <userId>" clause
        uint32_t userId = 0; // Default to user 0 for backward compatibility
        std::string keyword;
        auto pos = args.tellg();
        if (args >> keyword) {
            if (keyword == "USER") {
                uint32_t userIdArg;
                if (args >> userIdArg) {
                    userId = userIdArg;
                } else {
                    // "USER" without a number - restore position and use default
                    args.clear();
                    args.seekg(pos);
                }
            } else {
                // Not "USER" keyword - restore position for caller
                args.clear();
                args.seekg(pos);
            }
        }
        return appManager.findByName(arg.string, userId);
    }
    return nullptr;
}

void Control::ack(std::stringstream &out) const { out << "OK"; }

void Control::nack(std::stringstream &out) const { out << "NOK"; }

void Control::cmdHello(CmdParams &&params) const { ack(params.out); }

void Control::cmdQuit(CmdParams &&params) const { quit = true; }

void Control::cmdDevShutdown(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() != 1 || args[0].type != CmdArg::NONE) {
        nack(params.out);
        return;
    }

    const int fd = params.sockio ? params.sockio->fd() : -1;
    ucred cred{};
    socklen_t credLen = sizeof(cred);
    if (fd < 0 || getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &credLen) != 0) {
        nack(params.out);
        return;
    }
    // DEV.* commands are reserved for adb / root workflows.
    if (cred.uid != 0 && cred.uid != 2000) { // root / shell
        nack(params.out);
        return;
    }

    devShutdown = true;
    ack(params.out);
}

void Control::cmdPassword(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    if (arg.type == CmdArg::NONE) {
        params.out << JSS(settings.password());
        return;
    }

    ack(params.out);
    if (arg.type == CmdArg::STR) {
        const std::string &raw = arg.string;
        std::string value = raw;
        if (raw.size() >= 2) {
            const char first = raw.front();
            const char last = raw.back();
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                value = raw.substr(1, raw.size() - 2);
            }
        }
        settings.password(value);
    }
}

void Control::cmdPassState(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    if (arg.type == CmdArg::NONE) {
        params.out << static_cast<uint32_t>(settings.passState());
    } else {
        ack(params.out);
        if (arg.type == CmdArg::INT) {
            settings.passState(arg.number);
        }
    }
}

void Control::cmdPerfmetrics(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() != 1) {
        nack(params.out);
        return;
    }

    const auto &arg = args[0];
    if (arg.type == CmdArg::NONE) {
        params.out << (perfMetrics.enabled() ? 1 : 0);
        return;
    }

    if (arg.type != CmdArg::INT || (arg.number != 0 && arg.number != 1)) {
        nack(params.out);
        return;
    }

    perfMetrics.setEnabled(arg.number == 1);
    ack(params.out);
}

void Control::cmdMetricsPerf(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() != 1 || args[0].type != CmdArg::NONE) {
        nack(params.out);
        return;
    }

    const auto snap = perfMetrics.snapshotForControl();

    const auto printOne = [&](const PerfMetrics::Summary &s) {
        params.out << "{"
                   << JSF("samples") << s.samples << "," << JSF("min") << s.min << ","
                   << JSF("avg") << s.avg << "," << JSF("p50") << s.p50 << ","
                   << JSF("p95") << s.p95 << "," << JSF("p99") << s.p99 << ","
                   << JSF("max") << s.max << "}";
    };

    params.out << "{" << JSF("perf") << "{";
    params.out << JSF("nfq_total_us");
    printOne(snap.nfq_total_us);
    params.out << "," << JSF("dns_decision_us");
    printOne(snap.dns_decision_us);
    params.out << "}}";
}

void Control::cmdMetricsPerfReset(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() != 1 || args[0].type != CmdArg::NONE) {
        nack(params.out);
        return;
    }

    perfMetrics.reset();
    ack(params.out);
}

void Control::cmdMetricsReasons(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() != 1 || args[0].type != CmdArg::NONE) {
        nack(params.out);
        return;
    }

    const auto snap = pktManager.reasonMetricsSnapshot();

    params.out << "{" << JSF("reasons") << "{";
    bool first = true;
    for (const auto reasonId : kPacketReasonIds) {
        const size_t idx = static_cast<size_t>(reasonId);
        when(first, params.out << ",");
        params.out << JSF(packetReasonIdStr(reasonId)) << "{"
                   << JSF("packets") << snap.reasons[idx].packets << "," << JSF("bytes")
                   << snap.reasons[idx].bytes << "}";
    }
    params.out << "}}";
}

void Control::cmdMetricsReasonsReset(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() != 1 || args[0].type != CmdArg::NONE) {
        nack(params.out);
        return;
    }

    pktManager.resetReasonMetrics();
    ack(params.out);
}

namespace {
const char *ipRulesActionStr(const IpRulesEngine::Action a) noexcept {
    return a == IpRulesEngine::Action::ALLOW ? "allow" : "block";
}

const char *ipRulesDirStr(const IpRulesEngine::Direction d) noexcept {
    switch (d) {
    case IpRulesEngine::Direction::ANY:
        return "any";
    case IpRulesEngine::Direction::IN:
        return "in";
    case IpRulesEngine::Direction::OUT:
        return "out";
    }
    return "any";
}

const char *ipRulesIfaceStr(const IpRulesEngine::IfaceKind k) noexcept {
    switch (k) {
    case IpRulesEngine::IfaceKind::ANY:
        return "any";
    case IpRulesEngine::IfaceKind::WIFI:
        return "wifi";
    case IpRulesEngine::IfaceKind::DATA:
        return "data";
    case IpRulesEngine::IfaceKind::VPN:
        return "vpn";
    case IpRulesEngine::IfaceKind::UNMANAGED:
        return "unmanaged";
    }
    return "any";
}

const char *ipRulesProtoStr(const IpRulesEngine::Proto p) noexcept {
    switch (p) {
    case IpRulesEngine::Proto::ANY:
        return "any";
    case IpRulesEngine::Proto::TCP:
        return "tcp";
    case IpRulesEngine::Proto::UDP:
        return "udp";
    case IpRulesEngine::Proto::ICMP:
        return "icmp";
    }
    return "any";
}

std::string ipRulesCidrStr(const IpRulesEngine::CidrV4 &c) {
    if (c.any) {
        return "any";
    }
    in_addr a{};
    a.s_addr = htonl(c.addr);
    char buf[INET_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET, &a, buf, sizeof(buf)) == nullptr) {
        return "any";
    }
    return std::string(buf) + "/" + std::to_string(static_cast<uint32_t>(c.prefix));
}

std::string ipRulesPortPredStr(const IpRulesEngine::PortPredicate &p) {
    switch (p.kind) {
    case IpRulesEngine::PortPredicate::Kind::ANY:
        return "any";
    case IpRulesEngine::PortPredicate::Kind::EXACT:
        return std::to_string(static_cast<uint32_t>(p.lo));
    case IpRulesEngine::PortPredicate::Kind::RANGE:
        return std::to_string(static_cast<uint32_t>(p.lo)) + "-" +
               std::to_string(static_cast<uint32_t>(p.hi));
    }
    return "any";
}

const char *ifaceKindStrFromBit(const uint8_t bit) noexcept {
    switch (bit) {
    case 1:
        return "wifi";
    case 2:
        return "data";
    case 4:
        return "vpn";
    case 128:
        return "unmanaged";
    default:
        return "unmanaged";
    }
}
} // namespace

void Control::cmdIpRules(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() != 1) {
        nack(params.out);
        return;
    }

    const auto &arg = args[0];
    if (arg.type == CmdArg::NONE) {
        params.out << (settings.ipRulesEnabled() ? 1 : 0);
        return;
    }

    if (arg.type != CmdArg::INT || (arg.number != 0 && arg.number != 1)) {
        nack(params.out);
        return;
    }

    settings.ipRulesEnabled(arg.number == 1);
    ack(params.out);
}

void Control::cmdIpRulesAdd(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() < 3 || args[0].type != CmdArg::INT) {
        nack(params.out);
        return;
    }

    std::vector<std::string> kv;
    kv.reserve(args.size() - 1);
    for (size_t i = 1; i < args.size(); ++i) {
        if (args[i].type != CmdArg::STR) {
            nack(params.out);
            return;
        }
        kv.push_back(args[i].string);
    }

    const auto res = pktManager.ipRules().addFromKv(args[0].number, kv);
    if (res.ok && res.ruleId.has_value()) {
        params.out << *res.ruleId;
    } else {
        nack(params.out);
    }
}

void Control::cmdIpRulesUpdate(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() < 2 || args[0].type != CmdArg::INT) {
        nack(params.out);
        return;
    }

    std::vector<std::string> kv;
    kv.reserve(args.size() - 1);
    for (size_t i = 1; i < args.size(); ++i) {
        if (args[i].type != CmdArg::STR) {
            nack(params.out);
            return;
        }
        kv.push_back(args[i].string);
    }

    const auto res = pktManager.ipRules().updateFromKv(args[0].number, kv);
    if (res.ok) {
        ack(params.out);
    } else {
        nack(params.out);
    }
}

void Control::cmdIpRulesRemove(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() != 1 || args[0].type != CmdArg::INT) {
        nack(params.out);
        return;
    }

    const auto res = pktManager.ipRules().removeRule(args[0].number);
    if (res.ok) {
        ack(params.out);
    } else {
        nack(params.out);
    }
}

void Control::cmdIpRulesEnable(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() != 2 || args[0].type != CmdArg::INT || args[1].type != CmdArg::INT ||
        (args[1].number != 0 && args[1].number != 1)) {
        nack(params.out);
        return;
    }

    const auto res = pktManager.ipRules().enableRule(args[0].number, args[1].number == 1);
    if (res.ok) {
        ack(params.out);
    } else {
        nack(params.out);
    }
}

void Control::cmdIpRulesPrint(CmdParams &&params) const {
    std::optional<uint32_t> uidFilter = std::nullopt;
    std::optional<IpRulesEngine::RuleId> ruleFilter = std::nullopt;

    std::string tok;
    while (params.args >> tok) {
        if (tok == "UID") {
            uint32_t uid = 0;
            if (!(params.args >> uid)) {
                nack(params.out);
                return;
            }
            uidFilter = uid;
        } else if (tok == "RULE") {
            uint32_t rid = 0;
            if (!(params.args >> rid)) {
                nack(params.out);
                return;
            }
            ruleFilter = rid;
        } else {
            nack(params.out);
            return;
        }
    }

    const auto rules = pktManager.ipRules().listRules(uidFilter, ruleFilter);

    params.out << "{" << JSF("rules") << "[";
    bool first = true;
    for (const auto &r : rules) {
        when(first, params.out << ",");
        const auto stats = pktManager.ipRules().statsSnapshot(r.ruleId);
        const IpRulesEngine::RuleStatsSnapshot s = stats.value_or(IpRulesEngine::RuleStatsSnapshot{});

        params.out << "{"
                   << JSF("ruleId") << r.ruleId << "," << JSF("uid") << r.uid << ","
                   << JSF("action") << JSS(ipRulesActionStr(r.action)) << ","
                   << JSF("priority") << r.priority << "," << JSF("enabled") << JSB(r.enabled)
                   << "," << JSF("enforce") << JSB(r.enforce) << "," << JSF("log") << JSB(r.log)
                   << "," << JSF("dir") << JSS(ipRulesDirStr(r.dir)) << ","
                   << JSF("iface") << JSS(ipRulesIfaceStr(r.iface)) << ","
                   << JSF("ifindex") << r.ifindex << ","
                   << JSF("proto") << JSS(ipRulesProtoStr(r.proto)) << ","
                   << JSF("src") << JSS(ipRulesCidrStr(r.src)) << ","
                   << JSF("dst") << JSS(ipRulesCidrStr(r.dst)) << ","
                   << JSF("sport") << JSS(ipRulesPortPredStr(r.sport)) << ","
                   << JSF("dport") << JSS(ipRulesPortPredStr(r.dport)) << ","
                   << JSF("stats") << "{"
                   << JSF("hitPackets") << s.hitPackets << "," << JSF("hitBytes") << s.hitBytes
                   << "," << JSF("lastHitTsNs") << s.lastHitTsNs << ","
                   << JSF("wouldHitPackets") << s.wouldHitPackets << ","
                   << JSF("wouldHitBytes") << s.wouldHitBytes << ","
                   << JSF("lastWouldHitTsNs") << s.lastWouldHitTsNs << "}"
                   << "}";
    }
    params.out << "]}";
}

void Control::cmdIpRulesPreflight(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() != 1 || args[0].type != CmdArg::NONE) {
        nack(params.out);
        return;
    }

    const auto rep = pktManager.ipRules().preflight();

    const auto printIssues = [&](const std::vector<IpRulesEngine::PreflightIssue> &issues) {
        params.out << "[";
        bool first = true;
        for (const auto &it : issues) {
            when(first, params.out << ",");
            params.out << "{"
                       << JSF("metric") << JSS(it.metric) << "," << JSF("value") << it.value
                       << "," << JSF("limit") << it.limit << "," << JSF("message") << JSS(it.message)
                       << "}";
        }
        params.out << "]";
    };

    params.out << "{";
    params.out << JSF("summary") << "{"
               << JSF("rulesTotal") << rep.summary.rulesTotal << ","
               << JSF("rangeRulesTotal") << rep.summary.rangeRulesTotal << ","
               << JSF("subtablesTotal") << rep.summary.subtablesTotal << ","
               << JSF("maxSubtablesPerUid") << rep.summary.maxSubtablesPerUid << ","
               << JSF("maxRangeRulesPerBucket") << rep.summary.maxRangeRulesPerBucket << "}"
               << ",";
    params.out << JSF("limits") << "{"
               << JSF("recommended") << "{"
               << JSF("maxRulesTotal") << rep.recommended.maxRulesTotal << ","
               << JSF("maxSubtablesPerUid") << rep.recommended.maxSubtablesPerUid << ","
               << JSF("maxRangeRulesPerBucket") << rep.recommended.maxRangeRulesPerBucket << "}"
               << "," << JSF("hard") << "{"
               << JSF("maxRulesTotal") << rep.hard.maxRulesTotal << ","
               << JSF("maxSubtablesPerUid") << rep.hard.maxSubtablesPerUid << ","
               << JSF("maxRangeRulesPerBucket") << rep.hard.maxRangeRulesPerBucket << "}"
               << "}"
               << ",";
    params.out << JSF("warnings");
    printIssues(rep.warnings);
    params.out << "," << JSF("violations");
    printIssues(rep.violations);
    params.out << "}";
}

void Control::cmdIfacesPrint(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() != 1 || args[0].type != CmdArg::NONE) {
        nack(params.out);
        return;
    }

    pktManager.refreshIfacesOnce();

    auto ifaces = if_nameindex();
    if (ifaces == nullptr) {
        params.out << "{" << JSF("ifaces") << "[]}";
        return;
    }

    struct IfaceEntry {
        uint32_t ifindex = 0;
        std::string name;
        std::string kind;
        std::optional<uint32_t> type;
    };

    std::vector<IfaceEntry> entries;
    for (auto it = ifaces; it && it->if_index != 0 && it->if_name != nullptr; ++it) {
        const uint32_t ifindex = it->if_index;
        const std::string name = it->if_name;

        IfaceEntry e{};
        e.ifindex = ifindex;
        e.name = name;
        e.kind = ifaceKindStrFromBit(pktManager.ifaceKindBit(ifindex));

        const std::string typePath = std::string("/sys/class/net/") + name + "/type";
        uint32_t t = 0;
        if (std::ifstream in(typePath); in.is_open() && (in >> t)) {
            e.type = t;
        }

        entries.push_back(std::move(e));
    }
    if_freenameindex(ifaces);

    std::sort(entries.begin(), entries.end(),
              [](const IfaceEntry &a, const IfaceEntry &b) { return a.ifindex < b.ifindex; });

    params.out << "{" << JSF("ifaces") << "[";
    bool first = true;
    for (const auto &e : entries) {
        when(first, params.out << ",");
        params.out << "{"
                   << JSF("ifindex") << e.ifindex << "," << JSF("name") << JSS(e.name) << ","
                   << JSF("kind") << JSS(e.kind);
        if (e.type.has_value()) {
            params.out << "," << JSF("type") << *e.type;
        }
        params.out << "}";
    }
    params.out << "]}";
}

void Control::cmdResetAll(CmdParams &&params) const {
    ack(params.out);
    LOG(INFO) << "Resetting all";
    // Note: exclusive mutexListeners lock is already held by the command loop caller
    perfMetrics.resetAll();
    settings.reset();
    // Clear all per-user save directories before resetting modules
    Settings::clearSaveTreeForResetAll();
    appManager.reset();
    domManager.reset();
    blockingListManager.reset();
    rulesManager.reset();
    pktManager.reset();
    hostManager.reset();
    dnsListener.reset();
    pkgListener.reset();
    snortSave();
}

void Control::cmdAppsByUid(CmdParams &&params) const {
    const auto parg = readAppArg(params.args, true);
    if (parg.arg.type == CmdArg::INT) {
        // APP.UID <uid> - single app by UID
        params.out << '[';
        if (const auto app = arg2app(parg)) {
            app->print(params.out);
        }
        params.out << ']';
    } else if (parg.arg.type == CmdArg::STR) {
        // APP.UID <str> [<userId>|USER <userId>] - substring match within specified userId
        appManager.printAppsByUid(params.out, parg.arg.string, parg.userId);
    } else {
        // APP.UID [USER <userId>] - device-wide list, optionally filtered by userId
        std::optional<uint32_t> userFilter = std::nullopt;
        if (parg.hasUserClause) {
            userFilter = parg.userId;
        }
        appManager.printAppsByUid(params.out, std::string(), userFilter);
    }
}

void Control::cmdAppsByName(CmdParams &&params) const {
    const auto parg = readAppArg(params.args, true);
    if (parg.arg.type == CmdArg::INT) {
        // APP.NAME <uid> - behaves like APP.UID <uid>
        params.out << '[';
        if (const auto app = arg2app(parg)) {
            app->print(params.out);
        }
        params.out << ']';
    } else if (parg.arg.type == CmdArg::STR) {
        // APP.NAME <str> [<userId>|USER <userId>] - substring match within specified userId
        appManager.printAppsByName(params.out, parg.arg.string, parg.userId);
    } else {
        // APP.NAME [USER <userId>] - device-wide list, optionally filtered by userId
        std::optional<uint32_t> userFilter = std::nullopt;
        if (parg.hasUserClause) {
            userFilter = parg.userId;
        }
        appManager.printAppsByName(params.out, std::string(), userFilter);
    }
}

void Control::cmdBlock(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    if (arg.type == CmdArg::NONE) {
        params.out << settings.blockEnabled();
    } else {
        ack(params.out);
        if (arg.type == CmdArg::INT) {
            settings.blockEnabled(arg.number == 1);
            activityManager.update(nullptr, true);
        }
    }
}

void Control::cmdGetBlackIPs(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    if (arg.type == CmdArg::NONE) {
        params.out << settings.getBlackIPs();
    } else {
        ack(params.out);
        if (arg.type == CmdArg::INT) {
            settings.getBlackIPs(arg.number == 1);
        }
    }
}

void Control::cmdBlockIPLeaks(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    if (arg.type == CmdArg::NONE) {
        params.out << settings.blockIPLeaks();
    } else {
        ack(params.out);
        if (arg.type == CmdArg::INT) {
            settings.blockIPLeaks(arg.number == 1);
        }
    }
}

void Control::cmdMaxAgeIP(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    if (arg.type == CmdArg::NONE) {
        params.out << settings.maxAgeIP();
    } else {
        ack(params.out);
        if (arg.type == CmdArg::INT) {
            settings.maxAgeIP(arg.number);
        }
    }
}

void Control::cmdBlockMask(CmdParams &&params) const {
    const auto parg = readAppArg(params.args);  // Reads app + optional USER clause
    const auto mask = readSingleArg(params.args);  // Read optional mask

    if (mask.type == CmdArg::NONE) {
        // GET mode: BLOCKMASK <uid|str> [USER <userId>]
        if (const auto app = arg2app(parg)) {
            LOG(INFO) << " cmdBlockMask " << static_cast<uint32_t>(app->blockMask());
            params.out << static_cast<uint32_t>(app->blockMask());
        }
    } else {
        // SET mode: BLOCKMASK <uid|str> [USER <userId>] <mask>
        if (mask.type != CmdArg::INT || !Settings::isValidAppBlockMask(mask.number)) {
            nack(params.out);
            return;
        }
        ack(params.out);
        if (const auto app = arg2app(parg)) {
            app->blockMask(static_cast<uint8_t>(mask.number));
            activityManager.update(app, true);
            LOG(INFO) << " cmdBlockMask " << static_cast<uint32_t>(app->blockMask());
        }
    }
}

void Control::cmdBlockMaskDef(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    if (arg.type == CmdArg::NONE) {
        params.out << static_cast<uint32_t>(settings.blockMask());
    } else {
        if (arg.type != CmdArg::INT || !Settings::isValidAppBlockMask(arg.number)) {
            nack(params.out);
            return;
        }
        ack(params.out);
        settings.blockMask(static_cast<uint8_t>(arg.number));
    }
}

void Control::cmdBlockIface(CmdParams &&params) const {
    const auto parg = readAppArg(params.args);  // Reads app + optional USER clause
    const auto iface = readSingleArg(params.args);  // Read optional iface

    if (const auto app = arg2app(parg)) {
        if (iface.type == CmdArg::NONE) {
            // GET mode
            params.out << static_cast<uint32_t>(app->blockIface());
        } else {
            // SET mode
            ack(params.out);
            if (iface.type == CmdArg::INT) {
                app->blockIface(iface.number);
            }
        }
    }
}

void Control::cmdBlockIfaceDef(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    if (arg.type == CmdArg::NONE) {
        params.out << static_cast<uint32_t>(settings.blockIface());
    } else {
        ack(params.out);
        if (arg.type == CmdArg::INT) {
            settings.blockIface(arg.number);
        }
    }
}

void Control::cmdTrack(CmdParams &&params, bool track) const {
    const auto parg = readAppArg(params.args, true);
    ack(params.out);
    if (const auto app = arg2app(parg)) {
        app->tracked(track);
    }
}

void Control::cmdReverseDnsOn(CmdParams &&params) const {
    ack(params.out);
    settings.reverseDns(true);
}

void Control::cmdReverseDnsOff(CmdParams &&params) const {
    ack(params.out);
    settings.reverseDns(false);
}

void Control::cmdStartDnsStream(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    ++activeStreams;
    dnsListener.startStream(params.sockio, params.pretty,
                            args.size() >= 1 ? args[0].number : settings.dnsStreamDefaultHorizon,
                            args.size() == 2 ? args[1].number : settings.dnsStreamMinSize);
}

void Control::cmdStopDnsStream(CmdParams &&params) const {
    ack(params.out);
    dnsListener.stopStream(params.sockio);
    if (activeStreams > 0) {
        --activeStreams;
    }
}

void Control::cmdStartPktStream(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    ++activeStreams;
    pktManager.startStream(params.sockio, params.pretty,
                           args.size() >= 1 ? args[0].number : settings.pktStreamDefaultHorizon,
                           args.size() == 2 ? args[1].number : settings.pktStreamMinSize);
}

void Control::cmdStopPktStream(CmdParams &&params) const {
    pktManager.stopStream(params.sockio);
    if (activeStreams > 0) {
        --activeStreams;
    }
}

void Control::cmdStartActivityStream(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    (void)args;
    ++activeStreams;
    activityManager.startStream(params.sockio, params.pretty, 0, 0);
}

void Control::cmdStopActivityStream(CmdParams &&params) const {
    activityManager.stopStream(params.sockio);
    if (activeStreams > 0) {
        --activeStreams;
    }
}

template <class... TypeStat>
void Control::cmdStatsTotal(CmdParams &&params, const Stats::View view,
                            const TypeStat... ts) const {
    appManager.printStatsTotal(params.out, view, ts...);
}

template <class... TypeStat>
void Control::cmdStatsApp(CmdParams &&params, const Stats::View view, const TypeStat... ts) const {
    const auto parg = readAppArg(params.args, true);
    if (parg.arg.type == CmdArg::INT) {
        // APP.<v> <uid> - stats for a single app
        params.out << '[';
        if (const auto app = arg2app(parg)) {
            app->printAppStats(params.out, view, ts...);
        }
        params.out << ']';
    } else if (parg.arg.type == CmdArg::STR) {
        // APP.<v> <str> [<userId>|USER <userId>] - per-app stats within specified userId
        appManager.printApps(params.out, parg.arg.string, view,
            parg.hasUserClause ? std::optional<uint32_t>(parg.userId) : std::nullopt, ts...);
    } else {
        // APP.<v> [USER <userId>] - device-wide stats, optionally filtered by user
        std::optional<uint32_t> userFilter = std::nullopt;
        if (parg.hasUserClause) {
            userFilter = parg.userId;
        }
        appManager.printApps(params.out, std::string(), view, userFilter, ts...);
    }
}

void Control::cmdResetApp(CmdParams &&params, const Stats::View view) const {
    const auto parg = readAppArg(params.args, true);
    if (parg.arg.type == CmdArg::INT) {
        if (const auto app = arg2app(parg)) {
            app->reset(view);
        }
    } else if (parg.arg.type == CmdArg::STR) {
        if (parg.arg.string == "ALL") {
            // APP.RESET.<v> ALL [USER <userId>]
            if (parg.hasUserClause) {
                appManager.reset(view, std::optional<uint32_t>(parg.userId));
            } else {
                appManager.reset(view);
            }
        } else if (const auto app = arg2app(parg)) {
            app->reset(view);
        }
    }
    ack(params.out);
}

void Control::cmdAppCustomLists(CmdParams &&params) const {
    const auto parg = readAppArg(params.args, true);
    if (const auto app = arg2app(parg)) {
        app->printCustomLists(params.out);
    }
}

void Control::cmdHosts(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    hostManager.printHosts(params.out, arg.string);
}

void Control::cmdHostsByName(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    hostManager.printHostsByName(params.out, arg.string);
}

void Control::cmdBlackDomainsStats(CmdParams &&params, const Stats::View view) const {
    domManager.printBlackDomainsStats(params.out, view);
}

template <class... TypeStat>
void Control::cmdDomainlist(CmdParams &&params, const Stats::Color cs, const Stats::View view,
                            const TypeStat... ts) const {
    const auto arg = readCmdArg(params.args);
    domManager.printDomains(params.out, arg.string, cs, view, ts...);
}

template <class... TypeStat>
void Control::cmdDomainlistApp(CmdParams &&params, const Stats::Color cs, const Stats::View view,
                               const TypeStat... ts) const {
    const auto parg = readAppArg(params.args);
    if (parg.arg.type == CmdArg::INT) {
        if (auto app = arg2app(parg)) {
            app->printDomains(params.out, cs, view, ts...);
        } else {
            ack(params.out);
        }
    } else if (parg.arg.type == CmdArg::STR) {
        // STR case: substring match within specified userId (or all users if not specified)
        appManager.printDomains(params.out, parg.arg.string, cs, view,
            parg.hasUserClause ? std::optional<uint32_t>(parg.userId) : std::nullopt, ts...);
    }
}

void Control::cmdTopActivity(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    if (arg.type == CmdArg::INT) {
        if (const auto app = appManager.make(arg.number)) {
            activityManager.make(app);
        }
    }
}

void Control::cmdUseCustomList(CmdParams &&params, bool useCustom) const {
    const auto parg = readAppArg(params.args);
    ack(params.out);
    if (const auto app = arg2app(parg)) {
        app->useCustomList(useCustom);
    }
}

void Control::cmdAddCustomDomain(CmdParams &&params, Stats::Color color) const {
    const auto parg = readAppArg(params.args);  // Reads app/domain + optional USER clause
    const auto domain = readSingleArg(params.args);  // Read optional domain

    ack(params.out);
    if (domain.type == CmdArg::NONE) {
        // Global form: BLACKLIST.ADD <domain>
        // First arg was actually the domain, not an app
        domManager.removeCustomDomain(parg.arg.string,
                                      color == Stats::BLACK ? Stats::WHITE : Stats::BLACK);
        domManager.addCustomDomain(parg.arg.string, color);
    } else {
        // App-specific form: BLACKLIST.ADD <app> [USER <userId>] <domain>
        if (const auto app = arg2app(parg)) {
            app->removeCustomDomain(domain.string,
                                    color == Stats::BLACK ? Stats::WHITE : Stats::BLACK);
            app->addCustomDomain(domain.string, color);
        }
    }
}

void Control::cmdRemoveCustomDomain(CmdParams &&params, Stats::Color color) const {
    const auto parg = readAppArg(params.args);
    const auto domain = readSingleArg(params.args);

    ack(params.out);
    if (domain.type == CmdArg::NONE) {
        // Global form
        domManager.removeCustomDomain(parg.arg.string, color);
    } else {
        // App-specific form
        if (const auto app = arg2app(parg)) {
            app->removeCustomDomain(domain.string, color);
        }
    }
}

void Control::cmdPrintCustomList(CmdParams &&params, Stats::Color color) const {
    const auto parg = readAppArg(params.args);
    if (parg.arg.type == CmdArg::NONE) {
        domManager.printCustomDomains(params.out, color);
    } else if (const auto app = arg2app(parg)) {
        app->printCustomDomains(params.out, color);
    }
}

void Control::cmdAddRule(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    params.out << JSS(
        rulesManager.addRule(static_cast<Rule::Type>(args[0].number), args[1].string));
}

void Control::cmdRemoveRule(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    ack(params.out);
    rulesManager.removeRule(args[0].number);
}

void Control::cmdUpdateRule(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    ack(params.out);
    rulesManager.updateRule(args[0].number, static_cast<Rule::Type>(args[1].number),
                            args[2].string);
}

void Control::cmdPrintRules(CmdParams &&params) const { rulesManager.print(params.out); }

void Control::cmdAddCustomRule(CmdParams &&params, Stats::Color color) const {
    const auto parg = readAppArg(params.args);  // Reads app/ruleId + optional USER clause
    const auto ruleArg = readSingleArg(params.args);  // Read optional rule ID

    ack(params.out);
    if (ruleArg.type == CmdArg::NONE) {
        // Global form: BLACKRULES.ADD <ruleId>
        // First arg was actually the rule ID, not an app
        if (parg.arg.type == CmdArg::INT) {
            rulesManager.removeCustom(parg.arg.number,
                                      color == Stats::BLACK ? Stats::WHITE : Stats::BLACK);
            rulesManager.addCustom(parg.arg.number, color, true);
        }
    } else {
        // App-specific form: BLACKRULES.ADD <app> [USER <userId>] <ruleId>
        if (ruleArg.type == CmdArg::INT) {
            if (const auto app = arg2app(parg)) {
                rulesManager.removeCustom(app, ruleArg.number,
                                          color == Stats::BLACK ? Stats::WHITE : Stats::BLACK);
                rulesManager.addCustom(app, ruleArg.number, color, true);
            }
        }
    }
}

void Control::cmdRemoveCustomRule(CmdParams &&params, Stats::Color color) const {
    const auto parg = readAppArg(params.args);
    const auto ruleArg = readSingleArg(params.args);

    ack(params.out);
    if (ruleArg.type == CmdArg::NONE) {
        // Global form
        if (parg.arg.type == CmdArg::INT) {
            rulesManager.removeCustom(parg.arg.number, color);
        }
    } else {
        // App-specific form
        if (ruleArg.type == CmdArg::INT) {
            if (const auto app = arg2app(parg)) {
                rulesManager.removeCustom(app, ruleArg.number, color);
            }
        }
    }
}

void Control::cmdPrintCustomRules(CmdParams &&params, Stats::Color color) const {
    const auto parg = readAppArg(params.args);
    if (parg.arg.type == CmdArg::NONE) {
        domManager.printCustomRules(params.out, color);
    } else if (const auto app = arg2app(parg)) {
        app->printCustomRules(params.out, color);
    }
}

void Control::cmdAddBlockingList(CmdParams &&params, Stats::Color color) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() >= 4) {
        std::string id = args[0].string;
        std::string url = args[1].string;
        uint32_t blockMask = args[2].number;
        std::string name = args[3].string;
        for (unsigned long i = 4; i < args.size(); i++) {
            name += " ";
            name += args[i].string;
        }
        if (!Settings::isValidBlockingListMask(blockMask)) {
            LOG(ERROR) << __FUNCTION__ << " Invalid blockMask " << blockMask;
            nack(params.out);
            return;
        }
        if (blockingListManager.addBlockingList(id, url, name, color,
                                                static_cast<uint8_t>(blockMask))) {
            blockingListManager.save();
            ack(params.out);
        } else {
            LOG(ERROR) << __FUNCTION__ << " Error on add BlockingList id " << id;
            nack(params.out);
        }
    } else {
        LOG(ERROR) << __FUNCTION__ << " Wrong arg numbers";
        nack(params.out);
    }
}

void Control::cmdUpdateBlockingList(CmdParams &&params, Stats::Color color) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() >= 9) {
        std::string id = args[0].string;
        std::string url = args[1].string;
        uint32_t blockMask = args[2].number;
        uint32_t domainCount = args[3].number;
        std::string updatedAtStr = args[4].string;
        std::string etag = args[5].string;
        bool enabled = args[6].boolean;
        bool outdated = args[7].boolean;
        std::string name = args[8].string;
        // Join remaining name fragments
        for (unsigned long i = 9; i < args.size(); i++) {
            name += " ";
            name += args[i].string;
        }

        if (!Settings::isValidBlockingListMask(blockMask)) {
            LOG(ERROR) << __FUNCTION__ << " Invalid blockMask " << blockMask;
            nack(params.out);
            return;
        }
        const uint8_t newMask = static_cast<uint8_t>(blockMask);

        // Reflect structural changes first
        uint8_t currentMask = 0;
        bool hasMask = blockingListManager.getBlockMask(id, currentMask);
        if (!hasMask) {
            LOG(ERROR) << __FUNCTION__ << " Cannot update list with id : " << id << " list not found";
            nack(params.out);
            return;
        }
        if (newMask != currentMask) {
            domManager.changeBlockMask(id, newMask, color);
        }
        Stats::Color currentColor;
        if (blockingListManager.getColor(id, currentColor) && currentColor != color) {
            domManager.switchListColor(id, color);
        }

        // Manager performs validated update (fix 8a: strict time parsing inside)
        if (blockingListManager.updateBlockingList(id, url, name, color, newMask,
                                                   domainCount, updatedAtStr, etag, enabled, outdated)) {
            blockingListManager.save();
            ack(params.out);
        } else {
            LOG(ERROR) << __FUNCTION__ << " Cannot update list with id : " << id;
            nack(params.out);
        }
    } else {
        LOG(ERROR) << __FUNCTION__ << " Wrong arg numbers";
        nack(params.out);
    }
}

void Control::cmdOutdateBlockingList(CmdParams &&params, Stats::Color color) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() == 1) {
        std::string id = args[0].string;
        if (blockingListManager.markOutdated(id)) {
            blockingListManager.save();
            ack(params.out);
        } else {
            nack(params.out);
        }
    } else {
        LOG(ERROR) << __FUNCTION__ << " Wrong arg numbers";
        nack(params.out);
    }
}

void Control::cmdRemoveBlockingList(CmdParams &&params, Stats::Color color) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() == 1) {
        if (!domManager.removeDomainList(args[0].string, color)) {
            LOG(ERROR) << " Error when removing domain list :" << args[0].string;
        };
        if (!blockingListManager.removeBlockingList(args[0].string)) {
            LOG(ERROR) << " Error when removing blocking list :" << args[0].string;
        }
        blockingListManager.save();
        ack(params.out);
    } else {
        LOG(ERROR) << __FUNCTION__ << " Wrong arg numbers";
        nack(params.out);
    }
}

void Control::cmdPrintBlockingLists(CmdParams &&params) const {
    const auto args = readCmdArg(params.args);
    if (args.type == CmdArg::NONE) {
        blockingListManager.printAll(params.out);
    } else {
        nack(params.out);
    }
}

void Control::cmdClearBlockingLists(CmdParams &&params) const {
    const auto args = readCmdArg(params.args);
    if (args.type == CmdArg::NONE) {
        for (const auto &bl : blockingListManager.listsSnapshot()) {
            domManager.removeDomainList(bl.getId(), bl.getColor());
            blockingListManager.removeBlockingList(bl.getId());
        }
        blockingListManager.save();
        ack(params.out);
    } else {
        LOG(ERROR) << __FUNCTION__ << " Wrong arg numbers";
        nack(params.out);
    }
}

void Control::cmdSaveBlockingLists(CmdParams &&params) const {
    const auto args = readCmdArg(params.args);
    if (args.type == CmdArg::NONE) {
        blockingListManager.save();
        ack(params.out);
    } else {
        LOG(ERROR) << __FUNCTION__ << " Wrong arg numbers";
        nack(params.out);
    }
}

void Control::cmdEnableBlockingList(CmdParams &&params, Stats::Color color) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() == 1) {
        std::string id = args[0].string;
        uint8_t mask = 0;
        if (blockingListManager.getBlockMask(id, mask) && domManager.enableList(id, mask, color) &&
            blockingListManager.setEnabled(id, true)) {
            blockingListManager.save();
            ack(params.out);
        } else {
            nack(params.out);
        }
    } else {
        LOG(ERROR) << __FUNCTION__ << " Wrong arg numbers";
        nack(params.out);
    }
}

void Control::cmdDisableBlockingList(CmdParams &&params, Stats::Color color) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() == 1) {
        std::string id = args[0].string;
        if (domManager.disableList(id, color) && blockingListManager.setEnabled(id, false)) {
            blockingListManager.save();
            ack(params.out);
        } else {
            nack(params.out);
        }
    } else {
        LOG(ERROR) << __FUNCTION__ << " Wrong arg numbers";
        nack(params.out);
    }
}

void Control::cmdAddManyDomains(CmdParams &&params, Stats::Color color) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() == 4) {
        if (!Settings::isValidBlockingListMask(args[1].number)) {
            LOG(ERROR) << __FUNCTION__ << " Invalid blockMask " << args[1].number;
            nack(params.out);
            return;
        }
        params.out << domManager.addDomainsToList(
            args[0].string, static_cast<uint8_t>(args[1].number), args[2].boolean,
            parseAggregatedDomains(args[3]), color);
    } else {
        LOG(ERROR) << __FUNCTION__ << " Wrong arg numbers";
        nack(params.out);
    }
}

void Control::cmdDomainsCount(CmdParams &&params, Stats::Color color) const {
    const auto args = readCmdArg(params.args);
    if (args.type == CmdArg::NONE) {
        params.out << domManager.getDomainsCount(color);
    } else {
        LOG(ERROR) << __FUNCTION__ << " Wrong arg numbers";
        nack(params.out);
    }
}

void Control::cmdDomainsPrint(CmdParams &&params, Stats::Color color) const {
    const auto args = readCmdArgs(params.args);
    if (args.size() == 1) {
        domManager.printDomainsFromList(args[0].string, color, params.out);
    }
}

std::vector<std::string> Control::parseAggregatedDomains(CmdArg arg) const {
    std::string allAggregatedDomains = arg.string.c_str();
    std::string domain;
    const std::string separator = ";";
    size_t pos_start = 0, pos_end;
    std::vector<std::string> allDomains = {};
    // Parse allDomains to obtain all domains separated by ';'
    while ((pos_end = allAggregatedDomains.find(separator, pos_start)) != std::string::npos) {
        domain = allAggregatedDomains.substr(pos_start, pos_end - pos_start);
        pos_start = pos_end + 1;
        allDomains.push_back(domain);
    }
    allDomains.push_back(allAggregatedDomains.substr(pos_start));
    return allDomains;
}

void Control::cmdHelp(CmdParams &&params) const {
    params.out
        << "***\r\n"
        << "*** Command usage\r\n"
        << "***\r\n"
        << "\r\n"
        << "- ending a command name by '!' indents json output (e.g. APP.UID!).\r\n"
        << "- commands output either a single int (for e.g. blocking status), or an array "
           "of\r\n"
        << "      objects which can be apps, or domains.\r\n"
        << "- <uid> as parameter: complete Linux UID (e.g. 10123 for user 0, 110123 for\r\n"
        << "      user 1). Outputs an array containing a single json object. If no app\r\n"
        << "      exists with that uid, the array is empty.\r\n"
        << "- <str> as parameter: package name. By default \"<str>\" refers to the main\r\n"
        << "      user (user 0). For commands that support multi-user selection on\r\n"
        << "      <uid|str>:\r\n"
        << "        * \"<str>\" alone selects (packageName, userId=0);\r\n"
        << "        * \"<str> USER <userId>\" explicitly selects an Android user;\r\n"
        << "        * for commands that do NOT accept extra integer parameters after\r\n"
        << "          <uid|str> (e.g. APP.UID, APP.NAME, APP<v>, APP.RESET<v>, TRACK,\r\n"
        << "          UNTRACK, APP.CUSTOMLISTS), \"<str> <userId>\" is also accepted and\r\n"
        << "          is equivalent to \"<str> USER <userId>\".\r\n"
        << "      Example: com.example.app USER 1\r\n"
        << "      Outputs an array of objects whose name match the string.\r\n"
        << "\r\n"
        << "*** Multi-user support\r\n"
        << "\r\n"
        << "Commands supporting USER <userId> clause (for STR parameter):\r\n"
        << "  APP.UID, APP.NAME, BLOCKMASK, BLOCKIFACE, TRACK, UNTRACK,\r\n"
        << "  APP<v>, APP.DNS<v>, APP.RXP<v>, APP.RXB<v>, APP.TXP<v>, APP.TXB<v>,\r\n"
        << "  APP.RESET<v>, BLACK.APP<v>, WHITE.APP<v>, GREY.APP<v>,\r\n"
        << "  CUSTOMLIST.ON, CUSTOMLIST.OFF, BLACKLIST.*, WHITELIST.*,\r\n"
        << "  BLACKRULES.*, WHITERULES.*, APP.CUSTOMLISTS\r\n"
        << "\r\n"
        << "Commands NOT supporting USER clause (global or UID-only):\r\n"
        << "  RESETALL, PERFMETRICS, METRICS.PERF, METRICS.PERF.RESET,\r\n"
        << "  METRICS.REASONS, METRICS.REASONS.RESET,\r\n"
        << "  IPRULES, IPRULES.*, IFACES.PRINT,\r\n"
        << "  DNSSTREAM.*, PKTSTREAM.*, ACTIVITYSTREAM.*,\r\n"
        << "  TOPACTIVITY (accepts <uid> only, not <str>),\r\n"
        << "  BLOCKLIST.*, RULES.*, ALL<v>, DNS<v>, RXP<v>, RXB<v>, TXP<v>, TXB<v>\r\n"
        << "    For these commands, any \"USER <userId>\" tokens are not interpreted as\r\n"
        << "    a per-user filter and the commands keep their device-wide semantics.\r\n"
        << "\r\n"

        << "***\r\n"
        << "*** General commands\r\n"
        << "***\r\n"
        << "\r\n"
        << "HELLO: prints OK.\r\n"
        << "QUIT: closes connection to the server.\r\n"
        << "PASSWORD [<str>]: prints or sets password.\r\n"
        << "PASSSTATE [<int>]: prints or sets password protection state.\r\n"
        << "RESETALL: resets all settings and data (statistics, domains, ...).\r\n"
        << "PERFMETRICS [<0|1>]: prints or sets D-layer perf metrics collection toggle.\r\n"
        << "METRICS.PERF: prints a perf metrics JSON snapshot (us).\r\n"
        << "METRICS.PERF.RESET: clears perf metrics aggregates.\r\n"
        << "METRICS.REASONS: prints device-wide per-reason packet/byte counters.\r\n"
        << "METRICS.REASONS.RESET: clears per-reason counters.\r\n"
        << "IPRULES [<0|1>]: prints or sets IPv4 L3/L4 rules engine toggle.\r\n"
        << "IFACES.PRINT: prints a JSON snapshot of current network interfaces.\r\n"
        << "IPRULES.PREFLIGHT: prints current ruleset complexity report.\r\n"
        << "IPRULES.PRINT [UID <uid>] [RULE <ruleId>]: prints rules as {\"rules\":[...]}.\r\n"
        << "IPRULES.ADD <uid> <kv...>: adds a rule, returns ruleId.\r\n"
        << "IPRULES.UPDATE <ruleId> <kv...>: patch-updates a rule.\r\n"
        << "IPRULES.REMOVE <ruleId>: removes a rule.\r\n"
        << "IPRULES.ENABLE <ruleId> <0|1>: disables/enables a rule.\r\n"
        << "\r\n"

        << "***\r\n"
        << "*** App information\r\n"
        << "***\r\n"
        << "\r\n"
        << "APP.UID [<uid|str>]: prints apps sorted by uid.\r\n"
        << "APP.NAME [<uid|str>]: prints apps sorted by name.\r\n"
        << "\r\n"

        << "***\r\n"
        << "*** Block control through host lists\r\n"
        << "***\r\n"
        << "\r\n"
        << "BLOCK [<0|1>]: prints, disables or enables blocking.\r\n"
        << "BLOCKMASK <uid|str> [<mask>]: prints or sets the app blocking mask. Mask bits:\r\n"
        << "    standard: 1, reinforced: 8 (implies 1), extra chains: 2/4/16/32/64, custom: 128.\r\n"
        << "BLOCKMASKDEF [<mask>]: prints or sets the default blocking mask for newly\r\n"
        << "    installed apps.\r\n"
        << "\r\n"

        << "***\r\n"
        << "*** Block control through network interfaces\r\n"
        << "***\r\n"
        << "\r\n"
        << "BLOCKIFACE <uid|str> [<mask>]: prints or sets the app blocking mask. Mask bits:\r\n"
        << "    wifi: 1, mobile data: 2, VPN: 4.\r\n"
        << "BLOCKIFACEDEF [<mask>]: prints or sets the default blocking mask for newly\r\n"
        << "    installed apps.\r\n"
        << "\r\n"

        << "***\r\n"
        << "*** IP leaks control\r\n"
        << "***\r\n"
        << "\r\n"
        << "BLOCKIPLEAKS [<0|1>]: prints, disables or enables the IP leak blocking\r\n"
        << "    mechanism.\r\n"
        << "MAXAGEIP [<int>]: prints or sets the IP maximum age in seconds.\r\n"
        << "GETBLACKIPS [<0|1>]: prints, disables or enables blacklisted hosts IP "
           "retrieval.\r\n"
        << "\r\n"

        << "***\r\n"
        << "*** Track control\r\n"
        << "***\r\n"
        << "\r\n"
        << "TRACK <uid|str>: sets the (unique) app tracking switch.\r\n"
        << "UNTRACK <uid|str>: unsets the (unique) app tracking switch.\r\n"
        << "\r\n"

        << "***\r\n"
        << "*** DNS and newtork packet streaming\r\n"
        << "***\r\n"
        << "\r\n"
        << "DNSSTREAM.START [<horizon> [<nbrequests>]]: starts streaming DNS requests\r\n"
        << "    and outputs past requests on the given horizon (by default 600 seconds),\r\n"
        << "    keeping at least a given number of them even if outdated.\r\n"
        << "DNSSTREAM.STOP: stops streaming DNS requests.\r\n"
        << "PKTSTREAM.START: starts streaming network packets.\r\n"
        << "PKTSTREAM.STOP: stops streaming network packets.\r\n"
        << "\r\n"

        << "***\r\n"
        << "*** Apps and Domains statistics\r\n"
        << "***\r\n"
        << "\r\n"
        << "Command name must be postfixed by <v> which may be one of:\r\n"
        << "  - .0: Today statistics\r\n"
        << "  - .1: Day-1 statistics\r\n"
        << "  - ...\r\n"
        << "  - .6: Day-6 statistics\r\n"
        << "  - .W: Week statistics, i.e. total from day-6 up to today\r\n"
        << "  - .A: All time statistics\r\n"
        << "\r\n"

        << "*** Apps statistics\r\n"
        << "\r\n"
        << "Matrix dimensions:\r\n"
        << "    1 -> type (DNS, RX packets, RX bytes, TX packets, TX bytes)\r\n"
        << "    2 -> color (all colors, black, white, grey)\r\n"
        << "    3 -> blocking status (all status, blocking on, blocking off)\r\n"
        << "ALL<v>: prints total statistics.\r\n"
        << "DNS<v>: prints total number of DNS requests.\r\n"
        << "RXP<v>: prints total number of RX packets.\r\n"
        << "RXB<v>: prints total size in bytes of RX packet payloads.\r\n"
        << "TXP<v>: prints total number of TX packets.\r\n"
        << "TXB<v>: prints total size in bytes of TX packet payloads.\r\n"
        << "APP<v> [<uid|str>]: prints all app statistics.\r\n"
        << "APP.DNS<v> [<uid|str>]: prints the number of DNS requests.\r\n"
        << "APP.RXP<v> [<uid|str>]: prints the number of RX packets.\r\n"
        << "APP.RXB<v> [<uid|str>]: prints the size in bytes of RX packet payloads.\r\n"
        << "APP.TXP<v> [<uid|str>]: prints the number of TX packets.\r\n"
        << "APP.RXB<v> [<uid|str>]: prints the size in bytes of TX packet payloads.\r\n"
        << "APP.RESET<v> [<uid|str>|ALL]: resets app's statistics.\r\n"
        << "\r\n"

        << "*** Domains statistics\r\n"
        << "\r\n"
        << "Matrix dimensions:\r\n"
        << "    1 -> type (DNS, RX packets, RX bytes, TX packets, TX bytes)\r\n"
        << "    2 -> blocking status (all status, blocking on, blocking off)\r\n"
        << "\r\n"
        << "DOMAINS<v>: prints the number of contacted domains in each category.\r\n"
        << "BLACK<v> [<str>]: prints stats for blacklisted domains matching <str>.\r\n"
        << "WHITE<v> [<str>]: prints stats for whitelisted domains matching <str>.\r\n"
        << "GREY<v> [<str>]: prints stats for all other domains matching <str>.\r\n"
        << "BLACK.APP<v> [<uid|str>]: prints app stats for blacklisted domains.\r\n"
        << "WHITE.APP<v> [<uid|str>]: prints app stats for whitelisted domains.\r\n"
        << "GREY.APP<v> [<uid|str>]: prints app stats for all other domains.\r\n"
        << "--> The commands above can be postfixed by one of .DNS, .RXP, .RXB, .TXP, .TXB\r\n"
        << "    in order to restrict the returned statistics. Example: BLACK.APP.DNS.A\r\n"
        << "    prints\r\n"
        << "    for all apps, all DNS requests for blacklisted domains.\r\n"
        << "\r\n"

        << "***\r\n"
        << "*** Custom black/white lists management\r\n"
        << "***\r\n"
        << "\r\n"
        << "Only domains already encountered can be added to a black or white list. These\r\n"
        << "commands do nothing if the domain has not already been encountered.\r\n"
        << "\r\n"
        << "CUSTOMLIST.ON <uid|str>: use the custom lists for the app.\r\n"
        << "CUSTOMLIST.OFF <uid|str>: do not use the custom lists for the app.\r\n"
        << "BLACKLIST.ADD [<uid|str>] <domain>: adds the domain to either the global custom\r\n"
        << "    blacklist, or to the app custom blacklist.\r\n"
        << "WHITELIST.ADD [<uid|str>] <domain>: adds the domain to either the global custom\r\n"
        << "    whitelist, or to the app custom whitelist.\r\n"
        << "BLACKLIST.REMOVE [<uid|str>] <domain>: removes the domain from either the "
           "global\r\n"
        << "    custom blacklist, or from the app custom blacklist.\r\n"
        << "WHITELIST.REMOVE [<uid|str>] <domain>: removes the domain from either the "
           "global\r\n"
        << "    whitelist, or from the app custom whitelist.\r\n"
        << "BLACKLIST.CLEAR [<uid|str>]: clears either the global custom blacklist or the\r\n"
        << "    app custom blacklist.\r\n"
        << "WHITELIST.CLEAR [<uid|str>]: clears either the global custom whitelist or the\r\n"
        << "    app custom whitelist.\r\n"
        << "BLACKLIST.PRINT [<uid|str>] <domain>: prints either the global custom "
           "blacklist,\r\n"
        << "    or the app custom blacklist.\r\n"
        << "WHITELIST.PRINT [<uid|str>] <domain>: prints either the the global whitelist,\r\n"
        << "    or the app custom whitelist.\r\n"
        << "BLOCKLIST.ADD <id> <url> <name>: add a blocking list "
           "identified by an uuid as its id,\r\n"
        << "BLOCKLIST.UPDATE <id> <url> <name>: update a blocking "
           "list,\r\n"
        << "BLOCKLIST.OUTDATE <id>: flag a list as outdated,\r\n"
        << "BLOCKLIST.REMOVE <id>: remove a blocking list and all "
           "domains imported from it,\r\n"
        << "BLOCKLIST.TOGGLE <id>: enable or disable a blocking list "
           "and remove all domains imported from it from,\r\n"
        << "    BLACK or WHITE list.\r\n"
        << "BLOCKLIST.REFRESH <id>: set the refresh date of a "
           "blocking list,\r\n"
        << "BLOCKLIST.PRINT <id>: print all blocking lists,\r\n"
        << "BLOCKLIST.SAVE : save all blocking lists.\r\n"
        << "DOMAIN.ADD.MANY <id>: add many domains.\r\n"
        << "DOMAIN.REMOVE.MANY <id>: remove many domains.\r\n";
}

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

#include <cutils/sockets.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>

#include <iode-snort.hpp>
#include <PackageListener.hpp>
#include <DnsListener.hpp>
#include <HostManager.hpp>
#include <PacketManager.hpp>
#include <DefaultAppsManager.hpp>
#include <Settings.hpp>
#include <Control.hpp>

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
    _cmds.emplace("PASSWORD", make(&Control::cmdPassword));
    _cmds.emplace("PASSSTATE", make(&Control::cmdPassState));
    _cmds.emplace("RESETALL", make(&Control::cmdResetAll));
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
    _cmds.emplace("HOSTS", make(&Control::cmdHosts));
    _cmds.emplace("HOSTS.NAME", make(&Control::cmdHostsByName));
    _cmds.emplace("DEFAULTAPPS.LIST", make(&Control::cmdDefaultAppsList));
    _cmds.emplace("DEFAULTAPPS.INSTALL", make(&Control::cmdDefaultAppsInstall));
    _cmds.emplace("DEFAULTAPPS.REMOVE", make(&Control::cmdDefaultAppsRemove));
    _cmds.emplace("CUSTOMLIST.ON", make(&Control::cmdUseCustomList, true));
    _cmds.emplace("CUSTOMLIST.OFF", make(&Control::cmdUseCustomList, false));
    _cmds.emplace("BLACKLIST.ADD", make(&Control::cmdAddCustomDomain, Stats::BLACK));
    _cmds.emplace("WHITELIST.ADD", make(&Control::cmdAddCustomDomain, Stats::WHITE));
    _cmds.emplace("BLACKLIST.REMOVE", make(&Control::cmdRemoveCustomDomain, Stats::BLACK));
    _cmds.emplace("WHITELIST.REMOVE", make(&Control::cmdRemoveCustomDomain, Stats::WHITE));
    _cmds.emplace("BLACKLIST.CLEAR", make(&Control::cmdClearCustomList, Stats::BLACK));
    _cmds.emplace("WHITELIST.CLEAR", make(&Control::cmdClearCustomList, Stats::WHITE));
    _cmds.emplace("BLACKLIST.PRINT", make(&Control::cmdPrintCustomList, Stats::BLACK));
    _cmds.emplace("WHITELIST.PRINT", make(&Control::cmdPrintCustomList, Stats::WHITE));

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
    std::thread([=] { unixServer(); }).detach();
    if (settings.inetControl()) {
        std::thread([=] { inetServer(); }).detach();
    }
}

void Control::unixServer() {
    int unixSocket = android_get_control_socket(settings.controlSocketPath);

    if (unixSocket < 1) {
        throw std::runtime_error("control unix socket error");
    }

    if (const int one = 1;
        setsockopt(unixSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        throw std::runtime_error("control unix socket setsockopt error");
    }

    if (listen(unixSocket, settings.controlClients) == -1) {
        throw std::runtime_error("control unix socket listen error");
    }

    for (;;) {
        if (const int sockClient = accept(unixSocket, nullptr, nullptr); sockClient < 0) {
            LOG(ERROR) << __FUNCTION__ << " - unix socket accept error";
        } else {
            std::thread([=] { clientLoop(sockClient); }).detach();
        }
    }
}

void Control::inetServer() {
    int inetSocket;
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
                std::thread([=] { clientLoop(sockClient); }).detach();
            }
        }
    } catch (const char *error) {
        LOG(ERROR) << __FUNCTION__ << " - " << error;
        close(inetSocket);
    }
}

void Control::clientLoop(const int sockClient) const {
    SocketIO::Ptr _sockio = std::make_shared<SocketIO>(sockClient);
    const auto &resetall = _cmds.find("RESETALL");
    char buffer[settings.controlCmdLen];
    std::string answer;
    int len;
    while ((len = read(sockClient, buffer, settings.controlCmdLen)) > 0) {
        if (len >= settings.controlCmdLen) {
            buffer[settings.controlCmdLen - 1] = 0;
            LOG(ERROR) << __FUNCTION__ << " - control string too long " << len << " " << buffer;
            break;
        }
        buffer[len] = '\0';
        std::stringstream cmdLine(buffer);
        std::string cmd;
        std::stringstream out;
        bool pretty = false;
        cmdLine >> cmd;
        cmdLine.seekg(cmd.size());
        if (cmd.back() == '!') {
            pretty = true;
            cmd.pop_back();
        }
        if (auto it = _cmds.find(cmd); it != _cmds.end()) {
            const auto applyCmd = [&] { it->second({_sockio, pretty, out, cmdLine}); };
            if (it == resetall) {
                const std::lock_guard lock(mutexListeners);
                applyCmd();
            } else {
                const std::shared_lock_guard lock(mutexListeners);
                applyCmd();
            }
        } else if (cmd.size() == 0) {
            ack(out);
        } else {
            LOG(ERROR) << __FUNCTION__ << " - invalid command: '" << cmd << "'";
            out << "\"KO\"";
        }
        if (!_sockio->print(out, pretty)) {
            LOG(ERROR) << __FUNCTION__ << " - control socket write error";
            break;
        }
        if (quit) {
            break;
        }
    }
    close(sockClient);
}

auto Control::readCmdArgs(std::stringstream &args) {
    std::string arg;
    std::vector<CmdArg> vecArgs;
    while (args >> arg) {
        if (std::all_of(arg.begin(), arg.end(), ::isdigit)) {
            vecArgs.emplace_back(arg, std::stoi(arg));
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

const App::Ptr Control::arg2app(const CmdArg &arg) {
    if (arg.type == CmdArg::INT) {
        return appManager.find(arg.number);
    } else if (arg.type == CmdArg::STR) {
        return appManager.find(arg.string);
    }
    return nullptr;
}

void Control::ack(std::stringstream &out) const { out << "\"OK\""; }

void Control::cmdHello(CmdParams &&params) const { ack(params.out); }

void Control::cmdQuit(CmdParams &&params) const { quit = true; }

void Control::cmdPassword(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    if (arg.type == CmdArg::NONE) {
        params.out << JSS(settings.password());
    } else {
        ack(params.out);
        if (arg.type == CmdArg::STR) {
            settings.password(arg.string.substr(1, arg.string.size() - 2));
        }
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

void Control::cmdResetAll(CmdParams &&params) const {
    ack(params.out);
    settings.reset();
    appManager.reset();
    domManager.reset();
    pktManager.reset();
    hostManager.reset();
    dnsListener.reset();
    pkgListener.reset();
    snortSave();
}

void Control::cmdAppsByUid(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    if (arg.type == CmdArg::INT) {
        params.out << '[';
        if (const auto app = arg2app(arg)) {
            app->print(params.out);
        }
        params.out << ']';
    } else {
        appManager.printAppsByUid(params.out, arg.string);
    }
}

void Control::cmdAppsByName(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    if (arg.type == CmdArg::INT) {
        params.out << '[';
        if (const auto app = arg2app(arg)) {
            app->print(params.out);
        }
        params.out << ']';
    } else {
        appManager.printAppsByName(params.out, arg.string);
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
    const auto args = readCmdArgs(params.args);
    if (args.size() == 1) {
        if (const auto app = arg2app(args[0])) {
            params.out << static_cast<uint32_t>(app->blockMask());
        }
    } else {
        ack(params.out);
        if (args.size() == 2 && args[1].type == CmdArg::INT) {
            if (const auto app = arg2app(args[0])) {
                app->blockMask(args[1].number);
            }
        }
    }
}

void Control::cmdBlockMaskDef(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    if (arg.type == CmdArg::NONE) {
        params.out << static_cast<uint32_t>(settings.blockMask());
    } else {
        ack(params.out);
        if (arg.type == CmdArg::INT) {
            settings.blockMask(arg.number);
        }
    }
}

void Control::cmdBlockIface(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    if (const auto app = arg2app(args[0])) {
        if (args.size() == 1) {
            params.out << static_cast<uint32_t>(app->blockIface());
        } else {
            ack(params.out);
            if (args.size() == 2 && args[1].type == CmdArg::INT) {
                app->blockIface(args[1].number);
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
    const auto arg = readCmdArg(params.args);
    ack(params.out);
    if (const auto app = arg2app(arg)) {
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
    dnsListener.startStream(params.sockio, params.pretty,
                            args.size() >= 1 ? args[0].number : settings.dnsStreamDefaultHorizon,
                            args.size() == 2 ? args[1].number : settings.dnsStreamMinSize);
}

void Control::cmdStopDnsStream(CmdParams &&params) const {
    ack(params.out);
    dnsListener.stopStream(params.sockio);
}

void Control::cmdStartPktStream(CmdParams &&params) const {
    const auto args = readCmdArgs(params.args);
    pktManager.startStream(params.sockio, params.pretty,
                           args.size() >= 1 ? args[0].number : settings.pktStreamDefaultHorizon,
                           args.size() == 2 ? args[1].number : settings.pktStreamMinSize);
}

void Control::cmdStopPktStream(CmdParams &&params) const { pktManager.stopStream(params.sockio); }

template <class... TypeStat>
void Control::cmdStatsTotal(CmdParams &&params, const Stats::View view,
                            const TypeStat... ts) const {
    appManager.printStatsTotal(params.out, view, ts...);
}

template <class... TypeStat>
void Control::cmdStatsApp(CmdParams &&params, const Stats::View view, const TypeStat... ts) const {
    const auto arg = readCmdArg(params.args);
    if (arg.type == CmdArg::INT) {
        params.out << '[';
        if (const auto app = arg2app(arg)) {
            app->printAppStats(params.out, view, ts...);
        }
        params.out << ']';
    } else {
        appManager.printApps(params.out, arg.string, view, ts...);
    }
}

void Control::cmdResetApp(CmdParams &&params, const Stats::View view) const {
    const auto arg = readCmdArg(params.args);
    ack(params.out);
    if (arg.type == CmdArg::INT) {
        if (const auto app = arg2app(arg)) {
            app->reset(view);
        }
    } else if (arg.type == CmdArg::STR) {
        if (arg.string == "ALL") {
            appManager.reset(view);
        } else if (const auto app = appManager.find(arg.string)) {
            app->reset(view);
        }
    }
}

void Control::cmdAppCustomLists(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    if (const auto app = arg2app(arg)) {
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
    const auto arg = readCmdArg(params.args);
    if (arg.type == CmdArg::INT) {
        if (auto app = arg2app(arg)) {
            app->printDomains(params.out, cs, view, ts...);
        } else {
            ack(params.out);
        }
    } else {
        appManager.printDomains(params.out, arg.string, cs, view, ts...);
    }
}

void Control::cmdDefaultAppsList(CmdParams &&params) const { defAppManager.print(params.out); }

void Control::cmdDefaultAppsInstall(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    ack(params.out);
    defAppManager.install(arg.string);
}

void Control::cmdDefaultAppsRemove(CmdParams &&params) const {
    const auto arg = readCmdArg(params.args);
    ack(params.out);
    defAppManager.remove(arg.string);
}

void Control::cmdUseCustomList(CmdParams &&params, bool useCustom) const {
    const auto arg = readCmdArg(params.args);
    ack(params.out);
    if (const auto app = arg2app(arg)) {
        app->useCustomList(useCustom);
    }
}

void Control::cmdAddCustomDomain(CmdParams &&params, Stats::Color color) const {
    const auto args = readCmdArgs(params.args);
    ack(params.out);
    if (args.size() == 1) {
        domManager.customList(color).add(args[0].string);
        domManager.customList(color == Stats::BLACK ? Stats::WHITE : Stats::BLACK)
            .remove(args[0].string);
    } else if (args.size() == 2) {
        if (const auto app = arg2app(args[0])) {
            app->customList(color).add(args[1].string);
            app->customList(color == Stats::BLACK ? Stats::WHITE : Stats::BLACK)
                .remove(args[1].string);
        }
    }
}

void Control::cmdRemoveCustomDomain(CmdParams &&params, Stats::Color color) const {
    const auto args = readCmdArgs(params.args);
    ack(params.out);
    if (args.size() == 1) {
        domManager.customList(color).remove(args[0].string);
    } else if (args.size() == 2) {
        if (const auto app = arg2app(args[0])) {
            app->customList(color).remove(args[1].string);
        }
    }
}

void Control::cmdClearCustomList(CmdParams &&params, Stats::Color color) const {
    const auto arg = readCmdArg(params.args);
    ack(params.out);
    if (arg.type == CmdArg::NONE) {
        domManager.customList(color).reset();
    } else if (const auto app = arg2app(arg)) {
        app->customList(color).reset();
    }
}

void Control::cmdPrintCustomList(CmdParams &&params, Stats::Color color) const {
    const auto arg = readCmdArg(params.args);
    if (arg.type == CmdArg::NONE) {
        domManager.customList(color).print(params.out);
    } else if (const auto app = arg2app(arg)) {
        app->customListConst(color).print(params.out);
    }
}

void Control::cmdHelp(CmdParams &&params) const {
    params.out
        << "***\r\n"
        << "*** Command usage\r\n"
        << "***\r\n"
        << "\r\n"
        << "- ending a command name by '!' indents json output (e.g. APP.UID!).\r\n"
        << "- commands output either a single int (for e.g. blocking status), or an array of\r\n"
        << "      objects which can be apps, or domains.\r\n"
        << "- <uid> as parameter: outputs an array containing a single json object. If no\r\n"
        << "      app exists with that uid, the array is empty.\r\n"
        << "- <str> as parameter: outputs an array of objects whose name match the string.\r\n"
        << "      If no object exists with that uid, the array is empty.\r\n"
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
        << "    standard: 1, socials: 2, porn: 4, extreme: 8.\r\n"
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
        << "GETBLACKIPS [<0|1>]: prints, disables or enables blacklisted hosts IP retrieval.\r\n"
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
        << "BLACKLIST.REMOVE [<uid|str>] <domain>: removes the domain from either the global\r\n"
        << "    custom blacklist, or from the app custom blacklist.\r\n"
        << "WHITELIST.REMOVE [<uid|str>] <domain>: removes the domain from either the global\r\n"
        << "    whitelist, or from the app custom whitelist.\r\n"
        << "BLACKLIST.CLEAR [<uid|str>]: clears either the global custom blacklist or the\r\n"
        << "    app custom blacklist.\r\n"
        << "WHITELIST.CLEAR [<uid|str>]: clears either the global custom whitelist or the\r\n"
        << "    app custom whitelist.\r\n"
        << "BLACKLIST.PRINT [<uid|str>] <domain>: prints either the global custom blacklist,\r\n"
        << "    or the app custom blacklist.\r\n"
        << "WHITELIST.PRINT [<uid|str>] <domain>: prints either the the global whitelist,\r\n"
        << "    or the app custom whitelist.\r\n";
}

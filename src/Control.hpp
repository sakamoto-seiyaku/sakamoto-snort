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

#pragma once

#include <sstream>

class Control {
private:
    struct CmdArg {
        const enum { NONE, INT, STR } type;
        const uint32_t number = 0;
        const std::string string;

        CmdArg()
            : type(NONE) {}

        CmdArg(const std::string &str, const uint32_t num)
            : type(INT)
            , number(num)
            , string(str) {}

        CmdArg(const std::string &str)
            : type(STR)
            , string(str) {}
    };

    struct CmdParams {
        const SocketIO::Ptr sockio;
        const bool pretty;
        std::stringstream &out;
        std::stringstream &args;
    };

    using CmdFun = std::function<void(CmdParams &&)>;
    using CmdMap = std::unordered_map<std::string, const CmdFun>;

    CmdMap _cmds;

    thread_local static inline bool quit = false;

public:
    Control();

    ~Control();

    Control(const Control &) = delete;

    void start();

private:
    template <class Fun, class... Args> CmdFun make(const Fun &&fun, const Args... fargs);

    void inetServer();

    void unixServer();

    void clientLoop(const int sockClient) const;

    static auto readCmdArgs(std::stringstream &args);

    static auto readCmdArg(std::stringstream &args);

    static const App::Ptr arg2app(const CmdArg &arg);

    void ack(std::stringstream &out) const;

    void cmdHello(CmdParams &&params) const;

    void cmdQuit(CmdParams &&params) const;

    void cmdPassword(CmdParams &&params) const;

    void cmdPassState(CmdParams &&params) const;

    void cmdAppsByUid(CmdParams &&params) const;

    void cmdAppsByName(CmdParams &&params) const;

    void cmdAppCustomLists(CmdParams &&params) const;

    void cmdBlock(CmdParams &&params) const;

    void cmdGetBlackIPs(CmdParams &&params) const;

    void cmdBlockIPLeaks(CmdParams &&params) const;

    void cmdMaxAgeIP(CmdParams &&params) const;

    void cmdBlockMask(CmdParams &&params) const;

    void cmdBlockMaskDef(CmdParams &&params) const;

    void cmdBlockIface(CmdParams &&params) const;

    void cmdBlockIfaceDef(CmdParams &&params) const;

    void cmdTrack(CmdParams &&params, bool track) const;

    void cmdReverseDnsOn(CmdParams &&params) const;

    void cmdReverseDnsOff(CmdParams &&params) const;

    void cmdStartDnsStream(CmdParams &&params) const;

    void cmdStopDnsStream(CmdParams &&params) const;

    void cmdStartPktStream(CmdParams &&params) const;

    void cmdStopPktStream(CmdParams &&params) const;

    template <class... TypeStat>
    void cmdStatsTotal(CmdParams &&params, const Stats::View view, const TypeStat... ts) const;

    template <class... TypeStat>
    void cmdStatsApp(CmdParams &&params, const Stats::View view, const TypeStat... ts) const;

    void cmdResetApp(CmdParams &&params, const Stats::View view) const;

    void cmdResetAll(CmdParams &&params) const;

    void cmdHosts(CmdParams &&params) const;

    void cmdHostsByName(CmdParams &&params) const;

    void cmdBlackDomainsStats(CmdParams &&params, const Stats::View view) const;

    template <class... TypeStat>
    void cmdDomainlist(CmdParams &&params, const Stats::Color cs, const Stats::View view,
                       const TypeStat... ts) const;

    template <class... TypeStat>
    void cmdDomainlistApp(CmdParams &&params, const Stats::Color cs, const Stats::View view,
                          const TypeStat... ts) const;

    void cmdDefaultAppsList(CmdParams &&params) const;

    void cmdDefaultAppsInstall(CmdParams &&params) const;

    void cmdDefaultAppsRemove(CmdParams &&params) const;

    void cmdUseCustomList(CmdParams &&params, bool useCustom) const;

    void cmdAddCustomDomain(CmdParams &&params, Stats::Color color) const;

    void cmdRemoveCustomDomain(CmdParams &&params, Stats::Color color) const;

    void cmdClearCustomList(CmdParams &&params, Stats::Color color) const;

    void cmdPrintCustomList(CmdParams &&params, Stats::Color color) const;

    void cmdHelp(CmdParams &&params) const;
};

extern Control control;

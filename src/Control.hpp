/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <sstream>
#include <App.hpp>
#include <SocketIO.hpp>

class Control {
private:
    struct CmdArg {
        const enum { NONE, INT, STR, BOOL } type;
        const uint32_t number = 0;
        const bool boolean = false;
        const std::string string;

        CmdArg()
            : type(NONE) {}

        CmdArg(const std::string &str, const uint32_t num)
            : type(INT)
            , number(num)
            , string(str) {}

        CmdArg(const bool b)
            : type(BOOL)
            , boolean(b) {}

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

    void nack(std::stringstream &out) const;

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

    void cmdStartActivityStream(CmdParams &&params) const;

    void cmdStopActivityStream(CmdParams &&params) const;

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

    void cmdTopActivity(CmdParams &&params) const;

    void cmdUseCustomList(CmdParams &&params, bool useCustom) const;

    void cmdAddCustomDomain(CmdParams &&params, Stats::Color color) const;

    void cmdRemoveCustomDomain(CmdParams &&params, Stats::Color color) const;

    void cmdPrintCustomList(CmdParams &&params, Stats::Color color) const;

    void cmdAddRule(CmdParams &&params) const;

    void cmdRemoveRule(CmdParams &&params) const;

    void cmdUpdateRule(CmdParams &&params) const;

    void cmdPrintRules(CmdParams &&params) const;

    void cmdAddCustomRule(CmdParams &&params, Stats::Color color) const;

    void cmdRemoveCustomRule(CmdParams &&params, Stats::Color color) const;

    void cmdPrintCustomRules(CmdParams &&params, Stats::Color color) const;

    void cmdClearCustomRules(CmdParams &&params, Stats::Color color) const;

    void cmdHelp(CmdParams &&params) const;

    void cmdAddBlockingList(CmdParams &&params, Stats::Color color) const;

    void cmdRemoveBlockingList(CmdParams &&params, Stats::Color color) const;

    void cmdUpdateBlockingList(CmdParams &&params, Stats::Color color) const;

    void cmdOutdateBlockingList(CmdParams &&params, Stats::Color color) const;

    void cmdPrintBlockingLists(CmdParams &&params) const;

    void cmdClearBlockingLists(CmdParams &&params) const;

    void cmdSaveBlockingLists(CmdParams &&params) const;

    void cmdAddManyDomains(CmdParams &&params, Stats::Color color) const;

    void cmdEnableBlockingList(CmdParams &&params, Stats::Color color) const;

    void cmdDisableBlockingList(CmdParams &&params, Stats::Color color) const;

    void cmdDomainsCount(CmdParams &&params, Stats::Color color) const;

    void cmdDomainsPrint(CmdParams &&params, Stats::Color color) const;

    std::vector<std::string> parseAggregatedDomains(CmdArg arg) const;
};

extern Control control;

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

    // ParsedAppArg: holds a CmdArg with parsed userId for multi-user support
    // Unlike readCmdArg + arg2appWithUser pattern, readAppArg parses USER clause
    // as part of the initial read, avoiding stream exhaustion issues.
    struct ParsedAppArg {
        CmdArg arg;
        uint32_t userId = 0;
        bool hasUserClause = false;

        ParsedAppArg() : arg() {}
        ParsedAppArg(const CmdArg &a, uint32_t uid = 0, bool hasUser = false)
            : arg(a), userId(uid), hasUserClause(hasUser) {}
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

    // Per-control-thread state:
    // - quit: set by cmdQuit to stop the current client loop.
    // - activeStreams: number of active long-lived streams (DNS/packet/activity)
    //   associated with the current control connection.
    thread_local static inline bool quit = false;
    thread_local static inline bool devShutdown = false;
    thread_local static inline uint32_t activeStreams = 0;

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

    // Read a single token from stream (does NOT consume entire stream like readCmdArgs)
    static CmdArg readSingleArg(std::stringstream &args);

    // Read app identifier + optional USER <userId> clause
    // - For INT: userId is extracted from UID (uid / 100000)
    // - For STR: checks for optional "USER <userId>" and consumes if present
    // - For bare 'USER <userId>' (no app), returns ParsedAppArg with arg.type = NONE and
    //   hasUserClause = true to represent a pure user filter.
    // - Remaining stream position preserved for additional arguments
    // - When allowBareUserId is true, a second integer token after a string (e.g. "<str> <userId>")
    //   is interpreted as userId for commands that do not accept extra integer parameters.
    static ParsedAppArg readAppArg(std::stringstream &args, bool allowBareUserId = false);

    static const App::Ptr arg2app(const CmdArg &arg);

    // AppSelector from ParsedAppArg (preferred - already has userId parsed)
    static const App::Ptr arg2app(const ParsedAppArg &parg);

    // AppSelector: parses app argument with optional USER <userId> clause
    // - INT: treated as complete Linux UID, userId extracted from UID
    // - STR: package name, optionally followed by "USER <userId>" in remaining args
    // - Default userId is 0 for backward compatibility
    // DEPRECATED: Use readAppArg() + arg2app(ParsedAppArg) instead to avoid stream exhaustion
    static const App::Ptr arg2appWithUser(const CmdArg &arg, std::stringstream &args);

    void ack(std::stringstream &out) const;

    void nack(std::stringstream &out) const;

    void cmdHello(CmdParams &&params) const;

    void cmdQuit(CmdParams &&params) const;

    void cmdDevShutdown(CmdParams &&params) const;

    void cmdPassword(CmdParams &&params) const;

    void cmdPassState(CmdParams &&params) const;

    void cmdPerfmetrics(CmdParams &&params) const;

    void cmdMetricsPerf(CmdParams &&params) const;

    void cmdMetricsPerfReset(CmdParams &&params) const;

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

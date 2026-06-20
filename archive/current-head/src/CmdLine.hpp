/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <vector>

class CmdLine {
private:
    std::vector<std::string> _args;
    uint32_t _argc = 0;
    char **_argv = nullptr;

public:
    template <class... Targs> CmdLine(const Targs... args);

    CmdLine(const CmdLine &cmd);

    ~CmdLine();

    template <class T, class... Targs> void add(const T &&arg, const Targs... args);

    template <class T, class... Targs> void add(const T &arg, const Targs... args);

    template <class T> void add(const T &&arg);

    template <class T> void add(const T &arg);

    void exec();
};

template <class... Targs> CmdLine::CmdLine(const Targs... args) { add(args...); }

template <class T, class... Targs> void CmdLine::add(const T &&arg, const Targs... args) {
    add(arg);
    add(args...);
}

template <class T, class... Targs> void CmdLine::add(const T &arg, const Targs... args) {
    add(std::move(arg), args...);
}

template <class T> void CmdLine::add(const T &&arg) { _args.emplace_back(arg); }

template <class T> void CmdLine::add(const T &arg) { add(std::move(arg)); }

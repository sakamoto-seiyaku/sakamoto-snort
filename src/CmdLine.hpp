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

#include <vector>

class CmdLine {
private:
    std::vector<const std::string> _args;
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

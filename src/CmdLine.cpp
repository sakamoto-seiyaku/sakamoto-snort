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

#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iode-snort.hpp>
#include <CmdLine.hpp>

CmdLine::CmdLine(const CmdLine &cmd)
    : _args(cmd._args) {}

CmdLine::~CmdLine() {
    for (size_t i = 0; i < _argc; ++i) {
        delete[] _argv[i];
    }
    free(_argv);
}

void CmdLine::exec() {
    if (_argc < _args.size()) {
        if ((_argv = static_cast<char **>(reallocarray(_argv, _args.size() + 1, sizeof(char *))))) {
            for (; _argc < _args.size(); ++_argc) {
                _argv[_argc] = new char[_args[_argc].size() + 1];
                std::memcpy(_argv[_argc], _args[_argc].c_str(), _args[_argc].size() + 1);
            }
            _argv[_args.size()] = nullptr;
        }
    }
    if (_argc > 0) {
        if (const auto pid = fork(); pid == 0) {
            execv(_argv[0], _argv);
        } else {
            int wstatus;
            waitpid(pid, &wstatus, 0);
        }
    }
}

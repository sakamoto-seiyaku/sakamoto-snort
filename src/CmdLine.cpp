/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
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

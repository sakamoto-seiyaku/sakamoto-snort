/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <cstdlib>
#include <cstring>
#include <sys/wait.h>
#include <unistd.h>

#include <sucre-snort.hpp>
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
        // Use a temporary to avoid clobbering _argv on allocation failure.
        char **new_argv = static_cast<char **>(reallocarray(_argv, _args.size() + 1, sizeof(char *)));
        if (!new_argv) {
            LOG(ERROR) << __FUNCTION__ << " - argv allocation failed";
            return; // leave existing _argv/_argc intact
        }
        _argv = new_argv;
        for (; _argc < _args.size(); ++_argc) {
            _argv[_argc] = new char[_args[_argc].size() + 1];
            std::memcpy(_argv[_argc], _args[_argc].c_str(), _args[_argc].size() + 1);
        }
        _argv[_args.size()] = nullptr;
    }
    if (_argc > 0) {
        if (const auto pid = fork(); pid == 0) {
            // Child: replace image. If execv returns, it's a failure and we must not continue
            // running parent logic. Use only async-signal-safe calls here.
            execv(_argv[0], _argv);
            static const char msg[] = "sucre-snort: execv failed in child\n";
            (void)!write(STDERR_FILENO, msg, sizeof(msg) - 1);
            _exit(127); // unreachable on success
        } else {
            int wstatus;
            waitpid(pid, &wstatus, 0);
        }
    }
}

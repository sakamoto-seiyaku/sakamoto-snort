/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#ifdef __ANDROID__
#include <android/log.h>
#endif

#include <cstdlib>
#include <iostream>
#include <ostream>
#include <sstream>

namespace sucre::snort {

enum class LogSeverity {
    INFO,
    WARNING,
    ERROR,
    FATAL,
};

class LogStream {
public:
    LogStream(const LogSeverity severity, const char *const file, const int line)
        : _severity(severity), _file(file), _line(line) {}

    ~LogStream() noexcept {
        flush();
        if (_severity == LogSeverity::FATAL) {
            std::abort();
        }
    }

    LogStream(const LogStream &) = delete;
    LogStream &operator=(const LogStream &) = delete;

    template <class T> LogStream &operator<<(const T &value) {
        _stream << value;
        return *this;
    }

    LogStream &operator<<(std::ostream &(*manipulator)(std::ostream &)) {
        manipulator(_stream);
        return *this;
    }

private:
    static constexpr const char *tag() noexcept { return "sucre-snort"; }

    static const char *severityName(const LogSeverity severity) noexcept {
        switch (severity) {
        case LogSeverity::INFO:
            return "INFO";
        case LogSeverity::WARNING:
            return "WARNING";
        case LogSeverity::ERROR:
            return "ERROR";
        case LogSeverity::FATAL:
            return "FATAL";
        }
        return "UNKNOWN";
    }

#ifdef __ANDROID__
    static int androidPriority(const LogSeverity severity) noexcept {
        switch (severity) {
        case LogSeverity::INFO:
            return ANDROID_LOG_INFO;
        case LogSeverity::WARNING:
            return ANDROID_LOG_WARN;
        case LogSeverity::ERROR:
            return ANDROID_LOG_ERROR;
        case LogSeverity::FATAL:
            return ANDROID_LOG_FATAL;
        }
        return ANDROID_LOG_DEFAULT;
    }
#endif

    void flush() noexcept {
        try {
            std::ostringstream out;
            out << _file << ':' << _line << " " << _stream.str();
            const std::string message = out.str();
#ifdef __ANDROID__
            __android_log_write(androidPriority(_severity), tag(), message.c_str());
#else
            std::ostream &sink =
                (_severity == LogSeverity::ERROR || _severity == LogSeverity::FATAL) ? std::cerr
                                                                                     : std::clog;
            sink << tag() << ' ' << severityName(_severity) << ' ' << message << '\n';
#endif
        } catch (...) {
        }
    }

    LogSeverity _severity;
    const char *_file;
    int _line;
    std::ostringstream _stream;
};

} // namespace sucre::snort

#define LOG(severity)                                                                            \
    ::sucre::snort::LogStream(::sucre::snort::LogSeverity::severity, __FILE__, __LINE__)

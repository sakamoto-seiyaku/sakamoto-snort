/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sucre_snort_ctl_session.hpp>

#include <ControlVNextCodec.hpp>

#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <string>
#include <string_view>

namespace SucreSnortCtl {

namespace {

constexpr size_t kDefaultMaxFrameBytes = 16 * 1024 * 1024;

bool writeAll(const int fd, const std::string_view data) {
    size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t n = ::write(fd, data.data() + offset, data.size() - offset);
        if (n > 0) {
            offset += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

} // namespace

int runSession(const int fd, const RequestOptions &request, const SessionOptions &options,
               std::ostream &out, std::ostream &err) {
    rapidjson::Document argsDoc;
    ControlVNext::JsonError argsError;
    if (!ControlVNext::parseStrictJsonObject(request.argsJson, argsDoc, argsError)) {
        err << "args JSON parse failed at offset " << argsError.offset << ": " << argsError.message
            << "\n";
        return 2;
    }

    const rapidjson::Document requestDoc =
        ControlVNext::makeRequest(request.id, request.cmd, argsDoc);
    ControlVNext::RequestView requestView;
    if (const auto envErr = ControlVNext::parseRequestEnvelope(requestDoc, requestView);
        envErr.has_value()) {
        err << "constructed request invalid: " << envErr->code << ": " << envErr->message << "\n";
        return 2;
    }

    const std::string requestJson =
        ControlVNext::encodeJson(requestDoc, ControlVNext::JsonFormat::Compact);
    const std::string requestFrame = ControlVNext::encodeNetstring(requestJson);
    if (requestFrame.empty()) {
        err << "failed to encode request netstring\n";
        return 2;
    }
    if (!writeAll(fd, requestFrame)) {
        err << "write failed: " << std::strerror(errno) << "\n";
        return 2;
    }

    const size_t maxFrameBytes = options.maxFrameBytes == 0 ? kDefaultMaxFrameBytes : options.maxFrameBytes;
    ControlVNext::NetstringDecoder decoder(maxFrameBytes);

    bool sawResponse = false;
    int exitCode = 0;
    size_t printedFrames = 0;

    const auto printFrame = [&](const rapidjson::Document &doc) {
        const auto format =
            options.pretty ? ControlVNext::JsonFormat::Pretty : ControlVNext::JsonFormat::Compact;
        out << ControlVNext::encodeJson(doc, format) << "\n";
        printedFrames++;
    };

    std::array<std::byte, 4096> buf{};
    for (;;) {
        while (const auto payload = decoder.pop()) {
            rapidjson::Document doc;
            ControlVNext::JsonError jsonError;
            if (!ControlVNext::parseStrictJsonObject(*payload, doc, jsonError)) {
                err << "frame JSON parse failed at offset " << jsonError.offset << ": "
                    << jsonError.message << "\n";
                return 2;
            }

            if (doc.HasMember("id") || doc.HasMember("ok")) {
                ControlVNext::ResponseView responseView;
                const auto envErr = ControlVNext::parseResponseEnvelope(doc, responseView);
                if (envErr.has_value()) {
                    err << "invalid response envelope: " << envErr->code << ": " << envErr->message
                        << "\n";
                    return 2;
                }

                printFrame(doc);
                sawResponse = true;
                exitCode = responseView.ok ? 0 : 1;

                if (!options.follow) {
                    return exitCode;
                }
            } else if (doc.HasMember("type")) {
                ControlVNext::EventView eventView;
                const auto envErr = ControlVNext::parseEventEnvelope(doc, eventView);
                if (envErr.has_value()) {
                    err << "invalid event envelope: " << envErr->code << ": " << envErr->message
                        << "\n";
                    return 2;
                }
                (void)eventView;
                printFrame(doc);
            } else {
                printFrame(doc);
            }

            if (options.maxFrames > 0 && printedFrames >= options.maxFrames && sawResponse) {
                return exitCode;
            }
        }

        const ssize_t n = ::read(fd, buf.data(), buf.size());
        if (n == 0) {
            break;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            err << "read failed: " << std::strerror(errno) << "\n";
            return 2;
        }

        if (const auto framingErr =
                decoder.feed(std::span<const std::byte>(buf.data(), static_cast<size_t>(n)));
            framingErr.has_value()) {
            err << "framing error: " << framingErr->message << "\n";
            return 2;
        }
    }

    if (!sawResponse) {
        err << "connection closed without a response\n";
        return 1;
    }
    return exitCode;
}

} // namespace SucreSnortCtl


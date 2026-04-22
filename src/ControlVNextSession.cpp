/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextSession.hpp>

#include <ControlVNextCodec.hpp>
#include <ControlVNextSessionCommands.hpp>
#include <sucre-snort.hpp>

#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace {

class UniqueFd {
public:
    explicit UniqueFd(const int fd) : _fd(fd) {}

    ~UniqueFd() { reset(); }

    UniqueFd(const UniqueFd &) = delete;
    UniqueFd &operator=(const UniqueFd &) = delete;

    UniqueFd(UniqueFd &&other) noexcept : _fd(std::exchange(other._fd, -1)) {}

    UniqueFd &operator=(UniqueFd &&other) noexcept {
        if (this != &other) {
            reset(std::exchange(other._fd, -1));
        }
        return *this;
    }

    [[nodiscard]] int get() const { return _fd; }

    void reset(const int fd = -1) {
        if (_fd >= 0) {
            ::close(_fd);
        }
        _fd = fd;
    }

private:
    int _fd = -1;
};

[[nodiscard]] bool writeAll(const int fd, const std::string_view data) {
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

[[nodiscard]] rapidjson::Value makeString(const std::string_view value,
                                         rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out;
    out.SetString(value.data(), static_cast<rapidjson::SizeType>(value.size()), alloc);
    return out;
}

[[nodiscard]] uint32_t bestEffortRequestId(const rapidjson::Value &root) {
    if (!root.IsObject()) {
        return 0;
    }
    const auto it = root.FindMember("id");
    if (it == root.MemberEnd() || !it->value.IsUint()) {
        return 0;
    }
    return it->value.GetUint();
}

} // namespace

ControlVNextSession::ControlVNextSession(const int fd, const Limits limits)
    : _fd(fd), _limits(limits) {}

ControlVNextSession::~ControlVNextSession() {
    if (_fd >= 0) {
        ::close(_fd);
    }
}

void ControlVNextSession::run() {
    UniqueFd sock(std::exchange(_fd, -1));
    ControlVNext::NetstringDecoder decoder(_limits.maxRequestBytes);

    // Apply a receive timeout so that completely idle clients do not pin a thread forever.
    {
        const timeval tv{.tv_sec = 15 * 60, .tv_usec = 0};
        if (setsockopt(sock.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            const int err = errno;
            LOG(ERROR) << __FUNCTION__ << " - vNext control socket SO_RCVTIMEO error: "
                       << std::strerror(err);
        }
    }

    const auto sendResponse = [&](const rapidjson::Document &doc) -> bool {
        const std::string json = ControlVNext::encodeJson(doc, ControlVNext::JsonFormat::Compact);
        if (json.size() > _limits.maxResponseBytes) {
            return false;
        }
        const std::string frame = ControlVNext::encodeNetstring(json);
        if (frame.empty()) {
            return false;
        }
        return writeAll(sock.get(), frame);
    };

    using ResponsePlan = ControlVNextSessionCommands::ResponsePlan;

    const auto dispatch = [&](const ControlVNext::RequestView &request) -> ResponsePlan {
        const uint32_t id = request.id;
        const rapidjson::Value &args = *request.args;

        const auto requireEmptyArgs =
            [&](const std::string_view cmd) -> std::optional<rapidjson::Document> {
            if (const auto unknown = ControlVNext::findUnknownKey(args, {}); unknown.has_value()) {
                return ControlVNext::makeErrorResponse(
                    id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
            }
            (void)cmd;
            return std::nullopt;
        };

        if (request.cmd == "HELLO") {
            if (auto err = requireEmptyArgs("HELLO"); err.has_value()) {
                return ResponsePlan{.response = std::move(*err)};
            }

            rapidjson::Document result(rapidjson::kObjectType);
            auto &alloc = result.GetAllocator();
            result.AddMember("protocol", makeString("control-vnext", alloc), alloc);
            result.AddMember("protocolVersion", 1, alloc);
            result.AddMember("framing", makeString("netstring", alloc), alloc);
            result.AddMember("maxRequestBytes", static_cast<uint64_t>(_limits.maxRequestBytes), alloc);
            result.AddMember("maxResponseBytes", static_cast<uint64_t>(_limits.maxResponseBytes), alloc);

            rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
            return ResponsePlan{.response = std::move(response)};
        }

        if (request.cmd == "QUIT") {
            if (auto err = requireEmptyArgs("QUIT"); err.has_value()) {
                return ResponsePlan{.response = std::move(*err)};
            }

            rapidjson::Document response = ControlVNext::makeOkResponse(id, nullptr);
            return ResponsePlan{.response = std::move(response), .closeAfterWrite = true};
        }
        if (auto plan = ControlVNextSessionCommands::handleDaemonCommand(request, _limits); plan.has_value()) {
            return std::move(*plan);
        }
        if (auto plan = ControlVNextSessionCommands::handleDomainCommand(request, _limits); plan.has_value()) {
            return std::move(*plan);
        }
        if (auto plan = ControlVNextSessionCommands::handleIpRulesCommand(request, _limits); plan.has_value()) {
            return std::move(*plan);
        }
        if (auto plan = ControlVNextSessionCommands::handleMetricsCommand(request, _limits); plan.has_value()) {
            return std::move(*plan);
        }

        rapidjson::Document response = ControlVNext::makeErrorResponse(
            id, "UNSUPPORTED_COMMAND", "unsupported cmd: " + std::string(request.cmd));
        return ResponsePlan{.response = std::move(response)};
    };

    std::array<std::byte, 4096> buf{};
    for (;;) {
        while (const auto payload = decoder.pop()) {
            rapidjson::Document requestDoc;
            ControlVNext::JsonError jsonError;
            if (!ControlVNext::parseStrictJsonObject(*payload, requestDoc, jsonError)) {
                const rapidjson::Document response = ControlVNext::makeErrorResponse(
                    0, "SYNTAX_ERROR",
                    "JSON parse failed at offset " + std::to_string(jsonError.offset) + ": " +
                        jsonError.message);
                if (!sendResponse(response)) {
                    return;
                }
                continue;
            }

            const uint32_t id = bestEffortRequestId(requestDoc);
            ControlVNext::RequestView requestView;
            if (const auto envErr = ControlVNext::parseRequestEnvelope(requestDoc, requestView);
                envErr.has_value()) {
                const rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, envErr->code, envErr->message);
                if (!sendResponse(response)) {
                    return;
                }
                continue;
            }

            ResponsePlan plan{};
            const auto applyCommand = [&] { plan = dispatch(requestView); };
            if (requestView.cmd == "RESETALL" || requestView.cmd == "CONFIG.SET" ||
                requestView.cmd == "DOMAINRULES.APPLY" || requestView.cmd == "DOMAINPOLICY.APPLY" ||
                requestView.cmd == "DOMAINLISTS.APPLY" || requestView.cmd == "DOMAINLISTS.IMPORT" ||
                requestView.cmd == "IPRULES.APPLY" || requestView.cmd == "METRICS.RESET") {
                const std::lock_guard lock(mutexListeners);
                applyCommand();
            } else {
                const std::shared_lock<std::shared_mutex> lock(mutexListeners);
                applyCommand();
            }

            if (!sendResponse(plan.response)) {
                return;
            }
            if (plan.closeAfterWrite) {
                return;
            }
        }

        const ssize_t n = ::read(sock.get(), buf.data(), buf.size());
        if (n == 0) {
            return;
        }
        if (n < 0) {
            const int err = errno;
            if (err == EINTR) {
                continue;
            }
            if (err == EAGAIN || err == EWOULDBLOCK) {
                LOG(WARNING) << __FUNCTION__ << " - idle vNext control client timeout, closing";
            }
            return;
        }

        if (const auto framingErr = decoder.feed(
                std::span<const std::byte>(buf.data(), static_cast<size_t>(n)));
            framingErr.has_value()) {
            // Includes len > maxRequestBytes (FrameTooLarge) and other framing errors.
            return;
        }
    }
}

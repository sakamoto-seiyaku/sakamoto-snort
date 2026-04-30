/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextSession.hpp>

#include <ControlVNextCodec.hpp>
#include <ControlVNextSessionCommands.hpp>
#include <ControlVNextStreamJson.hpp>
#include <ControlVNextStreamManager.hpp>
#include <Settings.hpp>
#include <sucre-snort.hpp>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#ifndef SUCRE_SNORT_DAEMON_BUILD_ID
#define SUCRE_SNORT_DAEMON_BUILD_ID "host-dev"
#endif

#ifndef SUCRE_SNORT_ARTIFACT_ABI
#define SUCRE_SNORT_ARTIFACT_ABI "host"
#endif

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

class FrameWriter {
public:
    explicit FrameWriter(const int fd) : _fd(fd) {}

    FrameWriter(const FrameWriter &) = delete;
    FrameWriter &operator=(const FrameWriter &) = delete;

    void clearQueue() { _queue.clear(); }

    [[nodiscard]] bool hasPending() const { return !_current.empty() || !_queue.empty(); }

    [[nodiscard]] size_t queuedFrames() const { return _queue.size() + (!_current.empty() ? 1u : 0u); }

    void enqueue(std::string frame) { _queue.push_back(std::move(frame)); }

    // Flush queued frames using non-blocking writes.
    // Returns false on fatal write error.
    [[nodiscard]] bool flushOnce() {
        for (;;) {
            if (_current.empty()) {
                if (_queue.empty()) {
                    return true;
                }
                _current = std::move(_queue.front());
                _queue.pop_front();
                _offset = 0;
            }

            const ssize_t n = ::write(_fd, _current.data() + _offset, _current.size() - _offset);
            if (n > 0) {
                _offset += static_cast<size_t>(n);
                if (_offset >= _current.size()) {
                    _current.clear();
                    _offset = 0;
                }
                continue;
            }
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return true;
            }
            return false;
        }
    }

private:
    int _fd = -1;
    std::deque<std::string> _queue;
    std::string _current;
    size_t _offset = 0;
};

[[nodiscard]] rapidjson::Value makeString(const std::string_view value,
                                         rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out;
    out.SetString(value.data(), static_cast<rapidjson::SizeType>(value.size()), alloc);
    return out;
}

[[nodiscard]] rapidjson::Value makeCapabilities(rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value capabilities(rapidjson::kArrayType);
    for (const std::string_view capability :
         {"control-vnext", "nfqueue-datapath", "apk-native-artifact"}) {
        capabilities.PushBack(makeString(capability, alloc), alloc);
    }
    return capabilities;
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

ControlVNextSession::ControlVNextSession(const int fd, const Limits limits,
                                         const std::optional<bool> canPassFdOverride)
    : _fd(fd), _limits(limits), _canPassFdOverride(canPassFdOverride) {}

ControlVNextSession::~ControlVNextSession() {
    if (_fd >= 0) {
        ::close(_fd);
    }
}

void ControlVNextSession::run() {
    UniqueFd sock(std::exchange(_fd, -1));
    ControlVNext::NetstringDecoder decoder(_limits.maxRequestBytes);

    // Non-blocking I/O so stream writers can apply backpressure policies.
    {
        const int flags = ::fcntl(sock.get(), F_GETFL, 0);
        if (flags >= 0) {
            (void)::fcntl(sock.get(), F_SETFL, flags | O_NONBLOCK);
        }
    }

    bool canPassFd = _canPassFdOverride.value_or(false);
    if (!_canPassFdOverride.has_value()) {
        // Best-effort detection. Some host sandboxes may deny getsockopt/getsockname; in that case
        // we conservatively treat the session as non-fd-capable.
        int domain = 0;
        socklen_t len = sizeof(domain);
        if (::getsockopt(sock.get(), SOL_SOCKET, SO_DOMAIN, &domain, &len) == 0) {
            canPassFd = (domain == AF_UNIX);
        }
    }

    FrameWriter writer(sock.get());
    std::optional<std::chrono::steady_clock::time_point> pendingWriteSince;

    const auto pendingWriteWithinDeadline = [&]() -> bool {
        if (!writer.hasPending()) {
            pendingWriteSince = std::nullopt;
            return true;
        }
        const auto now = std::chrono::steady_clock::now();
        if (!pendingWriteSince.has_value()) {
            pendingWriteSince = now;
            return true;
        }
        return now - *pendingWriteSince <= snortControlSendDeadline;
    };

    const auto pendingWritePollTimeout = [&](const int defaultTimeoutMs) -> int {
        if (!pendingWriteSince.has_value()) {
            return defaultTimeoutMs;
        }
        const auto deadline = *pendingWriteSince + snortControlSendDeadline;
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return 0;
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        return static_cast<int>(std::min<std::int64_t>(defaultTimeoutMs, remaining));
    };

    const auto enqueueFrame = [&](const std::string_view json) -> bool {
        if (json.size() > _limits.maxResponseBytes) {
            return false;
        }
        std::string frame = ControlVNext::encodeNetstring(json);
        if (frame.empty()) {
            return false;
        }
        writer.enqueue(std::move(frame));
        (void)pendingWriteWithinDeadline();
        return true;
    };

    const auto enqueueDoc = [&](const rapidjson::Document &doc) -> bool {
        const std::string json = ControlVNext::encodeJson(doc, ControlVNext::JsonFormat::Compact);
        return enqueueFrame(json);
    };

    const auto flushBlocking = [&](const int timeoutMs) -> bool {
        while (writer.hasPending()) {
            if (!writer.flushOnce()) {
                return false;
            }
            if (!writer.hasPending()) {
                break;
            }
            if (!pendingWriteWithinDeadline()) {
                return false;
            }
            const int pollTimeoutMs = pendingWritePollTimeout(timeoutMs);
            if (pollTimeoutMs <= 0) {
                return false;
            }
            pollfd pfd{.fd = sock.get(), .events = POLLOUT | POLLHUP, .revents = 0};
            const int rc = ::poll(&pfd, 1, pollTimeoutMs);
            if (rc <= 0) {
                continue;
            }
            if (pfd.revents & POLLHUP) {
                return false;
            }
        }
        return true;
    };

    const auto sendFrameWithFdBlocking = [&](const std::string &frame, const int fdToSend) -> bool {
        if (fdToSend < 0) {
            return false;
        }
        if (frame.empty()) {
            return false;
        }

        const auto start = std::chrono::steady_clock::now();
        size_t offset = 0;
        bool sentControl = false;
        while (offset < frame.size()) {
            const auto now = std::chrono::steady_clock::now();
            if (now - start > snortControlSendDeadline) {
                return false;
            }

            iovec iov{};
            iov.iov_base = const_cast<char *>(frame.data() + offset);
            iov.iov_len = frame.size() - offset;

            msghdr msg{};
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            std::array<char, CMSG_SPACE(sizeof(int))> control{};
            if (!sentControl) {
                msg.msg_control = control.data();
                msg.msg_controllen = control.size();

                cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(int));
                std::memcpy(CMSG_DATA(cmsg), &fdToSend, sizeof(int));
            }

            const ssize_t n = ::sendmsg(sock.get(), &msg, 0);
            if (n > 0) {
                offset += static_cast<size_t>(n);
                sentControl = true;
                continue;
            }
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                pollfd pfd{.fd = sock.get(), .events = POLLOUT | POLLHUP, .revents = 0};
                const int rc = ::poll(&pfd, 1, /*timeoutMs=*/50);
                if (rc <= 0) {
                    continue;
                }
                if (pfd.revents & POLLHUP) {
                    return false;
                }
                continue;
            }
            return false;
        }
        return true;
    };

    using ResponsePlan = ControlVNextSessionCommands::ResponsePlan;
    void *sessionKey = this;
    std::optional<ControlVNextStreamManager::Type> activeStream = std::nullopt;
    std::optional<std::pair<ControlVNextStreamManager::Type, ControlVNextStreamManager::StartResult>>
        pendingStartedNotice = std::nullopt;

    struct StreamDetachGuard {
        void *key = nullptr;
        ~StreamDetachGuard() { controlVNextStream.detach(key); }
    } streamDetachGuard{sessionKey};

    struct StreamNoticeState {
        TrafficSnapshot suppressed{};
        std::uint64_t dropped = 0;
        std::chrono::steady_clock::time_point lastSuppressedSent{};
        std::chrono::steady_clock::time_point lastDroppedSent{};
    };
    StreamNoticeState notices;

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

        if (activeStream.has_value()) {
            if (request.cmd != "STREAM.START" && request.cmd != "STREAM.STOP") {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "STATE_CONFLICT", "connection is in stream mode");
                return ResponsePlan{.response = std::move(response)};
            }
        }

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
            result.AddMember("daemonBuildId", makeString(SUCRE_SNORT_DAEMON_BUILD_ID, alloc), alloc);
            result.AddMember("artifactAbi", makeString(SUCRE_SNORT_ARTIFACT_ABI, alloc), alloc);
            result.AddMember("capabilities", makeCapabilities(alloc), alloc);

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

        if (request.cmd == "STREAM.START") {
            if (activeStream.has_value()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "STATE_CONFLICT", "stream already started");
                return ResponsePlan{.response = std::move(response)};
            }

            if (const auto unknown = ControlVNext::findUnknownKey(args, {"type", "horizonSec", "minSize"});
                unknown.has_value()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
                return ResponsePlan{.response = std::move(response)};
            }

            const auto typeIt = args.FindMember("type");
            if (typeIt == args.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.type");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!typeIt->value.IsString()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.type must be string");
                return ResponsePlan{.response = std::move(response)};
            }

            const std::string_view type(typeIt->value.GetString(), typeIt->value.GetStringLength());
            ControlVNextStreamManager::Type streamType{};
            if (type == "dns") {
                streamType = ControlVNextStreamManager::Type::Dns;
            } else if (type == "pkt") {
                streamType = ControlVNextStreamManager::Type::Pkt;
            } else if (type == "activity") {
                streamType = ControlVNextStreamManager::Type::Activity;
            } else {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "invalid stream type");
                return ResponsePlan{.response = std::move(response)};
            }

            ControlVNextStreamManager::StartParams params{
                .type = streamType,
                .horizonSec = 0,
                .minSize = 0,
                .blockEnabled = settings.blockEnabled(),
            };

            if (streamType == ControlVNextStreamManager::Type::Dns ||
                streamType == ControlVNextStreamManager::Type::Pkt) {
                if (const auto it = args.FindMember("horizonSec"); it != args.MemberEnd()) {
                    if (!it->value.IsUint()) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "args.horizonSec must be u32");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    params.horizonSec = it->value.GetUint();
                }
                if (const auto it = args.FindMember("minSize"); it != args.MemberEnd()) {
                    if (!it->value.IsUint()) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "args.minSize must be u32");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    params.minSize = it->value.GetUint();
                }
            } else {
                if (args.HasMember("horizonSec") || args.HasMember("minSize")) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "SYNTAX_ERROR", "activity stream must not include horizonSec/minSize");
                    return ResponsePlan{.response = std::move(response)};
                }
            }

            ControlVNextStreamManager::StartResult startResult{};
            if (!controlVNextStream.start(sessionKey, params, startResult)) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "STATE_CONFLICT", "stream type already subscribed");
                return ResponsePlan{.response = std::move(response)};
            }

            activeStream = streamType;
            pendingStartedNotice = std::make_pair(streamType, startResult);
            notices.suppressed = TrafficSnapshot{};
            notices.dropped = 0;
            const auto now = std::chrono::steady_clock::now();
            notices.lastSuppressedSent = now;
            notices.lastDroppedSent = now;

            rapidjson::Document response = ControlVNext::makeOkResponse(id, nullptr);
            return ResponsePlan{.response = std::move(response)};
        }

        if (request.cmd == "STREAM.STOP") {
            if (auto err = requireEmptyArgs("STREAM.STOP"); err.has_value()) {
                return ResponsePlan{.response = std::move(*err)};
            }

            if (activeStream.has_value()) {
                // Ack barrier: drop any queued events/notices before sending STOP response.
                writer.clearQueue();
                controlVNextStream.stop(sessionKey);
                activeStream = std::nullopt;
                pendingStartedNotice = std::nullopt;
                notices.suppressed = TrafficSnapshot{};
                notices.dropped = 0;
            }

            rapidjson::Document response = ControlVNext::makeOkResponse(id, nullptr);
            return ResponsePlan{.response = std::move(response)};
        }

        if (auto plan = ControlVNextSessionCommands::handleDaemonCommand(request, _limits); plan.has_value()) {
            return std::move(*plan);
        }
        if (auto plan = ControlVNextSessionCommands::handleTelemetryCommand(request, _limits, sessionKey, canPassFd);
            plan.has_value()) {
            return std::move(*plan);
        }
        if (auto plan = ControlVNextSessionCommands::handleDomainCommand(request, _limits); plan.has_value()) {
            return std::move(*plan);
        }
        if (auto plan = ControlVNextSessionCommands::handleIpRulesCommand(request, _limits); plan.has_value()) {
            return std::move(*plan);
        }
        if (auto plan = ControlVNextSessionCommands::handleCheckpointCommand(request, _limits);
            plan.has_value()) {
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
    auto lastRead = std::chrono::steady_clock::now();
    for (;;) {
        while (const auto payload = decoder.pop()) {
            rapidjson::Document requestDoc;
            ControlVNext::JsonError jsonError;
            if (!ControlVNext::parseStrictJsonObject(*payload, requestDoc, jsonError)) {
                const rapidjson::Document response = ControlVNext::makeErrorResponse(
                    0, "SYNTAX_ERROR",
                    "JSON parse failed at offset " + std::to_string(jsonError.offset) + ": " +
                        jsonError.message);
                if (!enqueueDoc(response) || !flushBlocking(/*timeoutMs=*/250)) {
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
                if (!enqueueDoc(response) || !flushBlocking(/*timeoutMs=*/250)) {
                    return;
                }
                continue;
            }

            ResponsePlan plan{};
            const auto applyCommand = [&] { plan = dispatch(requestView); };
            if (requestView.cmd == "RESETALL" || requestView.cmd == "CHECKPOINT.LIST" ||
                requestView.cmd == "CHECKPOINT.SAVE" ||
                requestView.cmd == "CHECKPOINT.RESTORE" || requestView.cmd == "CHECKPOINT.CLEAR") {
                applyCommand();
            } else if (requestView.cmd == "CONFIG.SET" || requestView.cmd == "DOMAINRULES.APPLY" ||
                requestView.cmd == "DOMAINPOLICY.APPLY" ||
                requestView.cmd == "DOMAINLISTS.APPLY" || requestView.cmd == "DOMAINLISTS.IMPORT" ||
                requestView.cmd == "IPRULES.APPLY" || requestView.cmd == "METRICS.RESET" ||
                requestView.cmd == "TELEMETRY.OPEN" || requestView.cmd == "TELEMETRY.CLOSE") {
                const std::lock_guard<std::mutex> lock(mutexControlMutations);
                applyCommand();
            } else {
                const std::shared_lock<std::shared_mutex> lock(mutexListeners);
                applyCommand();
            }

            if (plan.fdToSend.valid()) {
                // Ensure any previously queued frames are flushed before sendmsg.
                if (!flushBlocking(/*timeoutMs=*/250)) {
                    return;
                }
                const std::string json =
                    ControlVNext::encodeJson(plan.response, ControlVNext::JsonFormat::Compact);
                if (json.size() > _limits.maxResponseBytes) {
                    return;
                }
                const std::string frame = ControlVNext::encodeNetstring(json);
                if (!sendFrameWithFdBlocking(frame, plan.fdToSend.get())) {
                    return;
                }
            } else {
                if (!enqueueDoc(plan.response) || !flushBlocking(/*timeoutMs=*/250)) {
                    return;
                }
            }

            // STREAM.START ordering: response → started notice.
            if (pendingStartedNotice.has_value()) {
                const auto [stream, startResult] = std::move(*pendingStartedNotice);
                pendingStartedNotice = std::nullopt;
                rapidjson::Document notice = ControlVNextStreamJson::makeStartedNotice(
                    stream, startResult.effectiveHorizonSec, startResult.effectiveMinSize);
                if (!enqueueDoc(notice) || !flushBlocking(/*timeoutMs=*/250)) {
                    return;
                }
            }

            if (plan.closeAfterWrite) {
                return;
            }
        }

        if (activeStream.has_value() &&
            !controlVNextStream.ownsSubscription(sessionKey, *activeStream)) {
            return;
        }

        // Stream writer: enqueue pending events + per-second notices (best-effort).
            if (activeStream.has_value()) {
                const auto stream = *activeStream;
                if (stream == ControlVNextStreamManager::Type::Dns || stream == ControlVNextStreamManager::Type::Pkt) {
                // Accumulate counters from hot path.
                const TrafficSnapshot delta = controlVNextStream.takeSuppressedTraffic(stream);
                for (size_t i = 0; i < notices.suppressed.dims.size(); ++i) {
                    notices.suppressed.dims[i].allow += delta.dims[i].allow;
                    notices.suppressed.dims[i].block += delta.dims[i].block;
                }
                notices.dropped += controlVNextStream.takeDroppedEvents(stream);

                const auto now = std::chrono::steady_clock::now();
                const auto suppressedElapsed =
                    std::chrono::duration_cast<std::chrono::milliseconds>(now - notices.lastSuppressedSent);
                if (suppressedElapsed.count() >= 1000) {
                    bool hasSuppressed = false;
                    for (const auto &c : notices.suppressed.dims) {
                        if (c.allow != 0 || c.block != 0) {
                            hasSuppressed = true;
                            break;
                        }
                    }
                    if (hasSuppressed) {
                        rapidjson::Document notice = ControlVNextStreamJson::makeSuppressedNotice(
                            stream, static_cast<std::uint32_t>(suppressedElapsed.count()), notices.suppressed);
                        if (!enqueueDoc(notice)) {
                            return;
                        }
                        notices.suppressed = TrafficSnapshot{};
                    }
                    notices.lastSuppressedSent = now;
                }

                const auto droppedElapsed =
                    std::chrono::duration_cast<std::chrono::milliseconds>(now - notices.lastDroppedSent);
                if (droppedElapsed.count() >= 1000) {
                    if (notices.dropped != 0) {
                        rapidjson::Document notice = ControlVNextStreamJson::makeDroppedNotice(
                            stream, static_cast<std::uint32_t>(droppedElapsed.count()), notices.dropped);
                        if (!enqueueDoc(notice)) {
                            return;
                        }
                        notices.dropped = 0;
                    }
                    notices.lastDroppedSent = now;
                }
            }

            // Drain pending events while we have room to queue frames.
            constexpr size_t kMaxQueuedFrames = 128;
            const size_t queued = writer.queuedFrames();
            const size_t budget = queued >= kMaxQueuedFrames ? 0u : (kMaxQueuedFrames - queued);
            for (size_t emitted = 0; emitted < budget; ++emitted) {
                if (!activeStream.has_value()) {
                    break;
                }
                const auto st = *activeStream;
                rapidjson::Document eventDoc;
                bool hasEvent = false;
                if (st == ControlVNextStreamManager::Type::Dns) {
                    if (auto ev = controlVNextStream.popDnsPending(sessionKey)) {
                        eventDoc = ControlVNextStreamJson::makeDnsEvent(*ev);
                        hasEvent = true;
                    }
                } else if (st == ControlVNextStreamManager::Type::Pkt) {
                    if (auto ev = controlVNextStream.popPktPending(sessionKey)) {
                        eventDoc = ControlVNextStreamJson::makePktEvent(*ev);
                        hasEvent = true;
                    }
                } else if (st == ControlVNextStreamManager::Type::Activity) {
                    if (auto ev = controlVNextStream.popActivityPending(sessionKey)) {
                        eventDoc = ControlVNextStreamJson::makeActivityEvent(*ev);
                        hasEvent = true;
                    }
                }

                if (!hasEvent) {
                    break;
                }

                if (!enqueueDoc(eventDoc)) {
                    return;
                }
            }
        }

        if (!writer.flushOnce()) {
            return;
        }
        if (!pendingWriteWithinDeadline()) {
            return;
        }

        short events = POLLIN | POLLHUP;
        if (writer.hasPending()) {
            events |= POLLOUT;
        }

        int timeoutMs = -1;
        if (activeStream.has_value()) {
            timeoutMs = 100;
        } else {
            constexpr auto idle = std::chrono::minutes(15);
            const auto now = std::chrono::steady_clock::now();
            const auto elapsed = now - lastRead;
            if (elapsed >= idle) {
                return;
            }
            const auto remaining = idle - elapsed;
            timeoutMs = static_cast<int>(
                std::min<std::int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(remaining).count(),
                                       15LL * 60 * 1000));
        }

        if (writer.hasPending()) {
            const int pendingTimeoutMs = pendingWritePollTimeout(timeoutMs);
            if (pendingTimeoutMs <= 0) {
                return;
            }
            timeoutMs = std::min(timeoutMs, pendingTimeoutMs);
        }

        pollfd pfd{.fd = sock.get(), .events = events, .revents = 0};
        const int pret = ::poll(&pfd, 1, timeoutMs);
        if (pret < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (pret == 0) {
            continue;
        }
        if (pfd.revents & POLLHUP) {
            return;
        }

        if (pfd.revents & POLLIN) {
            for (;;) {
                const ssize_t n = ::read(sock.get(), buf.data(), buf.size());
                if (n == 0) {
                    return;
                }
                if (n < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    }
                    return;
                }
                lastRead = std::chrono::steady_clock::now();

                if (const auto framingErr = decoder.feed(std::span<const std::byte>(
                        buf.data(), static_cast<size_t>(n)));
                    framingErr.has_value()) {
                    return;
                }
            }
        }

        if (pfd.revents & POLLOUT) {
            if (!writer.flushOnce()) {
                return;
            }
        }
    }
}

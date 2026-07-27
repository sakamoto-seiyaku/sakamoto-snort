/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueuePassThroughRuntime.hpp>

#include <DaemonRuntime.hpp>
#include <NfqueueHookInstaller.hpp>
#include <NfqueuePacketLeaseAdapter.hpp>
#include <NfqueuePassThrough.hpp>

#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr int kQueuePollTimeoutMs = 250;

class SystemHookCommandExecutor final : public SnortDatapath::Nfqueue::HookCommandExecutor {
public:
    bool execute(const SnortDatapath::Nfqueue::IptablesCommand &command) override {
        std::vector<std::string> argvStorage;
        argvStorage.reserve(command.args.size() + 1);
        argvStorage.push_back(command.executable);
        argvStorage.insert(argvStorage.end(), command.args.begin(), command.args.end());

        std::vector<char *> argv;
        argv.reserve(argvStorage.size() + 1);
        for (auto &arg : argvStorage) {
            argv.push_back(arg.data());
        }
        argv.push_back(nullptr);

        const pid_t pid = ::fork();
        if (pid < 0) {
            std::cerr << "iptables fork failed: " << std::strerror(errno) << "\n";
            return false;
        }
        if (pid == 0) {
            ::execv(command.executable.c_str(), argv.data());
            static const char msg[] = "sucre-snort: iptables execv failed\n";
            (void)!::write(STDERR_FILENO, msg, sizeof(msg) - 1);
            _exit(127);
        }

        int status = 0;
        while (::waitpid(pid, &status, 0) < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "iptables waitpid failed: " << std::strerror(errno) << "\n";
            return false;
        }
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
};

class SocketVerdictSink final
    : public SnortDatapath::Nfqueue::NfqueuePacketLeaseVerdictSink {
public:
    SocketVerdictSink(mnl_socket *socket, const std::uint32_t queue)
        : socket_(socket), queue_(queue) {}

    bool sendVerdict(
        const std::uint32_t packetId,
        const SnortDatapath::Nfqueue::NfqueuePacketLeaseVerdict verdict) override {
        std::vector<char> buffer(MNL_SOCKET_BUFFER_SIZE);
        nlmsghdr *nlh = nfq_nlmsg_put(buffer.data(), NFQNL_MSG_VERDICT, queue_);
        const auto kernelVerdict = verdict
            == SnortDatapath::Nfqueue::NfqueuePacketLeaseVerdict::Accept
            ? SnortDatapath::Nfqueue::kNfAcceptVerdict
            : 0U;
        nfq_nlmsg_verdict_put(
            nlh, static_cast<int>(packetId), static_cast<int>(kernelVerdict));
        return mnl_socket_sendto(socket_, nlh, nlh->nlmsg_len) >= 0;
    }

private:
    mnl_socket *socket_ = nullptr;
    std::uint32_t queue_ = 0;
};

struct QueueContext {
    mnl_socket *socket = nullptr;
    std::uint32_t queue = 0;
    SnortDatapath::Nfqueue::NfqueueFlowAdapter *flowAdapter = nullptr;
    SnortDatapath::Nfqueue::NfqueuePacketLeaseAdapter *leaseAdapter = nullptr;
    SnortDatapath::Nfqueue::NfqueueRuntimeFaultCounters *runtimeFaults = nullptr;
};

int socketFamily(const SnortDatapath::Nfqueue::NfqueueAddressFamily family) {
    switch (family) {
    case SnortDatapath::Nfqueue::NfqueueAddressFamily::Ipv4:
        return AF_INET;
    case SnortDatapath::Nfqueue::NfqueueAddressFamily::Ipv6:
        return AF_INET6;
    }
    return AF_INET;
}

const char *familyName(const SnortDatapath::Nfqueue::NfqueueAddressFamily family) {
    switch (family) {
    case SnortDatapath::Nfqueue::NfqueueAddressFamily::Ipv4:
        return "IPv4";
    case SnortDatapath::Nfqueue::NfqueueAddressFamily::Ipv6:
        return "IPv6";
    }
    return "unknown";
}

bool sendConfigMessage(mnl_socket *socket, const nlmsghdr *nlh) {
    return mnl_socket_sendto(socket, nlh, nlh->nlmsg_len) >= 0;
}

bool configureQueue(mnl_socket *socket,
                    const SnortDatapath::Nfqueue::PassThroughListenerPlan plan,
                    const SnortDatapath::Nfqueue::NfqueueFlowAdapter &flowAdapter) {
    std::vector<char> buffer(MNL_SOCKET_BUFFER_SIZE);

    nlmsghdr *nlh = nfq_nlmsg_put(buffer.data(), NFQNL_MSG_CONFIG, plan.queue);
    nfq_nlmsg_cfg_put_cmd(nlh, socketFamily(plan.family), NFQNL_CFG_CMD_BIND);
    if (!sendConfigMessage(socket, nlh)) {
        return false;
    }

    nlh = nfq_nlmsg_put(buffer.data(), NFQNL_MSG_CONFIG, plan.queue);
    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET,
                             static_cast<int>(flowAdapter.copyPrefixBytes()));
    if (!sendConfigMessage(socket, nlh)) {
        return false;
    }

    nlh = nfq_nlmsg_put(buffer.data(), NFQNL_MSG_CONFIG, plan.queue);
    nfq_nlmsg_cfg_put_qmaxlen(nlh, static_cast<std::uint32_t>(flowAdapter.queueCapacity()));
    if (!sendConfigMessage(socket, nlh)) {
        return false;
    }

    nlh = nfq_nlmsg_put(buffer.data(), NFQNL_MSG_CONFIG, plan.queue);
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_FAIL_OPEN));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_FAIL_OPEN));
    return sendConfigMessage(socket, nlh);
}

int passThroughCallback(const nlmsghdr *nlh, void *data) {
    auto *context = static_cast<QueueContext *>(data);
    nlattr *attrs[NFQA_MAX + 1] = {};

    if (nfq_nlmsg_parse(nlh, attrs) < 0) {
        context->runtimeFaults->recordPacketParseFailure();
        std::cerr << "NFQUEUE parse failed on queue " << context->queue << "\n";
        return MNL_CB_ERROR;
    }
    if (attrs[NFQA_PACKET_HDR] == nullptr) {
        context->runtimeFaults->recordMissingPacketHeader();
        std::cerr << "NFQUEUE packet header missing on queue " << context->queue << "\n";
        return MNL_CB_OK;
    }

    const auto *header =
        static_cast<nfqnl_msg_packet_hdr *>(mnl_attr_get_payload(attrs[NFQA_PACKET_HDR]));
    const auto *payloadAttr = attrs[NFQA_PAYLOAD];
    const auto *payload = payloadAttr == nullptr
        ? static_cast<const std::uint8_t *>(nullptr)
        : static_cast<const std::uint8_t *>(mnl_attr_get_payload(payloadAttr));
    const auto payloadLength = payloadAttr == nullptr
        ? std::size_t{0}
        : static_cast<std::size_t>(mnl_attr_get_payload_len(payloadAttr));
    std::uint32_t originalLengthHint = 0;
    if (attrs[NFQA_CAP_LEN] != nullptr) {
        originalLengthHint = ntohl(mnl_attr_get_u32(attrs[NFQA_CAP_LEN]));
    }

    const auto packetId = ntohl(header->packet_id);
    const auto admission = context->leaseAdapter->admit(packetId);
    if (admission.status
        != SnortDatapath::Nfqueue::NfqueuePacketLeaseAdmissionStatus::Retained) {
        if (admission.status
            == SnortDatapath::Nfqueue::NfqueuePacketLeaseAdmissionStatus::CapacityFailOpen) {
            std::cerr << "NFQUEUE lease capacity fail-open on queue " << context->queue << "\n";
        }
        return MNL_CB_OK;
    }

    const std::span<const std::uint8_t> packetPayload(payload, payloadLength);
    const auto verdictFailuresBefore = context->leaseAdapter->counters().verdictSendFailures;
    const auto gateResult = context->flowAdapter->process(
        context->queue, header->hook, packetPayload, originalLengthHint);
    const auto terminalReason = gateResult
        == SnortDatapath::Nfqueue::NfqueueFlowAdapterResult::FlowAccepted
        ? SnortDatapath::Nfqueue::NfqueuePacketLeaseTerminalReason::Accepted
        : SnortDatapath::Nfqueue::NfqueuePacketLeaseTerminalReason::FailOpen;
    const auto completion = context->leaseAdapter->complete(
        *admission.identity, terminalReason);
    if (completion
        != SnortDatapath::Nfqueue::NfqueuePacketLeaseCompletionStatus::Completed) {
        std::cerr << "NFQUEUE lease completion rejected on queue " << context->queue << "\n";
    }
    if (context->leaseAdapter->counters().verdictSendFailures > verdictFailuresBefore) {
        context->flowAdapter->recordVerdictSendFailure();
        std::cerr << "NFQUEUE verdict send failed on queue " << context->queue << "\n";
    }
    if (gateResult != SnortDatapath::Nfqueue::NfqueueFlowAdapterResult::FlowAccepted) {
        std::cerr << "NFQUEUE flow gate fail-open on queue " << context->queue << "\n";
    }
    return MNL_CB_OK;
}

void listenQueue(const SnortDatapath::Nfqueue::PassThroughListenerPlan listener,
                 SnortDatapath::Nfqueue::NfqueueFlowAdapter &flowAdapter,
                 SnortDatapath::Nfqueue::NfqueueRuntimeFaultCounters &runtimeFaults) {
    std::uint32_t laneGeneration = 1;
    while (!SnortRuntime::shutdownRequested()) {
        mnl_socket *socket = mnl_socket_open(NETLINK_NETFILTER);
        if (socket == nullptr) {
            runtimeFaults.recordListenerOpenFailure();
            std::cerr << familyName(listener.family) << " NFQUEUE socket open failed: "
                      << std::strerror(errno) << "\n";
            sleep(1);
            continue;
        }

        if (mnl_socket_bind(socket, 0, MNL_SOCKET_AUTOPID) < 0) {
            runtimeFaults.recordListenerBindFailure();
            std::cerr << familyName(listener.family) << " NFQUEUE socket bind failed: "
                      << std::strerror(errno) << "\n";
            mnl_socket_close(socket);
            sleep(1);
            continue;
        }

        if (!configureQueue(socket, listener, flowAdapter)) {
            runtimeFaults.recordQueueConfigFailure();
            std::cerr << familyName(listener.family) << " NFQUEUE configure failed for queue "
                      << listener.queue << ": " << std::strerror(errno) << "\n";
            mnl_socket_close(socket);
            sleep(1);
            continue;
        }

        int noEnobufs = 1;
        (void)mnl_socket_setsockopt(socket, NETLINK_NO_ENOBUFS, &noEnobufs, sizeof(noEnobufs));

        SocketVerdictSink sink(socket, listener.queue);
        SnortDatapath::Nfqueue::NfqueuePacketLeaseAdapter leaseAdapter(
            SnortDatapath::Nfqueue::NfqueuePacketLeaseAdapterConfig{
                .pendingCapacity = flowAdapter.queueCapacity(),
                .laneGeneration = laneGeneration,
                .queueNumber = listener.queue,
            },
            sink);
        QueueContext context{
            .socket = socket,
            .queue = listener.queue,
            .flowAdapter = &flowAdapter,
            .leaseAdapter = &leaseAdapter,
            .runtimeFaults = &runtimeFaults,
        };
        const unsigned int port = mnl_socket_get_portid(socket);
        std::vector<char> buffer(MNL_SOCKET_BUFFER_SIZE);
        pollfd pollFd{
            .fd = mnl_socket_get_fd(socket),
            .events = POLLIN,
            .revents = 0,
        };
        while (!SnortRuntime::shutdownRequested()) {
            pollFd.revents = 0;
            const int ready = ::poll(&pollFd, 1, kQueuePollTimeoutMs);
            if (ready < 0) {
                if (errno == EINTR) {
                    continue;
                }
                std::cerr << "NFQUEUE poll failed on queue " << listener.queue << ": "
                          << std::strerror(errno) << "\n";
                break;
            }
            if (ready == 0) {
                (void)leaseAdapter.expire(
                    SnortDatapath::Nfqueue::NfqueuePacketLeaseAdapter::Clock::now());
                continue;
            }
            if ((pollFd.revents & POLLIN) == 0) {
                std::cerr << "NFQUEUE poll closed on queue " << listener.queue << "\n";
                break;
            }

            const ssize_t received = mnl_socket_recvfrom(socket, buffer.data(), buffer.size());
            if (received < 0) {
                if (errno == EINTR) {
                    continue;
                }
                std::cerr << "NFQUEUE recv failed on queue " << listener.queue << ": "
                          << std::strerror(errno) << "\n";
                runtimeFaults.recordReceiveFailure();
                break;
            }
            if (mnl_cb_run(buffer.data(), static_cast<unsigned int>(received), 0, port,
                           passThroughCallback, &context) == -1) {
                runtimeFaults.recordCallbackFailure();
                std::cerr << "NFQUEUE callback failed on queue " << listener.queue << ": "
                          << std::strerror(errno) << "\n";
                break;
            }
        }

        (void)leaseAdapter.shutdown();
        mnl_socket_close(socket);
        laneGeneration = laneGeneration == std::numeric_limits<std::uint32_t>::max()
            ? 1U
            : laneGeneration + 1U;
    }
}

} // namespace

namespace SnortDatapath::Nfqueue {

DualStackPassThroughRuntime::DualStackPassThroughRuntime(DualStackPassThroughRuntimeConfig config)
    : config_(std::move(config)), flowAdapter_(config_.flowAdapter) {}

DualStackPassThroughRuntime::~DualStackPassThroughRuntime() {
    SnortRuntime::requestShutdown();
    ready_.store(false, std::memory_order_release);
    try {
        SystemHookCommandExecutor executor;
        const bool hooksRemoved = removeDualStackPassThroughHooks(
            HookCleanupPlanConfig{
                .inputChain = config_.inputChain,
                .outputChain = config_.outputChain,
            },
            executor);
        std::cerr << "Dual-stack NFQUEUE pass-through hook cleanup="
                  << (hooksRemoved ? "pass" : "fail") << "\n";
    } catch (const std::exception &e) {
        std::cerr << "Dual-stack NFQUEUE pass-through hook cleanup=fail: " << e.what() << "\n";
    } catch (...) {
        std::cerr << "Dual-stack NFQUEUE pass-through hook cleanup=fail: unknown exception\n";
    }
    workers_.join();
    const auto flowCounters = flowAdapter_.counters();
    const auto runtimeFaults = runtimeFaults_.snapshot();
    std::cerr << "Dual-stack NFQUEUE flow gate packets=" << flowCounters.packetsSeen
              << " accepted=" << flowCounters.acceptedPackets
              << " parse_pass=" << flowCounters.parsePassThroughPackets
              << " fragments=" << flowCounters.fragmentPassThroughPackets
              << " capacity_pass=" << flowCounters.capacityPassThroughPackets
              << " owner_fault=" << flowCounters.ownerFaultPassThroughPackets
              << " verdict_fail=" << flowCounters.verdictSendFailures
              << " listener_open_fail=" << runtimeFaults.listenerOpenFailures
              << " listener_bind_fail=" << runtimeFaults.listenerBindFailures
              << " queue_config_fail=" << runtimeFaults.queueConfigFailures
              << " packet_parse_fail=" << runtimeFaults.packetParseFailures
              << " receive_fail=" << runtimeFaults.receiveFailures
              << " callback_fail=" << runtimeFaults.callbackFailures << "\n";
}

bool DualStackPassThroughRuntime::start() {
    workers_.join();
    ready_.store(false, std::memory_order_release);
    const auto runtimePlan = makeDualStackPassThroughRuntimePlan(config_);

    SystemHookCommandExecutor executor;
    const bool hooksInstalled = installDualStackPassThroughHooks(runtimePlan.hookPlan, executor);
    if (!hooksInstalled) {
        std::cerr << "Dual-stack NFQUEUE hook install failed; listener startup skipped\n";
        ready_.store(false, std::memory_order_release);
        return false;
    }

    for (const auto listener : runtimePlan.listeners) {
        workers_.start([this, listener] {
            listenQueue(listener, flowAdapter_, runtimeFaults_);
        });
    }
    ready_.store(true, std::memory_order_release);

    std::cerr << "Dual-stack NFQUEUE pass-through listening on IPv4 queues "
              << runtimePlan.hookPlan.ipv4FirstQueue << ":"
              << (runtimePlan.hookPlan.ipv4FirstQueue + runtimePlan.hookPlan.queuesPerFamily - 1)
              << " and IPv6 queues " << runtimePlan.hookPlan.ipv6FirstQueue << ":"
              << (runtimePlan.hookPlan.ipv6FirstQueue + runtimePlan.hookPlan.queuesPerFamily - 1)
              << "\n";
    return true;
}

bool DualStackPassThroughRuntime::nfqueuePassThroughReady() const noexcept {
    return ready_.load(std::memory_order_acquire);
}

bool DualStackPassThroughRuntime::resetBaseRuntime() noexcept {
    try {
        const auto runtimePlan = makeDualStackPassThroughRuntimePlan(config_);
        SystemHookCommandExecutor executor;
        return installDualStackPassThroughHooks(runtimePlan.hookPlan, executor);
    } catch (const std::exception &e) {
        std::cerr << "Dual-stack NFQUEUE pass-through reset failed: " << e.what() << "\n";
    } catch (...) {
        std::cerr << "Dual-stack NFQUEUE pass-through reset failed: unknown exception\n";
    }
    return false;
}

Ipv4PassThroughRuntime::Ipv4PassThroughRuntime(Ipv4PassThroughRuntimeConfig config)
    : config_(std::move(config)), flowAdapter_(config_.flowAdapter) {}

Ipv4PassThroughRuntime::~Ipv4PassThroughRuntime() {
    SnortRuntime::requestShutdown();
    try {
        SystemHookCommandExecutor executor;
        const bool hooksRemoved = removeIpv4PassThroughHooks(
            HookCleanupPlanConfig{
                .inputChain = config_.inputChain,
                .outputChain = config_.outputChain,
            },
            executor);
        std::cerr << "IPv4 NFQUEUE pass-through hook cleanup="
                  << (hooksRemoved ? "pass" : "fail") << "\n";
    } catch (const std::exception &e) {
        std::cerr << "IPv4 NFQUEUE pass-through hook cleanup=fail: " << e.what() << "\n";
    } catch (...) {
        std::cerr << "IPv4 NFQUEUE pass-through hook cleanup=fail: unknown exception\n";
    }
    workers_.join();
    const auto flowCounters = flowAdapter_.counters();
    const auto runtimeFaults = runtimeFaults_.snapshot();
    std::cerr << "IPv4 NFQUEUE flow gate packets=" << flowCounters.packetsSeen
              << " accepted=" << flowCounters.acceptedPackets
              << " parse_pass=" << flowCounters.parsePassThroughPackets
              << " fragments=" << flowCounters.fragmentPassThroughPackets
              << " capacity_pass=" << flowCounters.capacityPassThroughPackets
              << " owner_fault=" << flowCounters.ownerFaultPassThroughPackets
              << " verdict_fail=" << flowCounters.verdictSendFailures
              << " listener_open_fail=" << runtimeFaults.listenerOpenFailures
              << " listener_bind_fail=" << runtimeFaults.listenerBindFailures
              << " queue_config_fail=" << runtimeFaults.queueConfigFailures
              << " packet_parse_fail=" << runtimeFaults.packetParseFailures
              << " receive_fail=" << runtimeFaults.receiveFailures
              << " callback_fail=" << runtimeFaults.callbackFailures << "\n";
}

bool Ipv4PassThroughRuntime::start() {
    workers_.join();
    const auto queuePlan =
        makeNfqueueQueuePlan(config_.topology, config_.firstQueue, config_.queueCount);

    SystemHookCommandExecutor executor;
    const bool hooksInstalled = installIpv4PassThroughHooks(
        HookPlanConfig{
            .inputChain = config_.inputChain,
            .outputChain = config_.outputChain,
            .queuePlan = queuePlan,
        },
        executor);
    if (!hooksInstalled) {
        std::cerr << "IPv4 NFQUEUE hook install failed; listener startup skipped\n";
        return false;
    }

    for (std::uint32_t i = 0; i < queuePlan.listeners.count; ++i) {
        workers_.start([this, queue = queuePlan.listeners.first + i] {
            listenQueue(PassThroughListenerPlan{
                .family = NfqueueAddressFamily::Ipv4,
                .queue = queue,
            }, flowAdapter_, runtimeFaults_);
        });
    }

    std::cerr << "IPv4 NFQUEUE pass-through listening on queues " << queuePlan.listeners.first
              << ":" << (queuePlan.listeners.first + queuePlan.listeners.count - 1) << "\n";
    return true;
}

} // namespace SnortDatapath::Nfqueue

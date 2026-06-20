/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueuePassThroughRuntime.hpp>

#include <DaemonRuntime.hpp>
#include <NfqueueHookInstaller.hpp>
#include <NfqueuePassThrough.hpp>

#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

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

class SocketVerdictSink final : public SnortDatapath::Nfqueue::VerdictSink {
public:
    SocketVerdictSink(mnl_socket *socket, const std::uint32_t queue)
        : socket_(socket), queue_(queue) {}

    bool sendVerdict(const std::uint32_t packetId, const std::uint32_t verdict) override {
        std::vector<char> buffer(MNL_SOCKET_BUFFER_SIZE);
        nlmsghdr *nlh = nfq_nlmsg_put(buffer.data(), NFQNL_MSG_VERDICT, queue_);
        nfq_nlmsg_verdict_put(nlh, static_cast<int>(packetId), static_cast<int>(verdict));
        return mnl_socket_sendto(socket_, nlh, nlh->nlmsg_len) >= 0;
    }

private:
    mnl_socket *socket_ = nullptr;
    std::uint32_t queue_ = 0;
};

struct QueueContext {
    mnl_socket *socket = nullptr;
    std::uint32_t queue = 0;
};

bool sendConfigMessage(mnl_socket *socket, const nlmsghdr *nlh) {
    return mnl_socket_sendto(socket, nlh, nlh->nlmsg_len) >= 0;
}

bool configureQueue(mnl_socket *socket, const std::uint32_t queue) {
    std::vector<char> buffer(MNL_SOCKET_BUFFER_SIZE);

    nlmsghdr *nlh = nfq_nlmsg_put(buffer.data(), NFQNL_MSG_CONFIG, queue);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);
    if (!sendConfigMessage(socket, nlh)) {
        return false;
    }

    nlh = nfq_nlmsg_put(buffer.data(), NFQNL_MSG_CONFIG, queue);
    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_META, 0);
    if (!sendConfigMessage(socket, nlh)) {
        return false;
    }

    nlh = nfq_nlmsg_put(buffer.data(), NFQNL_MSG_CONFIG, queue);
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_FAIL_OPEN));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_FAIL_OPEN));
    return sendConfigMessage(socket, nlh);
}

int passThroughCallback(const nlmsghdr *nlh, void *data) {
    auto *context = static_cast<QueueContext *>(data);
    nlattr *attrs[NFQA_MAX + 1] = {};

    if (nfq_nlmsg_parse(nlh, attrs) < 0) {
        std::cerr << "NFQUEUE parse failed on queue " << context->queue << "\n";
        return MNL_CB_ERROR;
    }
    if (attrs[NFQA_PACKET_HDR] == nullptr) {
        std::cerr << "NFQUEUE packet header missing on queue " << context->queue << "\n";
        return MNL_CB_OK;
    }

    const auto *header =
        static_cast<nfqnl_msg_packet_hdr *>(mnl_attr_get_payload(attrs[NFQA_PACKET_HDR]));
    SocketVerdictSink sink(context->socket, context->queue);
    const auto result = SnortDatapath::Nfqueue::acceptPassThroughEvent(
        SnortDatapath::Nfqueue::QueueEvent{.packetId = ntohl(header->packet_id)}, sink);
    if (result != SnortDatapath::Nfqueue::PassThroughResult::VerdictAccepted) {
        std::cerr << "NFQUEUE verdict send failed on queue " << context->queue << "\n";
    }
    return MNL_CB_OK;
}

void listenQueue(const std::uint32_t queue) {
    while (!SnortRuntime::shutdownRequested()) {
        mnl_socket *socket = mnl_socket_open(NETLINK_NETFILTER);
        if (socket == nullptr) {
            std::cerr << "NFQUEUE socket open failed: " << std::strerror(errno) << "\n";
            sleep(1);
            continue;
        }

        if (mnl_socket_bind(socket, 0, MNL_SOCKET_AUTOPID) < 0) {
            std::cerr << "NFQUEUE socket bind failed: " << std::strerror(errno) << "\n";
            mnl_socket_close(socket);
            sleep(1);
            continue;
        }

        if (!configureQueue(socket, queue)) {
            std::cerr << "NFQUEUE configure failed for queue " << queue << ": "
                      << std::strerror(errno) << "\n";
            mnl_socket_close(socket);
            sleep(1);
            continue;
        }

        int noEnobufs = 1;
        (void)mnl_socket_setsockopt(socket, NETLINK_NO_ENOBUFS, &noEnobufs, sizeof(noEnobufs));

        QueueContext context{.socket = socket, .queue = queue};
        const unsigned int port = mnl_socket_get_portid(socket);
        std::vector<char> buffer(MNL_SOCKET_BUFFER_SIZE);
        while (!SnortRuntime::shutdownRequested()) {
            const ssize_t received = mnl_socket_recvfrom(socket, buffer.data(), buffer.size());
            if (received < 0) {
                if (errno == EINTR) {
                    continue;
                }
                std::cerr << "NFQUEUE recv failed on queue " << queue << ": "
                          << std::strerror(errno) << "\n";
                break;
            }
            if (mnl_cb_run(buffer.data(), static_cast<unsigned int>(received), 0, port,
                           passThroughCallback, &context) == -1) {
                std::cerr << "NFQUEUE callback failed on queue " << queue << ": "
                          << std::strerror(errno) << "\n";
                break;
            }
        }

        mnl_socket_close(socket);
    }
}

} // namespace

namespace SnortDatapath::Nfqueue {

Ipv4PassThroughRuntime::Ipv4PassThroughRuntime(Ipv4PassThroughRuntimeConfig config)
    : config_(std::move(config)) {}

bool Ipv4PassThroughRuntime::start() {
    const auto queuePlan =
        makeNfqueueQueuePlan(config_.topology, config_.firstQueue, config_.queueCount);

    SystemHookCommandExecutor executor;
    (void)installIpv4PassThroughHooks(HookPlanConfig{
                                          .inputChain = config_.inputChain,
                                          .outputChain = config_.outputChain,
                                          .queuePlan = queuePlan,
                                      },
                                      executor);

    for (std::uint32_t i = 0; i < queuePlan.listeners.count; ++i) {
        std::thread([queue = queuePlan.listeners.first + i] { listenQueue(queue); }).detach();
    }

    std::cerr << "IPv4 NFQUEUE pass-through listening on queues " << queuePlan.listeners.first
              << ":" << (queuePlan.listeners.first + queuePlan.listeners.count - 1) << "\n";
    return true;
}

} // namespace SnortDatapath::Nfqueue

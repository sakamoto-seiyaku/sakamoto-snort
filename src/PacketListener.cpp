/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <thread>
#include <vector>

#include <CmdLine.hpp>
#include <PacketListener.hpp>

template <class IP> PacketListener<IP>::PacketListener() {}

template <class IP> PacketListener<IP>::~PacketListener() {}

template <class IP> void PacketListener<IP>::start() {
    uint32_t threads = std::thread::hardware_concurrency();
    if (threads < 4) {
        threads = 4;
    } else if (threads % 2 != 0) {
        ++threads;
    }

    if constexpr (std::is_same_v<IP, IPv4>) {
        _firstQueue = 0;
    } else {
        _firstQueue = threads;
    }

    _inputQueues = threads / 2;
    _outputQueues = threads / 2;

    CmdLine(IP::iptables, "-w", "-N", settings.inputChain).exec();
    CmdLine(IP::iptables, "-w", "-N", settings.outputChain).exec();
    CmdLine(IP::iptables, "-w", "-F", settings.inputChain).exec();
    CmdLine(IP::iptables, "-w", "-F", settings.outputChain).exec();
    CmdLine(IP::iptables, "-w", "-D", "INPUT", "-j", settings.inputChain).exec();
    CmdLine(IP::iptables, "-w", "-D", "OUTPUT", "-j", settings.outputChain).exec();
    CmdLine(IP::iptables, "-w", "-A", "INPUT", "-j", settings.inputChain).exec();
    CmdLine(IP::iptables, "-w", "-A", "OUTPUT", "-j", settings.outputChain).exec();
    CmdLine(IP::iptables, "-w", "-A", settings.inputChain, "-i", "lo", "-j", "RETURN").exec();
    CmdLine(IP::iptables, "-w", "-A", settings.outputChain, "-o", "lo", "-j", "RETURN").exec();

    for (const auto port : {"53", "853", "5353"}) {
        for (const auto proto : {"udp", "tcp"})
            for (const auto [chain, dir] : {std::make_tuple(settings.inputChain, "s"),
                                            std::make_tuple(settings.outputChain, "d")}) {
                CmdLine(IP::iptables, "-w", "-A", chain, "-p", proto,
                        std::string("--") + dir + "port", port, "-j", "RETURN")
                    .exec();
            }
    }

    const auto rule = [&](const std::string &&chain, const uint32_t firstq, const uint32_t nbq) {
        CmdLine cmd(IP::iptables, "-w", "-A", chain, "-j", "NFQUEUE", "--queue-bypass");
        if (nbq == 1) {
            cmd.add("--queue-num", std::to_string(firstq));
        } else {
            cmd.add("--queue-balance",
                    std::to_string(firstq) + ":" + std::to_string(firstq + nbq - 1));
        }
        cmd.exec();
    };
    rule(settings.inputChain, _firstQueue, _inputQueues);
    rule(settings.outputChain, _firstQueue + _inputQueues, _outputQueues);
    for (uint32_t i = 0; i < _inputQueues + _outputQueues; ++i) {
        std::thread([=] { listen(i); }).detach();
    }
}

template <class IP> void PacketListener<IP>::listen(const uint32_t threadId) {
    const uint32_t nlmsgSize = 0xffff + (MNL_SOCKET_BUFFER_SIZE / 2);
    // Avoid large VLA on stack: use a heap-backed buffer with stable address
    std::vector<char> buffer(nlmsgSize);
    _queueTLS = _firstQueue + threadId;
    _inputTLS = threadId < _inputQueues;

    for (;;) {
        mnl_socket *socket = mnl_socket_open(NETLINK_NETFILTER);
        _socketTLS = socket;

        try {
            if (socket == nullptr) {
                throw "cannot open MNL socket";
            }
            if (mnl_socket_bind(socket, 0, MNL_SOCKET_AUTOPID) < 0) {
                throw "cannot bind MNL socket";
            }
            auto nlh = putHeader(buffer.data(), NFQNL_MSG_CONFIG);
            nfq_nlmsg_cfg_put_cmd(nlh, IP::family, NFQNL_CFG_CMD_BIND);
            sendToSocket(nlh);

            nlh = putHeader(buffer.data(), NFQNL_MSG_CONFIG);
            nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);
            sendToSocket(nlh);

            nlh = putHeader(buffer.data(), NFQNL_MSG_CONFIG);
            mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
            mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));
            sendToSocket(nlh);

            nlh = putHeader(buffer.data(), NFQNL_MSG_CONFIG);
            mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_UID_GID));
            mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_UID_GID));
            sendToSocket(nlh);

            nlh = putHeader(buffer.data(), NFQNL_MSG_CONFIG);
            mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_FAIL_OPEN));
            mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_FAIL_OPEN));
            sendToSocket(nlh);

            int ret = 1;
            mnl_socket_setsockopt(socket, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

            const uint32_t port = mnl_socket_get_portid(socket);
            for (;;) {
                if (ssize_t ret = mnl_socket_recvfrom(socket, buffer.data(), nlmsgSize); ret >= 0) {
                    if (mnl_cb_run(buffer.data(), ret, 0, port, callback, nullptr) == -1) {
                        throw "MNL callback error";
                    }
                } else {
                    throw "MNL receive error";
                }
            };
        } catch (const char *error) {
            LOG(ERROR) << __FUNCTION__ << " - " << error;
            if (socket) {
                mnl_socket_close(socket);
            }
        }
    }
}

template <class IP> nlmsghdr *PacketListener<IP>::putHeader(char *buffer, const uint32_t type) {
    auto nlh = mnl_nlmsg_put_header(buffer);
    nlh->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | type;
    nlh->nlmsg_flags = NLM_F_REQUEST;

    auto nfg = static_cast<nfgenmsg *>(mnl_nlmsg_put_extra_header(nlh, sizeof(nfgenmsg)));
    nfg->nfgen_family = AF_UNSPEC;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons(_queueTLS);

    return nlh;
}

template <class IP> void PacketListener<IP>::sendToSocket(const nlmsghdr *nlh) {
    if (mnl_socket_sendto(_socketTLS, nlh, nlh->nlmsg_len) < 0) {
        throw "cannot send data to MNL socket";
    }
}

template <class IP>
void PacketListener<IP>::sendVerdict(const uint32_t id, const uint32_t verdict) {
    char buffer[MNL_SOCKET_BUFFER_SIZE];
    auto nlh = putHeader(buffer, NFQNL_MSG_VERDICT);
    nfq_nlmsg_verdict_put(nlh, id, verdict);
    sendToSocket(nlh);
}

template <class IP> int PacketListener<IP>::callback(const nlmsghdr *nlh, void *data) {
    nlattr *attr[NFQA_MAX + 1] = {};

    if (nfq_nlmsg_parse(nlh, attr) < 0) {
        LOG(ERROR) << __FUNCTION__ << " - cannot parse MNL header";
        return MNL_CB_ERROR;
    }
    if (attr[NFQA_PACKET_HDR] == nullptr) {
        LOG(ERROR) << __FUNCTION__ << " - metaheader not set";
        return MNL_CB_ERROR;
    }
    const auto nfqHeader =
        static_cast<nfqnl_msg_packet_hdr *>(mnl_attr_get_payload(attr[NFQA_PACKET_HDR]));
    if (attr[NFQA_PAYLOAD] == nullptr) {
        // Cannot parse payload but we do have a packet id; accept to avoid queue stall.
        LOG(ERROR) << __FUNCTION__ << " - payload attribute not set";
        sendVerdict(ntohl(nfqHeader->packet_id), NF_ACCEPT);
        return MNL_CB_OK;
    }

    const uint32_t payloadLen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);

    // Basic length guards: must at least contain the IP header of this family.
    if (payloadLen < sizeof(typename IP::Header)) {
        LOG(ERROR) << __FUNCTION__ << " - payload length too short";
        sendVerdict(ntohl(nfqHeader->packet_id), NF_ACCEPT);
        return MNL_CB_OK;
    }

    const auto payload = static_cast<const uint8_t *>(mnl_attr_get_payload(attr[NFQA_PAYLOAD]));
    const auto ip = reinterpret_cast<const typename IP::Header *>(payload);
    const auto iphdrLen = IP::hdrLen(ip);
    // Validate computed IP header length (e.g. IPv4 ihl field) against payload bounds.
    if (iphdrLen < sizeof(typename IP::Header) || iphdrLen > payloadLen) {
        LOG(ERROR) << __FUNCTION__ << " - invalid IP header length";
        sendVerdict(ntohl(nfqHeader->packet_id), NF_ACCEPT);
        return MNL_CB_OK;
    }
    uint32_t len = payloadLen - iphdrLen;
    App::Uid uid = 0;
    uint32_t iface = 0;
    timespec timestamp = {0, 0};
    uint32_t srcPort = 0;
    uint32_t dstPort = 0;

    if (attr[NFQA_UID]) {
        uid = ntohl(mnl_attr_get_u32(attr[NFQA_UID]));
    }
    if (attr[NFQA_IFINDEX_INDEV]) {
        iface = ntohl(mnl_attr_get_u32(attr[NFQA_IFINDEX_INDEV]));
    } else if (attr[NFQA_IFINDEX_OUTDEV]) {
        iface = ntohl(mnl_attr_get_u32(attr[NFQA_IFINDEX_OUTDEV]));
    }
    if (attr[NFQA_TIMESTAMP]) {
        const auto ts = reinterpret_cast<nfqnl_msg_packet_timestamp *>(
            mnl_attr_get_payload(attr[NFQA_TIMESTAMP]));
        timestamp.tv_sec = __be64_to_cpu(ts->sec);
        timestamp.tv_nsec = __be64_to_cpu(ts->usec) * 1000;
    } else {
        timespec_get(&timestamp, TIME_UTC);
    }

    switch (IP::payloadProto(ip)) {
    case IPPROTO_TCP:
        if (len < sizeof(tcphdr)) {
            // Not enough to contain TCP header; reject malformed L4 per original policy.
            LOG(ERROR) << __FUNCTION__ << " - TCP header too short";
            sendVerdict(ntohl(nfqHeader->packet_id), NF_DROP);
            return MNL_CB_OK;
        }
        {
            const auto tcp = reinterpret_cast<const tcphdr *>(payload + iphdrLen);
            const uint32_t tcpHdrLen = static_cast<uint32_t>(tcp->doff) * 4;
            if (tcp->doff < 5 || tcpHdrLen > len) {
                LOG(ERROR) << __FUNCTION__ << " - invalid TCP header length";
                sendVerdict(ntohl(nfqHeader->packet_id), NF_DROP);
                return MNL_CB_OK;
            }
            srcPort = ntohs(tcp->source);
            dstPort = ntohs(tcp->dest);
            len = len - tcpHdrLen;
        }
        break;
    case IPPROTO_UDP:
        if (len >= sizeof(udphdr)) {
            const auto udp = reinterpret_cast<const udphdr *>(payload + iphdrLen);
            srcPort = ntohs(udp->source);
            dstPort = ntohs(udp->dest);
            len -= sizeof(udphdr);
        } else {
            LOG(ERROR) << __FUNCTION__ << " - UDP header too short";
            sendVerdict(ntohl(nfqHeader->packet_id), NF_DROP);
            return MNL_CB_OK;
        }
        break;
    }

    bool verdict = true;

    if (settings.blockEnabled() && (!settings.inetControl() || (srcPort != settings.controlPort &&
                                                                dstPort != settings.controlPort))) {
        // Phase 1 (outside global listeners lock): build per-packet context. This may perform
        // reverse DNS (HostManager::make) or touch disk, but never holds mutexListeners.
        Address<IP> addr(reinterpret_cast<const uint8_t *>(
            _inputTLS ? &ip->saddr : &ip->daddr));
        const auto app = appManager.make(uid);
        const auto host = hostManager.make<IP>(addr);

        // Phase 2 (under global listeners shared lock): pure decision + stats + streaming. This
        // critical section must remain free of blocking I/O to avoid starving RESETALL and other
        // operations that need the exclusive listeners lock.
        const std::shared_lock<std::shared_mutex> lock(mutexListeners);
        verdict = pktManager.template make<IP>(addr, app, host, _inputTLS, iface, timestamp,
                                               IP::payloadProto(ip), srcPort, dstPort, payloadLen);
    }

    sendVerdict(ntohl(nfqHeader->packet_id), verdict ? NF_ACCEPT : NF_DROP);

    return MNL_CB_OK;
}

template class PacketListener<IPv4>;
template class PacketListener<IPv6>;

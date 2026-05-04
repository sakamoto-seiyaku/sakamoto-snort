/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <algorithm>
#include <cstring>
#include <thread>
#include <vector>

#include <CmdLine.hpp>
#include <Ipv6L4Walker.hpp>
#include <PacketListener.hpp>
#include <ControlVNextStreamManager.hpp>
#include <PerfMetrics.hpp>

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
        std::thread([=, this] { listen(i); }).detach();
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
    std::vector<char> buffer(static_cast<std::size_t>(MNL_SOCKET_BUFFER_SIZE));
    auto nlh = putHeader(buffer.data(), NFQNL_MSG_VERDICT);
    nfq_nlmsg_verdict_put(nlh, id, verdict);
    sendToSocket(nlh);
}

template <class IP> int PacketListener<IP>::callback(const nlmsghdr *nlh, void *data) {
    (void)data;

    const bool measure = perfMetrics.enabled();
    uint64_t startUs = 0;
    if (measure) {
        startUs = PerfMetrics::nowUs();
    }

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
    const uint32_t packetId = ntohl(nfqHeader->packet_id);
    if (attr[NFQA_PAYLOAD] == nullptr) {
        // Cannot parse payload but we do have a packet id; accept to avoid queue stall.
        LOG(ERROR) << __FUNCTION__ << " - payload attribute not set";
        sendVerdict(packetId, NF_ACCEPT);
        if (measure) {
            perfMetrics.observeNfqTotalUs(PerfMetrics::nowUs() - startUs);
        }
        return MNL_CB_OK;
    }

    const uint32_t payloadLen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);

    // Basic length guards: must at least contain the IP header of this family.
    if (payloadLen < sizeof(typename IP::Header)) {
        LOG(ERROR) << __FUNCTION__ << " - payload length too short";
        sendVerdict(packetId, NF_ACCEPT);
        if (measure) {
            perfMetrics.observeNfqTotalUs(PerfMetrics::nowUs() - startUs);
        }
        return MNL_CB_OK;
    }

    const auto payload = static_cast<const uint8_t *>(mnl_attr_get_payload(attr[NFQA_PAYLOAD]));
    const auto ip = reinterpret_cast<const typename IP::Header *>(payload);
    const auto iphdrLen = IP::hdrLen(ip);
    // Validate computed IP header length (e.g. IPv4 ihl field) against payload bounds.
    if (iphdrLen < sizeof(typename IP::Header) || iphdrLen > payloadLen) {
        LOG(ERROR) << __FUNCTION__ << " - invalid IP header length";
        sendVerdict(packetId, NF_ACCEPT);
        if (measure) {
            perfMetrics.observeNfqTotalUs(PerfMetrics::nowUs() - startUs);
        }
        return MNL_CB_OK;
    }
    uint32_t len = payloadLen - iphdrLen;
    const uint16_t ipPayloadLen = static_cast<uint16_t>(len);
    App::Uid uid = 0;
    uint32_t iface = 0;
    const bool uidKnown = attr[NFQA_UID] != nullptr;
    const bool ifindexKnown = attr[NFQA_IFINDEX_INDEV] != nullptr || attr[NFQA_IFINDEX_OUTDEV] != nullptr;
    timespec timestamp = {0, 0};
    L4ParseResult l4{};
    bool isFragment = false;
    Conntrack::PacketV4 ctPktV4{};
    Conntrack::PacketV6 ctPktV6{};

    if (uidKnown) {
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

    if constexpr (std::is_same_v<IP, IPv4>) {
        const uint16_t frag = ntohs(ip->frag_off);
        isFragment = (frag & (IP_MF | IP_OFFMASK)) != 0;

        ctPktV4.tsNs = static_cast<std::uint64_t>(timestamp.tv_sec) * 1000000000ULL +
                       static_cast<std::uint64_t>(timestamp.tv_nsec);
        ctPktV4.uid = uid;
        ctPktV4.srcIp = ntohl(ip->saddr);
        ctPktV4.dstIp = ntohl(ip->daddr);
        ctPktV4.proto = static_cast<std::uint8_t>(IP::payloadProto(ip));
        ctPktV4.isFragment = isFragment;
        ctPktV4.ipPayloadLen = ipPayloadLen;
    } else {
        ctPktV6.tsNs = static_cast<std::uint64_t>(timestamp.tv_sec) * 1000000000ULL +
                       static_cast<std::uint64_t>(timestamp.tv_nsec);
        ctPktV6.uid = uid;
        std::memcpy(ctPktV6.srcIp.data(), &ip->saddr, 16);
        std::memcpy(ctPktV6.dstIp.data(), &ip->daddr, 16);
    }

    const uint8_t declaredProto = static_cast<uint8_t>(IP::payloadProto(ip));
    if constexpr (std::is_same_v<IP, IPv4>) {
        l4.proto = declaredProto;
        if (isFragment) {
            l4.l4Status = L4Status::FRAGMENT;
        } else {
            const uint8_t *l4p = payload + iphdrLen;
            const size_t l4len = payloadLen - iphdrLen;

            switch (declaredProto) {
            case IPPROTO_TCP: {
                if (l4len < sizeof(tcphdr)) {
                    LOG(ERROR) << __FUNCTION__ << " - TCP header too short";
                    l4.l4Status = L4Status::INVALID_OR_UNAVAILABLE_L4;
                    break;
                }
                const auto tcp = reinterpret_cast<const tcphdr *>(l4p);
                const uint32_t tcpHdrLen = static_cast<uint32_t>(tcp->doff) * 4u;
                if (tcp->doff < 5 || tcpHdrLen > l4len) {
                    LOG(ERROR) << __FUNCTION__ << " - invalid TCP header length";
                    l4.l4Status = L4Status::INVALID_OR_UNAVAILABLE_L4;
                    break;
                }
                l4.l4Status = L4Status::KNOWN_L4;
                l4.srcPort = ntohs(tcp->source);
                l4.dstPort = ntohs(tcp->dest);
                l4.portsAvailable = 1;

                ctPktV4.srcPort = l4.srcPort;
                ctPktV4.dstPort = l4.dstPort;
                ctPktV4.hasTcp = true;
                ctPktV4.tcp.dataOffsetWords = static_cast<std::uint8_t>(tcp->doff);
                ctPktV4.tcp.window = ntohs(tcp->window);
                ctPktV4.tcp.seq = ntohl(tcp->seq);
                ctPktV4.tcp.ack = ntohl(tcp->ack_seq);
                std::uint8_t flags = 0;
                if (tcp->fin) flags |= TH_FIN;
                if (tcp->syn) flags |= TH_SYN;
                if (tcp->rst) flags |= TH_RST;
                if (tcp->psh) flags |= TH_PUSH;
                if (tcp->ack) flags |= TH_ACK;
                if (tcp->urg) flags |= TH_URG;
#ifdef TH_ECE
                if (tcp->ece) flags |= TH_ECE;
#endif
#ifdef TH_CWR
                if (tcp->cwr) flags |= TH_CWR;
#endif
                ctPktV4.tcp.flags = flags;
            } break;

            case IPPROTO_UDP: {
                if (l4len < sizeof(udphdr)) {
                    LOG(ERROR) << __FUNCTION__ << " - UDP header too short";
                    l4.l4Status = L4Status::INVALID_OR_UNAVAILABLE_L4;
                    break;
                }
                const auto udp = reinterpret_cast<const udphdr *>(l4p);
                l4.l4Status = L4Status::KNOWN_L4;
                l4.srcPort = ntohs(udp->source);
                l4.dstPort = ntohs(udp->dest);
                l4.portsAvailable = 1;

                ctPktV4.srcPort = l4.srcPort;
                ctPktV4.dstPort = l4.dstPort;
            } break;

            case IPPROTO_ICMP: {
                l4.proto = IPPROTO_ICMP;
                if (l4len < sizeof(icmphdr)) {
                    l4.l4Status = L4Status::INVALID_OR_UNAVAILABLE_L4;
                    break;
                }
                l4.l4Status = L4Status::KNOWN_L4;
                const auto icmp = reinterpret_cast<const icmphdr *>(l4p);
                ctPktV4.hasIcmp = true;
                ctPktV4.icmp.type = icmp->type;
                ctPktV4.icmp.code = icmp->code;
                ctPktV4.icmp.id = ntohs(icmp->un.echo.id);
            } break;

            default:
                l4.l4Status = L4Status::OTHER_TERMINAL;
                break;
            }
        }
    } else {
        const uint8_t *l4p = nullptr;
        std::uint16_t l4PayloadLenV6 = 0;
        l4 = parseIpv6L4(declaredProto, payload + iphdrLen,
                         static_cast<size_t>(payloadLen - iphdrLen), &l4p, &l4PayloadLenV6);

        ctPktV6.proto = static_cast<std::uint8_t>(l4.proto);
        ctPktV6.isFragment = l4.l4Status == L4Status::FRAGMENT;
        ctPktV6.ipPayloadLen = l4PayloadLenV6;
        ctPktV6.srcPort = l4.srcPort;
        ctPktV6.dstPort = l4.dstPort;

        if (l4.l4Status == L4Status::KNOWN_L4 && l4p != nullptr) {
            if (l4.proto == IPPROTO_TCP) {
                const auto tcp = reinterpret_cast<const tcphdr *>(l4p);
                ctPktV6.hasTcp = true;
                ctPktV6.tcp.dataOffsetWords = static_cast<std::uint8_t>(tcp->doff);
                ctPktV6.tcp.window = ntohs(tcp->window);
                ctPktV6.tcp.seq = ntohl(tcp->seq);
                ctPktV6.tcp.ack = ntohl(tcp->ack_seq);
                std::uint8_t flags = 0;
                if (tcp->fin) flags |= TH_FIN;
                if (tcp->syn) flags |= TH_SYN;
                if (tcp->rst) flags |= TH_RST;
                if (tcp->psh) flags |= TH_PUSH;
                if (tcp->ack) flags |= TH_ACK;
                if (tcp->urg) flags |= TH_URG;
#ifdef TH_ECE
                if (tcp->ece) flags |= TH_ECE;
#endif
#ifdef TH_CWR
                if (tcp->cwr) flags |= TH_CWR;
#endif
                ctPktV6.tcp.flags = flags;
            } else if (l4.proto == IPPROTO_ICMPV6) {
                ctPktV6.hasIcmp = true;
                ctPktV6.icmp.type = l4p[0];
                ctPktV6.icmp.code = l4p[1];
                std::uint16_t id = 0;
                std::memcpy(&id, l4p + 4, sizeof(id));
                ctPktV6.icmp.id = ntohs(id);
            }
        }
    }

    bool verdict = true;

    const bool isControlTraffic =
        l4.srcPort == settings.controlPort || l4.dstPort == settings.controlPort ||
        l4.srcPort == settings.controlVNextPort || l4.dstPort == settings.controlVNextPort;

    if (settings.blockEnabled() && (!settings.inetControl() || !isControlTraffic)) {
        Address<IP> srcIp(reinterpret_cast<const uint8_t *>(&ip->saddr));
        Address<IP> dstIp(reinterpret_cast<const uint8_t *>(&ip->daddr));
        const Address<IP> &remoteIp = _inputTLS ? srcIp : dstIp;
        const uint8_t ifaceKindBit = pktManager.ifaceKindBit(iface);

        for (;;) {
            const std::uint64_t resetEpoch = snortResetEpoch();
            if (!snortResetEpochIsStable(resetEpoch)) {
                const std::shared_lock<std::shared_mutex> lock(mutexListeners);
                continue;
            }

            const auto foundApp = appManager.find(uid);
            const auto preparedApp = foundApp ? App::Ptr{} : appManager.prepare(uid);
            const auto appForPrepare = foundApp ? foundApp : preparedApp;
            const bool prepareHost =
                appForPrepare == nullptr || (appForPrepare->blockIface() & ifaceKindBit) == 0;
            const auto foundHost = prepareHost ? hostManager.find<IP>(remoteIp, false) : Host::Ptr{};
            const auto preparedHost =
                (prepareHost && !foundHost) ? hostManager.prepare<IP>(remoteIp) : Host::Ptr{};

            ControlVNextStreamManager::PktEvent streamEvent{};
            bool trackedSnapshot = false;
            bool retryWithHost = false;

            {
                const std::shared_lock<std::shared_mutex> lock(mutexListeners);
                if (!snortResetEpochStillCurrent(resetEpoch)) {
                    continue;
                }

                const auto app = appManager.publishPrepared(uid, preparedApp);
                if (!app) {
                    continue;
                }

                const std::uint8_t appIfaceMask = app->blockIface();
                const bool ifaceBlocked = (appIfaceMask & ifaceKindBit) != 0;
                Host::Ptr host;
                if (ifaceBlocked) {
                    host = hostManager.anonymousHost();
                } else {
                    if (!prepareHost) {
                        retryWithHost = true;
                    } else {
                        host = foundHost ? foundHost
                                         : hostManager.publishPrepared<IP>(remoteIp, preparedHost);
                    }
                }
                if (retryWithHost || !host) {
                    continue;
                }

                const Conntrack::PacketV4 *ctPtrV4 = nullptr;
                const Conntrack::PacketV6 *ctPtrV6 = nullptr;
                if constexpr (std::is_same_v<IP, IPv4>) {
                    ctPtrV4 = &ctPktV4;
                } else {
                    ctPtrV6 = &ctPktV6;
                }
                verdict = pktManager.template make<IP>(srcIp, dstIp, app, host, _inputTLS, iface,
                                                       uidKnown, ifindexKnown, timestamp,
                                                       l4, payloadLen, ifaceKindBit, appIfaceMask,
                                                       ctPtrV4, ctPtrV6, &streamEvent, &trackedSnapshot);
                if (trackedSnapshot) {
                    controlVNextStream.observePktTracked(std::move(streamEvent));
                } else {
                    controlVNextStream.observePktSuppressed(_inputTLS, verdict, payloadLen);
                }
            }
            break;
        }
    }

    sendVerdict(packetId, verdict ? NF_ACCEPT : NF_DROP);
    if (measure) {
        perfMetrics.observeNfqTotalUs(PerfMetrics::nowUs() - startUs);
    }
    return MNL_CB_OK;
}

template class PacketListener<IPv4>;
template class PacketListener<IPv6>;

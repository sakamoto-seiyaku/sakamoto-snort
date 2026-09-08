#!/usr/bin/env python3
"""Keep fragment-visibility diagnostics outside PacketFacts and policy."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
adapter=(ROOT/'src/product/vpp/product_root_nfqueue_adapter.c').read_text()
header=(ROOT/'src/product/vpp/product_packet.h').read_text()
helper=(ROOT/'tests/device/helpers/s231-net.c').read_text()
assert 'case NFQA_SKB_INFO:' in adapter and 'case NFQA_CAP_LEN:' in adapter
assert 'packet->skb_info_present = 1' in adapter and 'packet->captured_length_present = 1' in adapter
assert 'skb_info' not in header and 'captured_length' not in header
trace=adapter.index('s231 event=nfq_payload')
assert adapter.rfind('product_packet_graph_trace_limit ()',0,trace)>adapter.rfind('obligation_id =',0,trace)
assert trace<adapter.index('submitted = product_packet_graph_submit_external',trace)
assert 'packet.payload[octet]' in adapter[trace:adapter.index('submitted =',trace)]
assert 'flockfile (stderr)' in adapter[trace-100:trace]
assert 'NF_INET_LOCAL_OUT' in adapter and 'NF_INET_LOCAL_IN' in adapter
assert 'AF_PACKET' in helper and 'IP_HDRINCL' in helper and 'IPV6_HDRINCL' in helper
assert 'vlib_' not in helper and 'nfq_set_verdict' not in helper
assert 'CAP_NET_RAW' in helper and 'setuid (uid)' in helper
print('S231 bounded pre-transfer NFQA observation, unknown attribute presence, independent kernel-only generator: PASS')

#!/usr/bin/env python3
"""Reproducible offline decomposition of one frozen single-little CPU profile."""
from collections import Counter, defaultdict
import argparse
import hashlib
import json
from pathlib import Path
import platform
import sys

ROOT=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source',type=Path,default=ROOT/'build-output/tcp-single-little-profile-20261022/profile-single-little/attribution.json')
parser.add_argument('--output',type=Path,default=ROOT/'build-output/tcp-single-little-deep-analysis-20261022')
args=parser.parse_args()
SOURCE=args.source.resolve()
OUT=args.output.resolve()
OUT.mkdir(parents=True,exist_ok=True)

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def base(frame):return frame['dso'].rsplit('/',1)[-1]
def kernel(frame):return frame['dso']=='[kernel.kallsyms]'
def words(text):return set(text.split())

USERCOPY=words('__arch_copy_to_user __arch_copy_from_user _copy_to_iter _copy_from_iter copyout copyin copy_to_iter copy_from_iter skb_copy_datagram_iter skb_copy_datagram_from_iter __skb_datagram_iter.2 __skb_datagram_iter skb_copy_datagram_msg skb_copy_datagram_from_iter')
CHECKSUM=words('do_csum csum_partial csum_partial_ext __skb_checksum __skb_checksum_complete skb_checksum_help skb_checksum nf_checksum nf_ip_checksum')
EVENTFD=words('eventfd_read eventfd_ctx_read eventfd_write eventfd_poll')
EPOLL=words('do_epoll_wait __arm64_sys_epoll_pwait ep_done_scan ep_start_scan ep_send_events select_estimate_accuracy __ep_eventpoll_poll')
LINUX_MEMORY=words('clear_page memset memblock_is_map_memory pfn_is_map_memory is_vmalloc_addr check_stack_object __check_object_size __check_heap_object check_heap_object free_large_kmalloc free_unref_page_prepare free_unref_page free_unref_page_commit get_populated_pcp_list post_alloc_hook prep_new_page prepare_alloc_pages get_page_from_freelist kernel_init_pages slab_pre_alloc_hook slab_post_alloc_hook kmalloc_size_roundup cmpxchg_double_slab __zone_watermark_ok __alloc_pages __alloc_skb gfp_zone')
CLOCK=words('ktime_get_ts64 ktime_get ktime_get_with_offset arch_counter_read arch_counter_get_cntpct set_normalized_timespec64 timespec64_add_safe get_timespec64 get_itimerspec64 __mod_timer')
SYSCALL_VFS=words('el0_svc_common el0_svc invoke_syscall do_el0_svc el0t_64_sync_handler el0t_64_sync vfs_read vfs_write ksys_read ksys_write do_readv do_iter_read do_iter_write __fdget __fdget_pos __fget_files fput file_start_write file_end_write __get_task_ioprio file_has_perm generic_write_checks set_user_sigmask copy_msghdr_from_user import_iovec iovec_from_user __import_iovec __sys_recvmsg ____sys_recvmsg syscall_trace_enter syscall_trace_exit __secure_computing __seccomp_filter fsnotify_perm __fsnotify_parent')
LOCK_SCHED=words('queued_spin_lock_slowpath finish_task_switch __schedule schedule schedule_hrtimeout_range_clock schedule_hrtimeout_range lock_sock_nested release_sock mutex_lock mutex_unlock queue_work_on migrate_enable migrate_disable load_balance update_blocked_averages idle_cpu cpu_overutilized __wake_up_sync_key')
HEV_COROUTINE=words('hev_task_execute hev_task_executer')
SETJMP=words('longjmp sigsetjmp _setjmp setjmp memtag_handle_longjmp __arm_za_disable')
MEM_COPY=words('__memmove_aarch64_simd __memset_aarch64 __memcmp_aarch64 __strcmp_aarch64')
LIBC_IO=words('read readv write recvmsg __recvmsg epoll_wait __epoll_pwait timerfd_settime')
LWIP_MEMORY=words('mem_malloc mem_free memp_malloc memp_free pbuf_alloc pbuf_free hev_lwip_malloc hev_lwip_free hev_lwip_pbuf_allocate hev_lwip_pbuf_deallocate')
VPP_FRAMEQUEUE=words('vlib_frame_queue_dequeue_fn vlib_buffer_enqueue_to_thread_retained_fn vlib_thread_wakeup')
VPP_FRAME=words('dispatch_node dispatch_pending_node vlib_worker_thread_fn vlib_main_or_worker_loop vlib_file_poll vlib_get_next_frame_internal vlib_put_next_frame vlib_next_frame_change_ownership vlib_frame_alloc_to_node vlib_put_frame_to_node vlib_get_frame_to_node vlib_buffer_enqueue_to_single_next_fn process_expired_timers')

def leaf_rule(frame):
    d,n=base(frame),frame['symbol']
    if kernel(frame):
        if n in USERCOPY:return 'linux_usercopy'
        if n in CHECKSUM:return 'linux_checksum'
        if n in EVENTFD:return 'linux_eventfd_leaf'
        if n in EPOLL:return 'linux_epoll_leaf'
        if n.startswith(('ipt_','iptable_','nf_','__nf_','ipv4_conntrack','bpf_','__cgroup_bpf_','htab_','__htab_')) or n in words('run_filter mark_tg connmark_mt policy_mt quota_mt2 xfrm4_policy_check get_l4proto raw_local_deliver') or '[bpf]' in n:return 'linux_netfilter_bpf'
        if n.startswith(('tcp_','__tcp_','inet_','sock_','sk_','__sk_','ip_','ipv4_','skb_','__skb_','netif_','__netif_','tun_','dev_','__dev_','neigh_')) or n in words('netif_receive_skb __netif_receive_skb virtio_net_hdr_to_skb __inet_lookup_established __unix_dgram_recvmsg napi_consume_skb'):return 'linux_tcp_ip_socket_tun_leaf'
        if n in LINUX_MEMORY or n.startswith(('kmem_','__kmem_','kfree','__kmalloc','kmalloc_','slab_','__slab_')):return 'linux_memory_safety_allocation'
        if n in CLOCK or n.startswith(('ktime_','arch_counter_','hrtimer_','do_timerfd_')):return 'linux_clock_timer'
        if n in LOCK_SCHED or n.startswith(('_raw_','__rcu_','rcu_','__list_','__ipi_','handle_softirq','local_bh_','__local_bh_')):return 'linux_lock_scheduler_workqueue'
        if n.startswith(('trace_event_','__traceiter_','tracing_','ring_buffer_')):return 'linux_tracepoint_ringbuffer_leaf'
        if n in SYSCALL_VFS or n.startswith(('security_','selinux_','avc_','ksu_','__arm64_sys_')):return 'linux_syscall_vfs_security'
        return 'linux_other_recorded_symbol'
    if d.endswith('.ko'):return 'device_module_leaf_recorded_only'
    if n=='@plt' or d=='linker64':return 'userspace_tls_plt_target_not_proven'
    if d=='[vdso]' or n=='clock_gettime':return 'userspace_clock'
    if d=='libc.so':
        if n in MEM_COPY:return 'userspace_copy_set_compare'
        if n in SETJMP:return 'userspace_setjmp_longjmp_helpers'
        if n in LIBC_IO:return 'userspace_syscall_wrapper'
        return 'userspace_libc_other'
    if d=='libvppinfra.so':
        if n in words('malloc free mspace_malloc mspace_free mspace_usable_size clib_mem_free clib_mem_alloc_aligned_or_null'):return 'vpp_heap_allocation'
        return 'vpp_infra_other'
    if d in ('libvlib.so','libsvm.so'):
        if n in VPP_FRAMEQUEUE:return 'vpp_framequeue_enqueue_dequeue_wakeup'
        if n in VPP_FRAME:return 'vpp_dispatch_native_frames_timers'
        if n.startswith('__aarch64_'):return 'userspace_atomic_helper'
        return 'vpp_other_leaf'
    if d=='libproduct_core_plugin.so':
        if n in LWIP_MEMORY:return 'hev_lwip_memory_helpers'
        if n in HEV_COROUTINE or n.startswith('hev_task_'):return 'hev_coroutine_scheduler'
        if n=='inet_chksum' or n.startswith('inet_cksum_'):return 'lwip_checksum'
        if n.startswith(('hev_','tcp_','pbuf_','ip4_','ip_','lwip_','guard_tcp_')) or n in words('output_packet pbuf_event tcp_session_task'):return 'hev_lwip_transport'
        if n.startswith('product_vpn_tun_') or n.startswith('tun_'):return 'product_tun_adapter_leaf'
        if n.startswith('product_'):return 'product_graph_policy_flow_observation'
        if n in words('find_entry timer_reorder owner_for trace buffers_allocated buffers_freed export_record output refresh schedule enter leave'):return 'plugin_named_helpers_source_not_disambiguated'
        if n.startswith('__aarch64_'):return 'userspace_atomic_helper'
        return 'plugin_other_leaf_not_inferred'
    return 'other_dso_leaf_not_inferred'

# Exact anchor sets, DSO guards and materialized matched (DSO,symbol) inventory
# are emitted. Inclusive sets overlap; a sample is counted once per anchor set.
ANCHORS={
 'linux_tcp_recvmsg':('kernel',words('tcp_recvmsg tcp_recvmsg_locked')),
 'linux_tcp_socket_receive':('kernel',words('tcp_recvmsg tcp_recvmsg_locked inet_recvmsg sock_read_iter __sys_recvmsg ____sys_recvmsg')),
 'linux_tcp_ip_path':('kernel',words('tcp_recvmsg tcp_recvmsg_locked tcp_rcv_established tcp_v4_rcv tcp_v4_do_rcv tcp_data_queue tcp_data_ready tcp_queue_rcv tcp_ack tcp_output __tcp_transmit_skb ip_rcv ip_local_deliver ip_protocol_deliver_rcu ip_finish_output2')),
 'linux_usercopy_to_user':('kernel',words('__arch_copy_to_user _copy_to_iter copyout')),
 'linux_usercopy_from_user':('kernel',words('__arch_copy_from_user _copy_from_iter copyin')),
 'linux_checksum':('kernel',CHECKSUM),
 'linux_netfilter':('kernel',words('ipt_do_table nf_hook_slow nf_conntrack_in nf_conntrack_tcp_packet ipv4_conntrack_in iptable_mangle_hook nf_nat_ipv4_pre_routing bpf_mt_v1')),
 'eventfd_write':('kernel',words('eventfd_write')),
 'eventfd_read':('kernel',words('eventfd_read eventfd_ctx_read')),
 'linux_epoll':('kernel',words('do_epoll_wait')),
 'linux_timerfd_settime':('kernel',words('do_timerfd_settime __arm64_sys_timerfd_settime')),
 'product_completion_publication':('libproduct_core_plugin.so',words('product_completion_batch_publish product_completion_batch_flush product_packet_terminal_node_fn')),
 'tun_kernel_write':('kernel',words('tun_chr_write_iter tun_get_user')),
 'tun_kernel_read':('kernel',words('tun_chr_read_iter tun_do_read tun_ring_recv')),
 'vpp_framequeue':('libvlib.so',VPP_FRAMEQUEUE),
 'vpp_dispatch_frames':('libvlib.so',VPP_FRAME),
 'hev_direct_tcp_receive':('libproduct_core_plugin.so',words('hev_socks5_session_tcp_direct_receive')),
 'hev_lwip_tcp_transport':('libproduct_core_plugin.so',words('tcp_input tcp_receive tcp_process tcp_output tcp_write tcp_session_task hev_owner_step hev_owner_input_copy')),
 'hev_coroutine_execution':('libproduct_core_plugin.so',words('hev_task_executer hev_task_execute hev_task_system_schedule hev_task_system_step')),
 'lwip_checksum':('libproduct_core_plugin.so',words('inet_chksum inet_cksum_pseudo_partial_base inet_cksum_pseudo_base')),
 'heap_memory':('any',words('mspace_malloc mspace_free malloc free clib_mem_alloc_aligned_or_null clib_mem_free mem_malloc mem_free memp_malloc memp_free hev_lwip_malloc hev_lwip_free')),
 'userspace_memory_copy_set':('libc.so',MEM_COPY),
 'product_policy':('libproduct_core_plugin.so',words('product_packet_policy_node_fn product_packet_graph_policy_stage_snapshot product_packet_graph_l4_view_evaluate')),
 'product_observation_publish':('libproduct_core_plugin.so',words('product_observation_publish export_record product_observation_observed')),
 'product_completion_origin':('libproduct_core_plugin.so',words('product_vpn_tun_complete_from_graph product_packet_origin_completion_node_fn product_origin_reclaim_flush')),
 'product_tun_write_once':('libproduct_core_plugin.so',words('product_vpn_tun_write_once')),
}

def anchor_hits(chain):
    hits={}
    for name,(guard,symbols) in ANCHORS.items():
        exact=[(i,f['dso'],f['symbol']) for i,f in enumerate(chain['frames']) if f['symbol'] in symbols and (guard=='any' or (kernel(f) if guard=='kernel' else base(f)==guard))]
        if exact:hits[name]=exact
    return hits

def metric(chains, thread, selected_total=None):
    samples=sum(c['samples'] for c in chains);period=sum(c['period_ns'] for c in chains)
    return dict(samples=samples,period_ns=period,sampled_cpu_seconds=period/1e9,
      fraction_thread_samples=samples/thread['samples'],fraction_global_samples=samples/GLOBAL_SAMPLES,
      fraction_thread_period=period/thread['period_ns'],fraction_global_period=period/GLOBAL_PERIOD,
      fraction_selected_samples=samples/selected_total if selected_total else None)

def top_self(chains,thread,limit=None):
    counter=defaultdict(list)
    for c in chains:counter[(c['frames'][0]['dso'],c['frames'][0]['symbol'])].append(c)
    return [dict(dso=d,symbol=n,**metric(cc,thread)) for (d,n),cc in sorted(counter.items(),key=lambda kv:-sum(c['period_ns'] for c in kv[1]))[:limit]]

def top_dsos(chains,thread):
    groups=defaultdict(list)
    for c in chains:groups[c['frames'][0]['dso']].append(c)
    return [dict(dso=d,**metric(cc,thread)) for d,cc in sorted(groups.items(),key=lambda kv:-sum(c['period_ns'] for c in kv[1]))]

def chain_evidence(c):
    root=c['frames'][-1]['symbol']
    return dict(chain_id=hashlib.sha256(json.dumps(dict(frames=c['frames'],phase=c['phase']),sort_keys=True).encode()).hexdigest(),phase=c['phase'],old_matched_anchor=c['matched_anchor'],frames_leaf_to_root=c['frames'],
      samples=c['samples'],period_ns=c['period_ns'],
      leaf_bucket=leaf_rule(c['frames'][0]),inclusive_anchor_matches=anchor_hits(c),
      coroutine_root_boundary=root in words('hev_task_execute hev_task_executer longjmp sigsetjmp _setjmp'),
      shallow_observed_depth=len(c['frames'])<=3,
      kernel_symbol_identity='recorded device kernel symbols only' if any(kernel(f) or base(f).endswith('.ko') for f in c['frames']) else None,
      semantic_trampoline_in_chain=any(f['symbol']=='@plt' or base(f)=='linker64' for f in c['frames']),
      full_unwind_completeness_asserted=False)

def summarize_selection(chains,thread):
    buckets=defaultdict(list)
    for c in chains:buckets[leaf_rule(c['frames'][0])].append(c)
    total=sum(c['samples'] for c in chains)
    exclusive=[dict(bucket=k,**metric(v,thread,total)) for k,v in sorted(buckets.items(),key=lambda kv:-sum(c['period_ns'] for c in kv[1]))]
    assert sum(r['samples'] for r in exclusive)==total
    assert sum(r['period_ns'] for r in exclusive)==sum(c['period_ns'] for c in chains)
    inclusive=[]
    for name in ANCHORS:
        selected=[c for c in chains if name in anchor_hits(c)]
        if selected:inclusive.append(dict(anchor=name,**metric(selected,thread,total)))
    by_reason=defaultdict(list)
    for c in chains:by_reason[c['matched_anchor'].split(':',1)[0]].append(c)
    coroutine=[c for c in chains if chain_evidence(c)['coroutine_root_boundary']]
    shallow=[c for c in chains if len(c['frames'])<=3]
    endings=defaultdict(list)
    for c in chains:endings[(c['frames'][-1]['dso'],c['frames'][-1]['symbol'])].append(c)
    return dict(total=metric(chains,thread),exclusive_leaf_buckets=exclusive,
      root_termination_symbols=[dict(dso=d,symbol=n,**metric(v,thread,total)) for (d,n),v in sorted(endings.items(),key=lambda kv:-sum(c['period_ns'] for c in kv[1]))],
      inclusive_observed_anchor_sets=sorted(inclusive,key=lambda r:-r['period_ns']),
      top_self=top_self(chains,thread),leaf_dsos=top_dsos(chains,thread),
      old_classifier_reasons={k:metric(v,thread,total) for k,v in by_reason.items()},
      coroutine_boundary_endings=metric(coroutine,thread,total),shallow_depth_1_to_3=metric(shallow,thread,total),
      chains=[chain_evidence(c) for c in sorted(chains,key=lambda c:-c['period_ns'])])

assert sha(SOURCE)=='8633f2b1957c6fce789401a7dc5cfd1765c4f892dd1e8e7ee472e58a01756bdc'
raw=json.loads(SOURCE.read_text());assert raw['event']=='cpu-clock' and raw['profile_mode']=='on-cpu'
GLOBAL_SAMPLES=sum(t['samples'] for t in raw['threads']);GLOBAL_PERIOD=sum(t['period_ns'] for t in raw['threads'])
assert GLOBAL_SAMPLES==3848
threads=[]
for t in raw['threads']:
    chains=t['symbol_chains'];assert all(c['period_ns']==c['samples']*5025125 for c in chains)
    assert sum(c['samples'] for c in chains)==t['samples'];assert sum(c['period_ns'] for c in chains)==t['period_ns']
    for phase,m in t['phases'].items():assert metric([c for c in chains if c['phase']==phase],t)['samples']==m['samples']
    threads.append(dict(tid=t['tid'],comm=t['name'],role='owner' if t['tid']==21243 else 'io' if t['tid']==21244 else 'main',
      denominator_samples=t['samples'],denominator_period_ns=t['period_ns'],diagnostics=t['diagnostics'],
      all_samples=summarize_selection(chains,t),
      old_other_unknown=summarize_selection([c for c in chains if c['phase']=='other_unknown'],t)))

t=next(t for t in raw['threads'] if t['tid']==21244)
def completion(c):return c['phase']=='completion_write_free'
def tunwrite(c):return kernel(c['frames'][0]) and 'tun_kernel_write' in anchor_hits(c)
sets={
 'intersection_completion_and_tun_kernel_write':[c for c in t['symbol_chains'] if completion(c) and tunwrite(c)],
 'completion_without_tun_kernel_write':[c for c in t['symbol_chains'] if completion(c) and not tunwrite(c)],
 'tun_kernel_write_without_completion':[c for c in t['symbol_chains'] if not completion(c) and tunwrite(c)],
 'neither':[c for c in t['symbol_chains'] if not completion(c) and not tunwrite(c)],
}
assert sum(sum(c['samples'] for c in v) for v in sets.values())==1754
assert metric(sets['intersection_completion_and_tun_kernel_write'],t)['samples']==814
assert sum(c['samples'] for c in t['symbol_chains'] if completion(c))==922
assert metric([c for c in t['symbol_chains'] if tunwrite(c)],t)['samples']==t['kernel_leaf_groups']['tun_write_return']['samples']
intersection={k:dict(**metric(v,t),top_self=top_self(v,t),chains=[chain_evidence(c) for c in sorted(v,key=lambda c:-c['period_ns'])]) for k,v in sets.items()}
difference=sets['completion_without_tun_kernel_write']
intersection['intersection_inclusive_anchors']=summarize_selection(sets['intersection_completion_and_tun_kernel_write'],t)['inclusive_observed_anchor_sets']
intersection['difference_subsets']={
 'write_wrapper_still_observed':metric([c for c in difference if 'product_tun_write_once' in anchor_hits(c)],t),
 'no_write_wrapper_observed':metric([c for c in difference if 'product_tun_write_once' not in anchor_hits(c)],t),
}
owner=next(t for t in raw['threads'] if t['tid']==21243)
spin=[c for c in owner['symbol_chains'] if kernel(c['frames'][0]) and c['frames'][0]['symbol']=='_raw_spin_unlock_irq']
spin_paths={n:[c for c in spin if n in anchor_hits(c)] for n in ('eventfd_write','linux_timerfd_settime','eventfd_read')}
assert all(sum(n in anchor_hits(c) for n in spin_paths)==1 for c in spin)
assert sum(sum(c['samples'] for c in v) for v in spin_paths.values())==235
assert all(sum(c['samples'] for c in v)==want for v,want in zip(spin_paths.values(),(186,37,12)))
spin_write=spin_paths['eventfd_write']
spin_write_contexts={n:[c for c in spin_write if n in anchor_hits(c)] for n in ('product_completion_publication','product_observation_publish')}
assert [sum(c['samples'] for c in v) for v in spin_write_contexts.values()]==[137,49]
assert all(sum(n in anchor_hits(c) for n in spin_write_contexts)==1 for c in spin_write)
ipt=[c for c in t['symbol_chains'] if kernel(c['frames'][0]) and c['frames'][0]['symbol']=='ipt_do_table']
assert sum(c['samples'] for c in ipt)==125 and all('tun_kernel_write' in anchor_hits(c) for c in ipt)
cross_tabs=dict(
 owner_spin_unlock_irq=dict(total=metric(spin,owner),
   observed_paths={n:dict(**metric(v,owner,235),chains=[chain_evidence(c) for c in v]) for n,v in spin_paths.items()},
   eventfd_write_contexts={n:dict(**metric(v,owner,186),chains=[chain_evidence(c) for c in v]) for n,v in spin_write_contexts.items()},
   interpretation='Self CPU in this unlock symbol on observed eventfd/timerfd paths; not spin waiting, blocked time, syscall counts, or number of notifications.'),
 io_ipt_do_table=dict(total=metric(ipt,t),tun_kernel_write_intersection=metric([c for c in ipt if 'tun_kernel_write' in anchor_hits(c)],t,125),chains=[chain_evidence(c) for c in sorted(ipt,key=lambda c:-c['period_ns'])]))
# Materialize every classification assignment: these exact input symbols, not
# arbitrary future names, are the auditable exclusive leaf classification.
assignments={}
for t in raw['threads']:
    for c in t['symbol_chains']:
        f=c['frames'][0];assignments[(f['dso'],f['symbol'])]=leaf_rule(f)
report=dict(schema='tcp-single-little-deep-attribution/v1',
 tool=dict(path=str(Path(__file__).resolve()),sha256=sha(Path(__file__)),python=sys.version,executable=sys.executable,executable_sha256=sha(Path(sys.executable)),argv=sys.argv,cwd=str(Path.cwd()),platform=platform.platform(),dependencies='Python standard library only'),
 input=dict(path=str(SOURCE),sha256=sha(SOURCE),upstream_schema=raw['schema'],upstream_tool_identities=raw['identities'],
            pid=raw['pid'],begin_monotonic_ns=raw['begin_monotonic_ns'],end_monotonic_ns=raw['end_monotonic_ns'],window_seconds=raw['window_seconds'],profile_integrity=raw['profile_integrity'],record_stats=raw['record_stats']),
 denominators=dict(global_samples=GLOBAL_SAMPLES,global_period_ns=GLOBAL_PERIOD,sampled_cpu_seconds=GLOBAL_PERIOD/1e9,meaning='Sum across all sampled threads, not wall time or one-core utilization.'),
 rules=dict(schema='observed-leaf-exclusive-plus-observed-chain-inclusive/v1',
   exclusive='One leaf bucket per sample, based only on observed leaf DSO+symbol, never inferred from a caller. Rule precedence is the retained script leaf_rule function; exact assignments below.',
   exclusive_exact_assignments=[dict(dso=d,symbol=n,bucket=k) for (d,n),k in sorted(assignments.items())],
   inclusive='Each sample counted once per exact observed anchor set; sets overlap and must not be added. DSO guards are mandatory. Missing/inlined/coroutine caller ancestry is not reconstructed.',
   inclusive_anchor_sets={n:dict(dso_guard=g,exact_symbols=sorted(s)) for n,(g,s) in ANCHORS.items()},
   original_completion='Frozen input phase equals completion_write_free, without reclassifying original evidence.',
   original_tun_write='Kernel leaf and exact tun_get_user/tun_chr_write_iter observed in chain; checked against original814-sample kernel bucket.',
   certainty='Symbol names and observed membership are factual. Bucket semantic grouping is an offline interpretation. No full unwinding, fd identity from generic wrappers, causal wait attribution, or independent kernel rebuild is asserted.'),
 threads=threads,io_completion_write_intersection=intersection,requested_leaf_path_cross_tabs=cross_tabs,
 limits=['cpu-clock sample periods approximate sampled CPU; all3848 periods happen to equal5025125ns. Counts are not packet/syscall/eventfd counts or energy.',
 'Other_unknown means unmatched by the original conservative phase anchors, not unresolved leaf symbols; input reports zero unresolved frames.',
 'A stack ending hev_task_execute records an observed coroutine boundary, not its missing scheduling caller or proof of a product bug.',
 'Kernel/module symbols are retained device-record identities; Linux categories are not independent kernel source/line verification.',
 'PLT/TLS frames are resolved names with opaque/indirect target semantics; fully named observed chains need not be complete.',
 'Spinlock/scheduler self CPU is not blocked time or evidence of lock contention duration.',
 'Inclusive TCP/socket/netfilter/usercopy/checksum/HEV categories overlap; only exclusive leaf rows form an additive budget.',
 'The108 completion-minus-TUN samples include46 with the write wrapper still observed; this difference is not108 samples of pure bookkeeping/free.'])
(OUT/'profile-decomposition.json').write_text(json.dumps(report,indent=2)+'\n')

def percent(value):return f'{100*value:.2f}%'
def table_metric(row):return f"{row['samples']} | {percent(row['fraction_thread_samples'])} | {percent(row['fraction_global_samples'])}"
labels={
 'product_graph_policy_flow_observation':'Product graph / policy / flow / observation',
 'linux_usercopy':'Linux usercopy / datagram iterator',
 'linux_lock_scheduler_workqueue':'Linux locks / scheduler / workqueue',
 'linux_syscall_vfs_security':'Linux syscall / VFS / security',
 'plugin_named_helpers_source_not_disambiguated':'Shared plugin helper names: source ambiguous',
 'hev_lwip_transport':'HEV / lwIP transport', 'lwip_checksum':'lwIP checksum',
 'linux_tcp_ip_socket_tun_leaf':'Linux TCP / IP / socket / TUN leaf',
 'linux_memory_safety_allocation':'Linux allocation / memory safety',
 'userspace_tls_plt_target_not_proven':'TLS / PLT: indirect target not proven',
 'linux_epoll_leaf':'Linux epoll leaf', 'userspace_syscall_wrapper':'Userspace syscall wrappers',
 'linux_clock_timer':'Linux clocks / timers', 'product_tun_adapter_leaf':'Product TUN adapter leaf',
 'vpp_dispatch_native_frames_timers':'VPP dispatch / native-frame / timer leaf',
}
lines=['# Single-little: deeper observed CPU attribution','',
 'Only the existing frozen profile was analyzed. Owner denominator: **2,093** samples; I/O: **1,754**; main: **1**; global: **3,848**. Each sample period is 5,025,125 ns; aggregate sampled CPU is 19.336681 s across threads, not wall time or energy.',
 '', '## Original other_unknown, now decomposed by exclusive leaf','',
 'These rows partition the original unknown phase only; they do not rewrite it. Thread % uses that thread’s entire sample count, and global % uses 3,848. The JSON retains every leaf, DSO, period and exact chain.','']
for th,limit in ((threads[1],10),(threads[2],7)):
    selection=th['old_other_unknown'];total=selection['total']
    lines += [f"### {th['role']}: {total['samples']} samples ({percent(total['fraction_thread_samples'])})",'',
              '| Exclusive observed leaf category | Samples | Thread % | Global % |',
              '| --- | ---: | ---: | ---: |']
    shown=selection['exclusive_leaf_buckets'][:limit]
    for row in shown:lines.append(f"| {labels.get(row['bucket'],row['bucket'])} | {table_metric(row)} |")
    remainder=selection['exclusive_leaf_buckets'][limit:]
    count=sum(r['samples'] for r in remainder)
    lines.append(f"| Other exclusive leaf categories | {count} | {percent(count/th['denominator_samples'])} | {percent(count/GLOBAL_SAMPLES)} |")
    lines.append('')
lines += [
 'Unknown-phase leaf DSOs: owner kernel **593** / plugin **431** / libc **39** / VPP vlib **29**; I/O kernel **299** / libc **21** / plugin **19** / VPP vlib **19**. Remaining DSOs are explicit in JSON.',
 '',
 'Largest unknown owner self leaves include `__arch_copy_to_user` **148** (7.07% owner), `_raw_spin_unlock_irq` **68** (3.25%), `product_packet_policy_node_fn` **42** (2.01%) and `inet_chksum` **41** (1.96%). I/O unknown self includes `el0_svc_common` **34** (1.94%), `finish_task_switch` **32** (1.82%) and `do_epoll_wait` **20** (1.14%). These are self CPU samples, not blocked time.',
 '', '## Inclusive observed call-chain contexts: overlapping, never additive','',
 '| Selection / observed anchor | Samples | Thread % | Global % |', '| --- | ---: | ---: | ---: |']
for name in ('hev_coroutine_execution','hev_direct_tcp_receive','product_policy','linux_tcp_recvmsg','linux_usercopy_to_user','product_observation_publish','eventfd_write','linux_epoll','heap_memory','lwip_checksum','vpp_dispatch_frames'):
    row=next(r for r in threads[1]['old_other_unknown']['inclusive_observed_anchor_sets'] if r['anchor']==name)
    lines.append(f'| Owner unknown / {name} | {table_metric(row)} |')
for name in ('linux_epoll','eventfd_read'):
    row=next(r for r in threads[2]['old_other_unknown']['inclusive_observed_anchor_sets'] if r['anchor']==name)
    lines.append(f'| I/O unknown / {name} | {table_metric(row)} |')
for name in ('tun_kernel_write','linux_tcp_ip_path','linux_netfilter','linux_checksum','linux_usercopy_from_user'):
    row=next(r for r in threads[2]['all_samples']['inclusive_observed_anchor_sets'] if r['anchor']==name)
    lines.append(f'| All I/O / {name} | {table_metric(row)} |')
lines += ['',
 'The owner’s **614** unknown samples with an outer VPP dispatch frame are not 614 samples of dispatch self overhead. Many are nested policy, syscall or transport work. Owner unknown contains **501** samples whose observed roots end at a coroutine/context boundary (499 at `hev_task_execute`, one `longjmp`, one `sigsetjmp`); **30** have only 1–3 observed frames. Callers beyond those boundaries are not reconstructed.',
 '',
 'A concrete owner chain is `__arch_copy_to_user → _copy_to_iter → ... → tcp_recvmsg_locked → ... → readv → hev_socks5_session_tcp_direct_receive → tcp_session_task → hev_task_executer → hev_task_execute` (105 samples for the largest exact variant, another 42 for a variant with a repeated iterator frame). This proves observed socket receive/usercopy under the coroutine, not a complete ancestry to VPP.',
 '',
 'I/O unknown is **337** outer-runtime-only samples plus **25** mixed-callback samples; it is dominated by generic read/epoll/syscall/scheduler work. The large TCP/IP/netfilter return cost is already inside the recognized completion phase, not hidden in that 20.64%.',
 '', '## Exact I/O completion versus kernel TUN-write overlap','',
 '| Set | Samples | I/O % | Global % |','| --- | ---: | ---: | ---: |']
for key,label in [('intersection_completion_and_tun_kernel_write','Completion AND kernel TUN-write'),('completion_without_tun_kernel_write','Completion WITHOUT kernel TUN-write'),('tun_kernel_write_without_completion','Kernel TUN-write WITHOUT completion'),('neither','Neither')]:
    lines.append(f'| {label} | {table_metric(intersection[key])} |')
lines += ['',
 '**922 = 814 + 108**. The 814 TUN-kernel samples are a subset of the 922 completion samples, not an additional 46.41%. Of the 108 difference, **46 still show `product_vpn_tun_write_once`** (libc write, syscall/VFS/security and some freeing paths); **62 do not show that wrapper**. Thus 108 is not a pure bookkeeping/free budget.',
 '',
 'Concrete difference leaves: `product_origin_reclaim_flush` 15, `product_packet_origin_completion_node_fn` 13, libc `__memset_aarch64` 12, `product_vpn_tun_complete_from_graph` 9 and libc `write` 7. The inclusive write-wrapper scope is 860 = 814 + 46. Inclusive completion-origin anchors cover 923, one above the original phase count: `tun_resume_reads` is classified read_readiness despite its observed completion caller.',
 '', '## Independently verified leaf/path cross-tabs','',
 'Owner `_raw_spin_unlock_irq` self: **235** samples, **11.23% owner**, **6.11% global**. Its observed paths form this exclusive partition:', '',
 '| Observed path for that leaf | Samples | % of 235 leaf samples | Owner % | Global % |',
 '| --- | ---: | ---: | ---: | ---: |']
for name,row in cross_tabs['owner_spin_unlock_irq']['observed_paths'].items():
    lines.append(f"| {name} | {row['samples']} | {percent(row['fraction_selected_samples'])} | {percent(row['fraction_thread_samples'])} | {percent(row['fraction_global_samples'])} |")
lines += ['',
 'Within the 186 eventfd-write samples, **137 (73.66%)** follow `vlib_thread_wakeup → vlib_buffer_enqueue_to_thread_retained_fn → product_completion_batch_publish`; **49 (26.34%)** follow `product_observation_publish → export_record → product_observation_observed`. Those are CPU locations under notification paths, not spin waiting or counts of writes/wakeups/notifications. Existing pending latches are not measured by these samples.',
 '',
 'I/O `ipt_do_table` self: **125** samples, **7.13% I/O**, **3.25% global**; all 125 have observed `tun_get_user`/`tun_chr_write_iter` ancestry. Example: `ipt_do_table → nf_hook_slow → ... → tun_get_user → ... → product_vpn_tun_write_once → product_vpn_tun_complete_from_graph`. Within the broader 814 TUN-kernel subset, TCP/IP anchors cover 585, netfilter 324, kernel checksum 56 and from-user copy 35; these overlap.',
 '',
 'Limits: input has zero unresolved observed frames and no reported loss/truncation, but coroutine cuts, inline omissions, generic helpers and PLT/TLS targets prevent a complete causal budget. Kernel/module names are device-record symbols, not independently rebuilt/source-line verified. No new device run, build, Product edit, external write or test suite was performed.',
 '', 'Reproduce from the repository root:', '',
 '```sh',
 'rtk proxy python3 tests/benchmark/tcp_single_little_profile.py \\',
 '  --source build-output/tcp-single-little-profile-20261022/profile-single-little/attribution.json \\',
 '  --output build-output/tcp-single-little-deep-analysis-20261022',
 '```','',
 f"Schema: `{report['schema']}`; rule schema: `{report['rules']['schema']}`. Exact leaf assignments, inclusive anchor sets, raw chain IDs and integer periods are retained in `profile-decomposition.json`.",'',
 f"Tool SHA-256: `{report['tool']['sha256']}`.",
 f"Input SHA-256: `{report['input']['sha256']}`.",
 f"Runtime: Python {sys.version.split()[0]}, standard library only."]
(OUT/'findings.md').write_text('\n'.join(lines)+'\n')
print(OUT/'profile-decomposition.json')
print(OUT/'findings.md')

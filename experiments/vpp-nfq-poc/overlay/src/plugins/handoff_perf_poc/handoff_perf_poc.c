/* SPDX-License-Identifier: Apache-2.0 */

/*
 * PROTOTYPE ONLY.
 *
 * Question: what incremental throughput, cycles, congestion, and sampled
 * latency does VLIB frame-queue transfer add for zero, one, and two
 * cross-thread transfers when buffer allocation and terminal free work are
 * otherwise held constant?
 */

#include <vlib/vlib.h>
#include <vlib/buffer_node.h>
#include <vlib/threads.h>

#define HANDOFF_PERF_MAX_THREADS 32
#define HANDOFF_PERF_MAX_BURST VLIB_FRAME_SIZE
#define HANDOFF_PERF_HIST_BUCKETS 64
#define HANDOFF_PERF_MAX_TOKENS 16384
#define HANDOFF_PERF_RECLAIM_CAPACITY 32768
#define HANDOFF_PERF_EXACT_LATENCY_CAPACITY 4096

typedef enum {
    HANDOFF_PERF_MODE_LOCAL,
    HANDOFF_PERF_MODE_ONE,
    HANDOFF_PERF_MODE_RETURN,
    HANDOFF_PERF_MODE_MIXED_FASTPATH,
    HANDOFF_PERF_MODE_ALWAYS_ENQUEUE,
} handoff_perf_mode_t;

typedef enum {
    HANDOFF_PERF_DIST_HOT,
    HANDOFF_PERF_DIST_UNIFORM,
} handoff_perf_distribution_t;

typedef struct {
    CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
    u64 worker_packets;
    u64 terminal_packets;
    u64 terminal_bytes;
    u64 return_enqueued;
    u64 return_drops;
    u64 return_enqueue_cycles;
    u64 latency_samples;
    u64 latency_cycles_sum;
    u64 latency_cycles_min;
    u64 latency_cycles_max;
    u64 latency_hist[HANDOFF_PERF_HIST_BUCKETS];
} handoff_perf_thread_stats_t;

typedef struct {
    CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
    u32 head;
    CLIB_CACHE_LINE_ALIGN_MARK(cacheline1);
    u32 tail;
    CLIB_CACHE_LINE_ALIGN_MARK(cacheline2);
    u32 buffers[HANDOFF_PERF_RECLAIM_CAPACITY];
} handoff_perf_reclaim_ring_t;

typedef struct {
    u8 running;
    handoff_perf_mode_t mode;
    handoff_perf_distribution_t distribution;
    u32 burst_size;
    u32 packet_size;
    u32 sample_rate;
    u64 sample_seed;
    u32 configured_tokens;
    u32 live_tokens;
    u32 available_count;
    u32 available[HANDOFF_PERF_MAX_TOKENS];
    u64 offered_pps;
    f64 rate_credit;
    f64 rate_fraction;
    f64 rate_last_schedule;
    f64 rate_next_wake;
    f64 rate_tick_seconds;
    u64 scheduled_packets;
    u64 rate_timer_wakes;
    u64 rate_timer_missed_wakes;
    u64 wake_requests;
    u32 worker_count;
    u8 wake_workers;
    u32 worker_fq_index;
    u32 return_fq_index;
    u64 generated_packets;
    u64 generated_bytes;
    u64 local_packets;
    u64 ingress_enqueued;
    u64 ingress_drops;
    u64 alloc_errors;
    u64 reclaimed_packets;
    u64 reclaim_overflows;
    u64 clock_anomalies;
    u64 credit_stalls;
    u64 producer_cycles;
    u64 producer_batches;
    u64 primary_enqueue_cycles;
    u64 primary_enqueue_calls;
    u64 sampled_remote_enqueues;
    u64 sampled_target_sleeping;
    u32 exact_latency_count;
    u64 exact_latency_overflows;
    u64 exact_latency[HANDOFF_PERF_EXACT_LATENCY_CAPACITY];
    u32 exact_sleep_latency_count;
    u64 exact_sleep_latency_overflows;
    u64 exact_sleep_latency[HANDOFF_PERF_EXACT_LATENCY_CAPACITY];
    f64 measurement_started;
    f64 measurement_stopped;
    handoff_perf_thread_stats_t thread[HANDOFF_PERF_MAX_THREADS];
    handoff_perf_reclaim_ring_t reclaim[HANDOFF_PERF_MAX_THREADS];
} handoff_perf_main_t;

static handoff_perf_main_t handoff_perf_main;
#ifdef HANDOFF_PERF_WAKE_PATCH
extern u8 vlib_frame_queue_wakeup_mode;
#endif

typedef struct {
    u64 wake_calls;
    u64 wake_sleeps_seen;
    u64 wake_pending_claims;
    u64 wake_writes;
    u64 wake_write_errors;
    u64 wake_write_retries;
    u64 wake_write_eagain;
    u64 wake_epoch_max;
    u64 wake_faults;
    u64 wake_fault_code;
    u64 wake_phase_awake;
    u64 wake_phase_preparing;
    u64 wake_phase_sleeping;
    u64 wake_phase_notified;
    u64 wake_phase_draining;
    u64 wake_phase_notifying;
    u64 sleep_attempts;
    u64 sleep_frame_queue_rechecks;
    u64 sleep_epoll_wakeups;
    u64 sleep_epoll_timeouts;
    u64 sleep_cycles;
    u64 sleep_max_cycles;
    u64 fq_full_waits;
    u64 fq_full_wait_cycles;
    u64 fq_full_wait_max_cycles;
} handoff_perf_diagnostics_t;

extern vlib_node_registration_t handoff_perf_source_node;
extern vlib_node_registration_t handoff_perf_worker_node;
extern vlib_node_registration_t handoff_perf_completion_node;
extern vlib_node_registration_t handoff_perf_rate_process_node;

static const char *handoff_perf_mode_name(handoff_perf_mode_t mode) {
    switch (mode) {
    case HANDOFF_PERF_MODE_LOCAL:
        return "local";
    case HANDOFF_PERF_MODE_ONE:
        return "handoff-one";
    case HANDOFF_PERF_MODE_RETURN:
        return "handoff-return";
    case HANDOFF_PERF_MODE_MIXED_FASTPATH:
        return "mixed-local-fastpath";
    case HANDOFF_PERF_MODE_ALWAYS_ENQUEUE:
        return "always-enqueue";
    }
    return "unknown";
}

static const char *handoff_perf_distribution_name(handoff_perf_distribution_t distribution) {
    return distribution == HANDOFF_PERF_DIST_UNIFORM ? "uniform" : "hot";
}

static u64 handoff_perf_outstanding_packets(handoff_perf_main_t *hm) {
    u64 settled = hm->ingress_drops;

    for (u32 thread = 0; thread < HANDOFF_PERF_MAX_THREADS; thread++) {
        settled += hm->thread[thread].terminal_packets;
        settled += hm->thread[thread].return_drops;
    }
    return settled <= hm->generated_packets ? hm->generated_packets - settled : ~0ULL;
}

static clib_error_t *handoff_perf_set_wake_mode(vlib_main_t *vm, handoff_perf_main_t *hm,
                                                u8 mode) {
    u64 outstanding = handoff_perf_outstanding_packets(hm);

    if (hm->running || hm->live_tokens != 0 || outstanding != 0)
        return clib_error_return(0,
                                 "wake mode change requires stopped benchmark with zero "
                                 "live/outstanding packets");
#ifdef HANDOFF_PERF_WAKE_PATCH
    clib_error_t *error = 0;

    if (vm->thread_index != 0)
        return clib_error_return(0, "wake mode change requires main thread");

    /* Barrier wakeups use the old mode; publish the new mode only inside. */
    vlib_worker_thread_barrier_sync(vm);
    for (u32 thread = 0; thread < vlib_get_n_threads(); thread++) {
        vlib_main_t *thread_vm = vlib_get_main_by_index(thread);
        u64 state = __atomic_load_n(&thread_vm->wakeup_epoch_state, __ATOMIC_ACQUIRE);
        u32 fault = __atomic_load_n(&thread_vm->wakeup_channel_fault, __ATOMIC_ACQUIRE);

        if (vlib_wakeup_epoch_phase(state) == VLIB_WAKE_PHASE_NOTIFYING) {
            error = clib_error_return(0, "thread %u still owns a wake write", thread);
            break;
        }
        if (fault != VLIB_WAKE_FAULT_NONE) {
            error = clib_error_return(0, "thread %u has stable wake fault %u", thread, fault);
            break;
        }
    }
    if (error == 0) {
        for (u32 thread = 0; thread < vlib_get_n_threads(); thread++) {
            vlib_main_t *thread_vm = vlib_get_main_by_index(thread);
            u64 state = __atomic_load_n(&thread_vm->wakeup_epoch_state, __ATOMIC_ACQUIRE);

            __atomic_store_n(&thread_vm->thread_sleeps, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&thread_vm->wakeup_pending, 0, __ATOMIC_RELEASE);
            __atomic_store_n(&thread_vm->wakeup_epoch_state,
                             (state & VLIB_WAKE_EPOCH_MASK) | VLIB_WAKE_PHASE_AWAKE,
                             __ATOMIC_RELEASE);
        }
        __atomic_store_n(&vlib_frame_queue_wakeup_mode, mode, __ATOMIC_RELEASE);
    }
    vlib_worker_thread_barrier_release(vm);
    if (error != 0)
        return error;
#endif
    hm->wake_workers = mode;
    return 0;
}

static void handoff_perf_reset_stats(handoff_perf_main_t *hm) {
    hm->generated_packets = 0;
    hm->generated_bytes = 0;
    hm->local_packets = 0;
    hm->ingress_enqueued = 0;
    hm->ingress_drops = 0;
    hm->alloc_errors = 0;
    hm->reclaimed_packets = 0;
    hm->reclaim_overflows = 0;
    hm->clock_anomalies = 0;
    hm->credit_stalls = 0;
    hm->producer_cycles = 0;
    hm->producer_batches = 0;
    hm->primary_enqueue_cycles = 0;
    hm->primary_enqueue_calls = 0;
    hm->sampled_remote_enqueues = 0;
    hm->sampled_target_sleeping = 0;
    hm->exact_latency_count = 0;
    hm->exact_latency_overflows = 0;
    hm->exact_sleep_latency_count = 0;
    hm->exact_sleep_latency_overflows = 0;
    hm->scheduled_packets = 0;
    hm->rate_timer_wakes = 0;
    hm->rate_timer_missed_wakes = 0;
    hm->wake_requests = 0;
    hm->measurement_started = 0;
    hm->measurement_stopped = 0;
    clib_memset(hm->thread, 0, sizeof(hm->thread));
}

static void handoff_perf_reset_diagnostics(handoff_perf_main_t *hm) {
#ifdef HANDOFF_PERF_WAKE_PATCH
    vlib_thread_main_t *tm = vlib_get_thread_main();
    u32 fq_indices[] = {hm->worker_fq_index, hm->return_fq_index};

    for (u32 thread = 0; thread < vlib_get_n_threads(); thread++) {
        vlib_main_t *thread_vm = vlib_get_main_by_index(thread);

        __atomic_store_n(&thread_vm->wakeup_calls, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&thread_vm->wakeup_sleeps_seen, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&thread_vm->wakeup_pending_claims, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&thread_vm->wakeup_writes, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&thread_vm->wakeup_write_errors, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&thread_vm->wakeup_write_retries, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&thread_vm->wakeup_write_eagain, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&thread_vm->sleep_attempts, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&thread_vm->sleep_frame_queue_rechecks, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&thread_vm->sleep_epoll_wakeups, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&thread_vm->sleep_epoll_timeouts, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&thread_vm->sleep_cycles, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&thread_vm->sleep_max_cycles, 0, __ATOMIC_RELAXED);
    }

    for (u32 i = 0; i < ARRAY_LEN(fq_indices); i++) {
        vlib_frame_queue_main_t *fqm = vec_elt_at_index(tm->frame_queue_mains, fq_indices[i]);

        for (u32 thread = 0; thread < vlib_get_n_threads(); thread++) {
            vlib_frame_queue_t *fq = fqm->vlib_frame_queues[thread];

            __atomic_store_n(&fq->full_waits, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&fq->full_wait_cycles, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&fq->full_wait_max_cycles, 0, __ATOMIC_RELAXED);
        }
    }
#else
    (void)hm;
#endif
}

static handoff_perf_diagnostics_t handoff_perf_get_diagnostics(handoff_perf_main_t *hm) {
    handoff_perf_diagnostics_t diagnostics = {};
#ifdef HANDOFF_PERF_WAKE_PATCH
    vlib_thread_main_t *tm = vlib_get_thread_main();
    u32 fq_indices[] = {hm->worker_fq_index, hm->return_fq_index};

    for (u32 thread = 0; thread < vlib_get_n_threads(); thread++) {
        vlib_main_t *thread_vm = vlib_get_main_by_index(thread);
        u64 wake_state;
        u32 wake_fault;
        vlib_wake_phase_t wake_phase;

        diagnostics.wake_calls += __atomic_load_n(&thread_vm->wakeup_calls, __ATOMIC_RELAXED);
        diagnostics.wake_sleeps_seen +=
            __atomic_load_n(&thread_vm->wakeup_sleeps_seen, __ATOMIC_RELAXED);
        diagnostics.wake_pending_claims +=
            __atomic_load_n(&thread_vm->wakeup_pending_claims, __ATOMIC_RELAXED);
        diagnostics.wake_writes += __atomic_load_n(&thread_vm->wakeup_writes, __ATOMIC_RELAXED);
        diagnostics.wake_write_errors +=
            __atomic_load_n(&thread_vm->wakeup_write_errors, __ATOMIC_RELAXED);
        diagnostics.wake_write_retries +=
            __atomic_load_n(&thread_vm->wakeup_write_retries, __ATOMIC_RELAXED);
        diagnostics.wake_write_eagain +=
            __atomic_load_n(&thread_vm->wakeup_write_eagain, __ATOMIC_RELAXED);
        wake_state = __atomic_load_n(&thread_vm->wakeup_epoch_state, __ATOMIC_ACQUIRE);
        wake_phase = vlib_wakeup_epoch_phase(wake_state);
        diagnostics.wake_epoch_max = clib_max(diagnostics.wake_epoch_max, wake_state >> 3);
        wake_fault = __atomic_load_n(&thread_vm->wakeup_channel_fault, __ATOMIC_ACQUIRE);
        if (wake_fault != VLIB_WAKE_FAULT_NONE) {
            diagnostics.wake_faults++;
            if (diagnostics.wake_fault_code == VLIB_WAKE_FAULT_NONE)
                diagnostics.wake_fault_code = wake_fault;
        }
        diagnostics.wake_phase_awake += wake_phase == VLIB_WAKE_PHASE_AWAKE;
        diagnostics.wake_phase_preparing +=
            wake_phase == VLIB_WAKE_PHASE_PREPARING_TO_SLEEP;
        diagnostics.wake_phase_sleeping += wake_phase == VLIB_WAKE_PHASE_SLEEPING;
        diagnostics.wake_phase_notified += wake_phase == VLIB_WAKE_PHASE_NOTIFIED;
        diagnostics.wake_phase_draining += wake_phase == VLIB_WAKE_PHASE_DRAINING;
        diagnostics.wake_phase_notifying += wake_phase == VLIB_WAKE_PHASE_NOTIFYING;
        diagnostics.sleep_attempts += __atomic_load_n(&thread_vm->sleep_attempts, __ATOMIC_RELAXED);
        diagnostics.sleep_frame_queue_rechecks +=
            __atomic_load_n(&thread_vm->sleep_frame_queue_rechecks, __ATOMIC_RELAXED);
        diagnostics.sleep_epoll_wakeups +=
            __atomic_load_n(&thread_vm->sleep_epoll_wakeups, __ATOMIC_RELAXED);
        diagnostics.sleep_epoll_timeouts +=
            __atomic_load_n(&thread_vm->sleep_epoll_timeouts, __ATOMIC_RELAXED);
        diagnostics.sleep_cycles += __atomic_load_n(&thread_vm->sleep_cycles, __ATOMIC_RELAXED);
        diagnostics.sleep_max_cycles =
            clib_max(diagnostics.sleep_max_cycles,
                     __atomic_load_n(&thread_vm->sleep_max_cycles, __ATOMIC_RELAXED));
    }

    for (u32 i = 0; i < ARRAY_LEN(fq_indices); i++) {
        vlib_frame_queue_main_t *fqm = vec_elt_at_index(tm->frame_queue_mains, fq_indices[i]);

        for (u32 thread = 0; thread < vlib_get_n_threads(); thread++) {
            vlib_frame_queue_t *fq = fqm->vlib_frame_queues[thread];

            diagnostics.fq_full_waits += __atomic_load_n(&fq->full_waits, __ATOMIC_RELAXED);
            diagnostics.fq_full_wait_cycles +=
                __atomic_load_n(&fq->full_wait_cycles, __ATOMIC_RELAXED);
            diagnostics.fq_full_wait_max_cycles =
                clib_max(diagnostics.fq_full_wait_max_cycles,
                         __atomic_load_n(&fq->full_wait_max_cycles, __ATOMIC_RELAXED));
        }
    }
#else
    (void)hm;
#endif
    return diagnostics;
}

static void handoff_perf_reset_reclaim(handoff_perf_main_t *hm) {
    for (u32 thread = 0; thread < HANDOFF_PERF_MAX_THREADS; thread++) {
        __atomic_store_n(&hm->reclaim[thread].head, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&hm->reclaim[thread].tail, 0, __ATOMIC_RELAXED);
    }
}

static void handoff_perf_reset_rate(handoff_perf_main_t *hm, vlib_main_t *vm) {
    f64 now = vlib_time_now(vm);

    hm->rate_credit = 0;
    hm->rate_fraction = 0;
    hm->rate_tick_seconds = 100e-6;
    hm->rate_last_schedule = now;
    hm->rate_next_wake = now + hm->rate_tick_seconds;
}

static int handoff_perf_reclaim_push(handoff_perf_main_t *hm, u32 thread_index, u32 buffer) {
    handoff_perf_reclaim_ring_t *ring = &hm->reclaim[thread_index];
    u32 head = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);
    u32 tail = __atomic_load_n(&ring->tail, __ATOMIC_ACQUIRE);

    if (head - tail >= HANDOFF_PERF_RECLAIM_CAPACITY)
        return 0;
    ring->buffers[head & (HANDOFF_PERF_RECLAIM_CAPACITY - 1)] = buffer;
    __atomic_store_n(&ring->head, head + 1, __ATOMIC_RELEASE);
    return 1;
}

static void handoff_perf_drain_reclaim(handoff_perf_main_t *hm) {
    for (u32 thread = 0; thread < vlib_get_n_threads(); thread++) {
        handoff_perf_reclaim_ring_t *ring = &hm->reclaim[thread];
        u32 tail = __atomic_load_n(&ring->tail, __ATOMIC_RELAXED);
        u32 head = __atomic_load_n(&ring->head, __ATOMIC_ACQUIRE);

        while (tail != head && hm->available_count < HANDOFF_PERF_MAX_TOKENS) {
            hm->available[hm->available_count++] =
                ring->buffers[tail & (HANDOFF_PERF_RECLAIM_CAPACITY - 1)];
            hm->reclaimed_packets++;
            tail++;
        }
        __atomic_store_n(&ring->tail, tail, __ATOMIC_RELEASE);
    }
}

static_always_inline u8 handoff_perf_should_sample(handoff_perf_main_t *hm, u64 sequence) {
    u64 value;

    if (hm->sample_rate == 0)
        return 0;
    value = sequence + hm->sample_seed + 0x9e3779b97f4a7c15ULL;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
    value ^= value >> 31;
    return value % hm->sample_rate == 0;
}

static_always_inline void handoff_perf_set_publish_timestamp(vlib_main_t *vm, u32 *buffers,
                                                             u32 count, u64 now) {
    for (u32 i = 0; i < count; i++) {
        vlib_buffer_t *b = vlib_get_buffer(vm, buffers[i]);

        b->opaque[0] = (u32)now;
        b->opaque[1] = (u32)(now >> 32);
    }
}

static u32 handoff_perf_hist_bucket(u64 cycles) {
    u32 bucket = 0;

    while (cycles > 1 && bucket + 1 < HANDOFF_PERF_HIST_BUCKETS) {
        cycles >>= 1;
        bucket++;
    }
    return bucket;
}

static void handoff_perf_note_terminal(handoff_perf_main_t *hm, vlib_main_t *vm, u32 *buffers,
                                       u32 count) {
    u32 thread_index = vlib_get_thread_index();
    handoff_perf_thread_stats_t *stats;
    u64 now = clib_cpu_time_now();

    ASSERT(thread_index < HANDOFF_PERF_MAX_THREADS);
    stats = &hm->thread[thread_index];
    stats->terminal_packets += count;
    stats->terminal_bytes += (u64)count * hm->packet_size;

    for (u32 i = 0; i < count; i++) {
        vlib_buffer_t *b = vlib_get_buffer(vm, buffers[i]);
        u64 started = ((u64)b->opaque[1] << 32) | b->opaque[0];

        if (started != 0) {
            u64 cycles;

            if (PREDICT_FALSE(now < started)) {
                hm->clock_anomalies++;
                continue;
            }
            cycles = now - started;
            u32 bucket = handoff_perf_hist_bucket(cycles);
            stats->latency_samples++;
            stats->latency_cycles_sum += cycles;
            stats->latency_cycles_min = stats->latency_cycles_min == 0
                                            ? cycles
                                            : clib_min(stats->latency_cycles_min, cycles);
            stats->latency_cycles_max = clib_max(stats->latency_cycles_max, cycles);
            stats->latency_hist[bucket]++;
            u32 exact_index = __atomic_fetch_add(&hm->exact_latency_count, 1, __ATOMIC_RELAXED);
            if (exact_index < HANDOFF_PERF_EXACT_LATENCY_CAPACITY)
                hm->exact_latency[exact_index] = cycles;
            else
                __atomic_fetch_add(&hm->exact_latency_overflows, 1, __ATOMIC_RELAXED);
            if (b->opaque[2] != 0) {
                u32 sleep_index =
                    __atomic_fetch_add(&hm->exact_sleep_latency_count, 1, __ATOMIC_RELAXED);
                if (sleep_index < HANDOFF_PERF_EXACT_LATENCY_CAPACITY)
                    hm->exact_sleep_latency[sleep_index] = cycles;
                else
                    __atomic_fetch_add(&hm->exact_sleep_latency_overflows, 1,
                                       __ATOMIC_RELAXED);
            }
        }
    }

    for (u32 i = 0; i < count; i++)
        if (!handoff_perf_reclaim_push(hm, thread_index, buffers[i])) {
            stats->terminal_packets--;
            stats->terminal_bytes -= hm->packet_size;
            hm->reclaim_overflows++;
            __atomic_fetch_sub(&hm->live_tokens, 1, __ATOMIC_RELAXED);
            vlib_buffer_free_one(vm, buffers[i]);
        }
}

static u64 handoff_perf_hist_quantile(handoff_perf_main_t *hm, u32 numerator, u32 denominator) {
    u64 hist[HANDOFF_PERF_HIST_BUCKETS] = {};
    u64 total = 0;
    u64 target;
    u64 seen = 0;

    for (u32 thread = 0; thread < HANDOFF_PERF_MAX_THREADS; thread++)
        for (u32 bucket = 0; bucket < HANDOFF_PERF_HIST_BUCKETS; bucket++) {
            hist[bucket] += hm->thread[thread].latency_hist[bucket];
            total += hm->thread[thread].latency_hist[bucket];
        }

    if (total == 0)
        return 0;
    target = (total * numerator + denominator - 1) / denominator;
    for (u32 bucket = 0; bucket < HANDOFF_PERF_HIST_BUCKETS; bucket++) {
        seen += hist[bucket];
        if (seen >= target)
            return (u64)1 << bucket;
    }
    return (u64)1 << (HANDOFF_PERF_HIST_BUCKETS - 1);
}

static int handoff_perf_u64_compare(const void *a, const void *b) {
    u64 left = *(const u64 *)a;
    u64 right = *(const u64 *)b;
    return (left > right) - (left < right);
}

static u16 handoff_perf_remote_target(handoff_perf_main_t *hm, u64 sequence) {
    if (hm->distribution == HANDOFF_PERF_DIST_HOT)
        return 1;
    return (u16)(1 + (sequence % hm->worker_count));
}

static_always_inline void handoff_perf_wake_targets(handoff_perf_main_t *hm, u16 *targets,
                                                    u32 count) {
    u32 seen = 0;

    if (hm->wake_workers != 1)
        return;
    for (u32 i = 0; i < count; i++) {
        u32 bit = (u32)1 << targets[i];

        if (seen & bit)
            continue;
        seen |= bit;
        vlib_thread_wakeup(targets[i]);
        __atomic_fetch_add(&hm->wake_requests, 1, __ATOMIC_RELAXED);
    }
}

static u32 handoff_perf_rate_budget(handoff_perf_main_t *hm) {
    if (hm->offered_pps != 0) {
        if (hm->rate_credit < hm->burst_size)
            return 0;
        hm->rate_credit -= hm->burst_size;
    }
    return hm->burst_size;
}

typedef enum {
    HANDOFF_PERF_SOURCE_NEXT_COMPLETION,
    HANDOFF_PERF_SOURCE_N_NEXT,
} handoff_perf_source_next_t;

VLIB_NODE_FN(handoff_perf_source_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    handoff_perf_main_t *hm = &handoff_perf_main;
    u32 buffers[HANDOFF_PERF_MAX_BURST];
    u32 remote_buffers[HANDOFF_PERF_MAX_BURST];
    u32 local_buffers[HANDOFF_PERF_MAX_BURST];
    u32 remote_sample_buffers[HANDOFF_PERF_MAX_BURST];
    u32 local_sample_buffers[HANDOFF_PERF_MAX_BURST];
    u16 targets[HANDOFF_PERF_MAX_BURST];
    u32 budget;
    u32 allocated;
    u32 remote_count = 0;
    u32 local_count = 0;
    u32 remote_sample_count = 0;
    u32 local_sample_count = 0;
    u64 batch_started;

    (void)frame;
    if (!hm->running || vlib_get_thread_index() != 0)
        return 0;

    handoff_perf_drain_reclaim(hm);
    budget = handoff_perf_rate_budget(hm);
    if (budget == 0)
        goto rearm;

    if (hm->available_count < budget) {
        if (hm->offered_pps != 0)
            hm->rate_credit += budget;
        budget = 0;
        hm->credit_stalls++;
        goto rearm;
    }
    batch_started = clib_cpu_time_now();
    allocated = budget;
    for (u32 i = 0; i < allocated; i++)
        buffers[i] = hm->available[--hm->available_count];

    for (u32 i = 0; i < budget; i++) {
        vlib_buffer_t *b = vlib_get_buffer(vm, buffers[i]);
        u64 sequence = hm->generated_packets + i;
        u16 target = handoff_perf_remote_target(hm, sequence);
        u8 is_local = hm->mode == HANDOFF_PERF_MODE_LOCAL ||
                      ((hm->mode == HANDOFF_PERF_MODE_MIXED_FASTPATH ||
                        hm->mode == HANDOFF_PERF_MODE_ALWAYS_ENQUEUE) &&
                       (sequence & 1) == 0);

        b->opaque[0] = 0;
        b->opaque[1] = 0;
        b->opaque[2] = 0;
        ((u8 *)vlib_buffer_get_current(b))[0] = (u8)sequence;
        ((u8 *)vlib_buffer_get_current(b))[1] = (u8)(sequence >> 8);

        if (is_local && hm->mode != HANDOFF_PERF_MODE_ALWAYS_ENQUEUE) {
            local_buffers[local_count++] = buffers[i];
            if (handoff_perf_should_sample(hm, sequence))
                local_sample_buffers[local_sample_count++] = buffers[i];
        } else {
            remote_buffers[remote_count] = buffers[i];
            if ((hm->mode == HANDOFF_PERF_MODE_MIXED_FASTPATH ||
                 hm->mode == HANDOFF_PERF_MODE_ALWAYS_ENQUEUE) &&
                !is_local)
                target = handoff_perf_remote_target(hm, sequence >> 1);
            targets[remote_count] = is_local ? 0 : target;
            remote_count++;
            if (handoff_perf_should_sample(hm, sequence)) {
                remote_sample_buffers[remote_sample_count++] = buffers[i];
                hm->sampled_remote_enqueues++;
#ifdef HANDOFF_PERF_WAKE_PATCH
                if (vlib_thread_is_sleeping(vlib_get_main_by_index(target))) {
#else
                if (__atomic_load_n(&vlib_get_main_by_index(target)->thread_sleeps,
                                    __ATOMIC_ACQUIRE)) {
#endif
                    hm->sampled_target_sleeping++;
                    vlib_get_buffer(vm, buffers[i])->opaque[2] = 1;
                }
            }
        }
    }

    hm->generated_packets += budget;
    hm->generated_bytes += (u64)budget * hm->packet_size;

    if (local_count != 0) {
        hm->local_packets += local_count;
        handoff_perf_set_publish_timestamp(vm, local_sample_buffers, local_sample_count,
                                           clib_cpu_time_now());
        vlib_buffer_enqueue_to_single_next(vm, node, local_buffers,
                                           HANDOFF_PERF_SOURCE_NEXT_COMPLETION, local_count);
    }

    if (remote_count != 0) {
        u64 enqueue_started;

        handoff_perf_set_publish_timestamp(vm, remote_sample_buffers, remote_sample_count,
                                           clib_cpu_time_now());
        enqueue_started = clib_cpu_time_now();
        u32 enqueued =
            vlib_buffer_enqueue_to_thread(vm, node, hm->worker_fq_index, remote_buffers, targets,
                                          remote_count, 0 /* backpressure, never drop */);
        handoff_perf_wake_targets(hm, targets, enqueued);
        hm->ingress_enqueued += enqueued;
        hm->ingress_drops += remote_count - enqueued;
        hm->primary_enqueue_cycles += clib_cpu_time_now() - enqueue_started;
        hm->primary_enqueue_calls++;
        if (enqueued != remote_count)
            __atomic_fetch_sub(&hm->live_tokens, remote_count - enqueued, __ATOMIC_RELAXED);
    }

    hm->producer_cycles += clib_cpu_time_now() - batch_started;
    hm->producer_batches++;
rearm:
    if (hm->running && (hm->offered_pps == 0 || (hm->rate_credit >= hm->burst_size &&
                                                 hm->available_count >= hm->burst_size)))
        vlib_node_set_interrupt_pending(vm, handoff_perf_source_node.index);
    return budget;
}

VLIB_REGISTER_NODE(handoff_perf_source_node) = {
    .name = "handoff-perf-source",
    .function = handoff_perf_source_node_fn,
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_INTERRUPT,
    .vector_size = sizeof(u32),
    .n_next_nodes = HANDOFF_PERF_SOURCE_N_NEXT,
    .next_nodes =
        {
            [HANDOFF_PERF_SOURCE_NEXT_COMPLETION] = "handoff-perf-completion",
        },
};

static uword handoff_perf_rate_process(vlib_main_t *vm, vlib_node_runtime_t *node,
                                       vlib_frame_t *frame) {
    handoff_perf_main_t *hm = &handoff_perf_main;
    uword *event_data = 0;

    (void)node;
    (void)frame;
    while (1) {
        f64 wait = 1e9;

        if (hm->running && hm->offered_pps != 0) {
            f64 now = vlib_time_now(vm);

            if (now >= hm->rate_next_wake) {
                f64 packet_credit =
                    (now - hm->rate_last_schedule) * hm->offered_pps + hm->rate_fraction;
                u64 granted = (u64)packet_credit;
                u64 elapsed_ticks = 1 + (u64)((now - hm->rate_next_wake) / hm->rate_tick_seconds);

                hm->rate_fraction = packet_credit - granted;
                hm->rate_credit += granted;
                hm->scheduled_packets += granted;
                hm->rate_timer_wakes++;
                hm->rate_timer_missed_wakes += elapsed_ticks - 1;
                hm->rate_last_schedule = now;
                hm->rate_next_wake += elapsed_ticks * hm->rate_tick_seconds;
                if (hm->rate_credit >= hm->burst_size)
                    vlib_node_set_interrupt_pending(vm, handoff_perf_source_node.index);
            }
            wait = clib_max(hm->rate_next_wake - vlib_time_now(vm), 1e-6);
        }
        vlib_process_wait_for_event_or_clock(vm, wait);
        (void)vlib_process_get_events(vm, &event_data);
        vec_reset_length(event_data);
    }
    return 0;
}

VLIB_REGISTER_NODE(handoff_perf_rate_process_node) = {
    .function = handoff_perf_rate_process,
    .name = "handoff-perf-rate-process",
    .type = VLIB_NODE_TYPE_PROCESS,
};

VLIB_NODE_FN(handoff_perf_worker_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    handoff_perf_main_t *hm = &handoff_perf_main;
    u32 *buffers = vlib_frame_vector_args(frame);
    u32 count = frame->n_vectors;

    hm->thread[vlib_get_thread_index()].worker_packets += count;

    if (hm->mode != HANDOFF_PERF_MODE_RETURN) {
        handoff_perf_note_terminal(hm, vm, buffers, count);
        return count;
    }

    {
        handoff_perf_thread_stats_t *stats = &hm->thread[vlib_get_thread_index()];
        u16 targets[HANDOFF_PERF_MAX_BURST];
        u64 started = clib_cpu_time_now();
        u32 enqueued;

        for (u32 i = 0; i < count; i++)
            targets[i] = 0;
        enqueued = vlib_buffer_enqueue_to_thread(vm, node, hm->return_fq_index, buffers, targets,
                                                 count, 0 /* backpressure, never drop */);
        handoff_perf_wake_targets(hm, targets, enqueued);
        stats->return_enqueued += enqueued;
        stats->return_drops += count - enqueued;
        stats->return_enqueue_cycles += clib_cpu_time_now() - started;
        if (enqueued != count)
            __atomic_fetch_sub(&hm->live_tokens, count - enqueued, __ATOMIC_RELAXED);
    }
    return count;
}

VLIB_REGISTER_NODE(handoff_perf_worker_node) = {
    .name = "handoff-perf-worker",
    .function = handoff_perf_worker_node_fn,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .vector_size = sizeof(u32),
};

VLIB_NODE_FN(handoff_perf_completion_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    handoff_perf_main_t *hm = &handoff_perf_main;
    u32 *buffers = vlib_frame_vector_args(frame);

    (void)node;
    handoff_perf_note_terminal(hm, vm, buffers, frame->n_vectors);
    return frame->n_vectors;
}

VLIB_REGISTER_NODE(handoff_perf_completion_node) = {
    .name = "handoff-perf-completion",
    .function = handoff_perf_completion_node_fn,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .vector_size = sizeof(u32),
};

static clib_error_t *handoff_perf_start_command_fn(vlib_main_t *vm, unformat_input_t *input,
                                                   vlib_cli_command_t *cmd) {
    handoff_perf_main_t *hm = &handoff_perf_main;
    handoff_perf_mode_t mode = HANDOFF_PERF_MODE_LOCAL;
    handoff_perf_distribution_t distribution = HANDOFF_PERF_DIST_HOT;
    u32 burst = 64;
    u32 packet_size = 64;
    u32 sample_rate = 1024;
    u32 configured_tokens = 8192;
    u64 offered_pps = 0;
    u64 sample_seed = 20260802;
    u32 wake_workers = 0;
    clib_error_t *error;

    (void)cmd;
    if (hm->running)
        return clib_error_return(0, "benchmark is already running");

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "mode local"))
            mode = HANDOFF_PERF_MODE_LOCAL;
        else if (unformat(input, "mode handoff-one"))
            mode = HANDOFF_PERF_MODE_ONE;
        else if (unformat(input, "mode handoff-return"))
            mode = HANDOFF_PERF_MODE_RETURN;
        else if (unformat(input, "mode mixed-local-fastpath"))
            mode = HANDOFF_PERF_MODE_MIXED_FASTPATH;
        else if (unformat(input, "mode always-enqueue"))
            mode = HANDOFF_PERF_MODE_ALWAYS_ENQUEUE;
        else if (unformat(input, "distribution hot"))
            distribution = HANDOFF_PERF_DIST_HOT;
        else if (unformat(input, "distribution uniform"))
            distribution = HANDOFF_PERF_DIST_UNIFORM;
        else if (unformat(input, "burst %u", &burst))
            ;
        else if (unformat(input, "packet-size %u", &packet_size))
            ;
        else if (unformat(input, "sample-rate %u", &sample_rate))
            ;
        else if (unformat(input, "tokens %u", &configured_tokens))
            ;
        else if (unformat(input, "rate %llu", &offered_pps))
            ;
        else if (unformat(input, "seed %llu", &sample_seed))
            ;
        else if (unformat(input, "wake-workers %u", &wake_workers))
            ;
        else
            return clib_error_return(0, "unknown input `%U'", format_unformat_error, input);
    }

    if (vlib_get_n_threads() < 2)
        return clib_error_return(0, "at least one VPP worker is required");
    if (vlib_get_n_threads() > HANDOFF_PERF_MAX_THREADS)
        return clib_error_return(0, "too many VPP threads (max %u)", HANDOFF_PERF_MAX_THREADS);
    if (burst == 0 || burst > HANDOFF_PERF_MAX_BURST)
        return clib_error_return(0, "burst must be 1..%u", HANDOFF_PERF_MAX_BURST);
    if (packet_size < 2 || packet_size > vlib_buffer_get_default_data_size(vm))
        return clib_error_return(0, "packet-size must be 2..%u",
                                 vlib_buffer_get_default_data_size(vm));
    if (configured_tokens < burst || configured_tokens > HANDOFF_PERF_MAX_TOKENS)
        return clib_error_return(0, "tokens must be burst..%u", HANDOFF_PERF_MAX_TOKENS);
    if (wake_workers > 3)
        return clib_error_return(0, "wake-workers must be 0, 1, 2, or 3");
    if (hm->live_tokens != 0)
        return clib_error_return(0, "previous token pool is not cleaned up");

    error = handoff_perf_set_wake_mode(vm, hm, (u8)wake_workers);
    if (error != 0)
        return error;

    hm->mode = mode;
    hm->distribution = distribution;
    hm->burst_size = burst;
    hm->packet_size = packet_size;
    hm->sample_rate = sample_rate;
    hm->sample_seed = sample_seed;
    hm->configured_tokens = configured_tokens;
    hm->offered_pps = offered_pps;
    hm->worker_count = vlib_get_n_threads() - 1;
    handoff_perf_reset_stats(hm);
    handoff_perf_reset_diagnostics(hm);
    handoff_perf_reset_rate(hm, vm);
    handoff_perf_reset_reclaim(hm);
    hm->available_count = vlib_buffer_alloc(vm, hm->available, configured_tokens);
    hm->live_tokens = hm->available_count;
    if (hm->available_count != configured_tokens) {
        hm->alloc_errors = configured_tokens - hm->available_count;
        if (hm->available_count != 0)
            vlib_buffer_free(vm, hm->available, hm->available_count);
        hm->available_count = 0;
        hm->live_tokens = 0;
        error = handoff_perf_set_wake_mode(vm, hm, 0);
        if (error != 0)
            return error;
        return clib_error_return(0, "could only allocate %u of %u tokens",
                                 configured_tokens - hm->alloc_errors, configured_tokens);
    }
    for (u32 i = 0; i < hm->available_count; i++) {
        vlib_buffer_t *b = vlib_get_buffer(vm, hm->available[i]);
        b->flags = 0;
        b->current_data = 0;
        b->current_length = packet_size;
        clib_memset(vlib_buffer_get_current(b), 0, clib_min(packet_size, 64u));
    }
    hm->running = 1;
    hm->measurement_started = vlib_time_now(vm);
    if (hm->offered_pps == 0)
        vlib_node_set_interrupt_pending(vm, handoff_perf_source_node.index);
    vlib_process_signal_event(vm, handoff_perf_rate_process_node.index, 1, 0);
    vlib_cli_output(vm, "handoff-perf started");
    return 0;
}

VLIB_CLI_COMMAND(handoff_perf_start_command, static) = {
    .path = "handoff-perf start",
    .short_help = "handoff-perf start mode <local|handoff-one|handoff-return|"
                  "mixed-local-fastpath|always-enqueue> burst <1..256> "
                  "packet-size <bytes> distribution <hot|uniform> "
                  "sample-rate <packets> seed <u64> tokens <count> rate <pps|0> "
                  "wake-workers <0|1|2|3>",
    .function = handoff_perf_start_command_fn,
};

static clib_error_t *handoff_perf_stop_command_fn(vlib_main_t *vm, unformat_input_t *input,
                                                  vlib_cli_command_t *cmd) {
    handoff_perf_main_t *hm = &handoff_perf_main;

    (void)input;
    (void)cmd;
    hm->measurement_stopped = vlib_time_now(vm);
    hm->running = 0;
    vlib_process_signal_event(vm, handoff_perf_rate_process_node.index, 1, 0);
    handoff_perf_drain_reclaim(hm);
    vlib_cli_output(vm, "handoff-perf stopped");
    return 0;
}

VLIB_CLI_COMMAND(handoff_perf_stop_command, static) = {
    .path = "handoff-perf stop",
    .short_help = "handoff-perf stop",
    .function = handoff_perf_stop_command_fn,
};

static clib_error_t *handoff_perf_resume_command_fn(vlib_main_t *vm, unformat_input_t *input,
                                                    vlib_cli_command_t *cmd) {
    handoff_perf_main_t *hm = &handoff_perf_main;

    (void)input;
    (void)cmd;
    if (hm->running)
        return clib_error_return(0, "benchmark is already running");
    handoff_perf_drain_reclaim(hm);
    if (hm->live_tokens == 0 || hm->available_count != hm->live_tokens)
        return clib_error_return(0, "token pool is not fully drained");
    handoff_perf_reset_stats(hm);
    handoff_perf_reset_diagnostics(hm);
    handoff_perf_reset_rate(hm, vm);
    hm->running = 1;
    hm->measurement_started = vlib_time_now(vm);
    if (hm->offered_pps == 0)
        vlib_node_set_interrupt_pending(vm, handoff_perf_source_node.index);
    vlib_process_signal_event(vm, handoff_perf_rate_process_node.index, 1, 0);
    vlib_cli_output(vm, "handoff-perf resumed with counters reset");
    return 0;
}

VLIB_CLI_COMMAND(handoff_perf_resume_command, static) = {
    .path = "handoff-perf resume",
    .short_help = "handoff-perf resume",
    .function = handoff_perf_resume_command_fn,
};

static clib_error_t *handoff_perf_cleanup_command_fn(vlib_main_t *vm, unformat_input_t *input,
                                                     vlib_cli_command_t *cmd) {
    handoff_perf_main_t *hm = &handoff_perf_main;
    clib_error_t *error;

    (void)input;
    (void)cmd;
    if (hm->running)
        return clib_error_return(0, "stop benchmark before cleanup");
    handoff_perf_drain_reclaim(hm);
    if (hm->available_count != hm->live_tokens)
        return clib_error_return(0, "%u buffers are still outstanding",
                                 hm->live_tokens - hm->available_count);
    if (hm->available_count != 0)
        vlib_buffer_free(vm, hm->available, hm->available_count);
    hm->available_count = 0;
    hm->live_tokens = 0;
    error = handoff_perf_set_wake_mode(vm, hm, 0);
    if (error != 0)
        return error;
    vlib_cli_output(vm, "handoff-perf token pool cleaned");
    return 0;
}

VLIB_CLI_COMMAND(handoff_perf_cleanup_command, static) = {
    .path = "handoff-perf cleanup",
    .short_help = "handoff-perf cleanup",
    .function = handoff_perf_cleanup_command_fn,
};

static clib_error_t *
handoff_perf_wake_mode_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                   vlib_cli_command_t *cmd)
{
    handoff_perf_main_t *hm = &handoff_perf_main;
    u32 mode = ~0;
    clib_error_t *error;

    (void) vm;
    (void) cmd;
    if (!unformat (input, "%u", &mode) ||
        unformat_check_input (input) != UNFORMAT_END_OF_INPUT || mode > 3)
        return clib_error_return (0, "wake mode must be 0, 1, 2, or 3");

    error = handoff_perf_set_wake_mode(vm, hm, (u8)mode);
    if (error != 0)
        return error;
    vlib_cli_output (vm, "handoff-perf wake mode %u", mode);
    return 0;
}

VLIB_CLI_COMMAND (handoff_perf_wake_mode_command, static) = {
    .path = "handoff-perf wake-mode",
    .short_help = "handoff-perf wake-mode <0|1|2|3>",
    .function = handoff_perf_wake_mode_command_fn,
};

static clib_error_t *
handoff_perf_wake_fault_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                    vlib_cli_command_t *cmd)
{
#if VLIB_WAKE_FAULT_INJECTION
    handoff_perf_main_t *hm = &handoff_perf_main;
    u32 thread = ~0;
    u32 outcome = VLIB_WAKE_INJECT_OFF;
    u32 count = 0;
    u32 plan;

    (void) cmd;
    if (unformat (input, "thread %u off", &thread))
        ;
    else if (unformat (input, "thread %u success count %u", &thread, &count))
        outcome = VLIB_WAKE_INJECT_SUCCESS;
    else if (unformat (input, "thread %u eintr count %u", &thread, &count))
        outcome = VLIB_WAKE_INJECT_EINTR;
    else if (unformat (input, "thread %u eagain count %u", &thread, &count))
        outcome = VLIB_WAKE_INJECT_EAGAIN;
    else if (unformat (input, "thread %u ebadf count %u", &thread, &count))
        outcome = VLIB_WAKE_INJECT_EBADF;
    else if (unformat (input, "thread %u einval count %u", &thread, &count))
        outcome = VLIB_WAKE_INJECT_EINVAL;
    else if (unformat (input, "thread %u short count %u", &thread, &count))
        outcome = VLIB_WAKE_INJECT_SHORT;
    else
        return clib_error_return (0, "expected thread <index> <outcome> count <1..3>");

    if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT ||
        (outcome != VLIB_WAKE_INJECT_OFF && (count == 0 || count > 3)))
        return clib_error_return (0, "fault injection count must be 1..3");
    if (thread == 0 || thread >= vlib_get_n_threads ())
        return clib_error_return (0, "fault injection target must be worker thread 1..%u",
                                  vlib_get_n_threads () - 1);
    if (hm->running || hm->live_tokens != 0 || handoff_perf_outstanding_packets(hm) != 0)
        return clib_error_return (0,
                                  "fault injection requires stopped benchmark with zero "
                                  "live/outstanding packets");
    if (vm->thread_index != 0)
        return clib_error_return (0, "fault injection requires main thread");

    plan = VLIB_WAKE_INJECT_PLAN(outcome, count);
    vlib_worker_thread_barrier_sync(vm);
    __atomic_store_n (&vlib_get_main_by_index(thread)->wakeup_inject_plan, plan,
                      __ATOMIC_RELEASE);
    vlib_worker_thread_barrier_release(vm);
    vlib_cli_output (vm, "handoff-perf wake fault thread %u outcome %u count %u", thread,
                     outcome, count);
    return 0;
#else
    (void) vm;
    (void) input;
    (void) cmd;
    return clib_error_return (0, "wake fault injection unavailable in this build");
#endif
}

VLIB_CLI_COMMAND (handoff_perf_wake_fault_command, static) = {
    .path = "handoff-perf wake-fault",
    .short_help = "handoff-perf wake-fault thread <index> "
                  "<off|success|eintr|eagain|ebadf|einval|short> [count <1..3>]",
    .function = handoff_perf_wake_fault_command_fn,
};

static clib_error_t *handoff_perf_show_command_fn(vlib_main_t *vm, unformat_input_t *input,
                                                  vlib_cli_command_t *cmd) {
    handoff_perf_main_t *hm = &handoff_perf_main;
    u64 terminal = 0;
    u64 terminal_bytes = 0;
    u64 return_enqueued = 0;
    u64 return_drops = 0;
    u64 return_cycles = 0;
    u64 samples = 0;
    u64 sample_cycles = 0;
    u64 sample_min = 0;
    u64 sample_max = 0;
    f64 measurement_seconds;
    handoff_perf_diagnostics_t diagnostics;
    u64 *exact_latency = 0;
    u64 *exact_sleep_latency = 0;
    u32 exact_count;
    u32 exact_sleep_count;

    (void)input;
    (void)cmd;
    handoff_perf_drain_reclaim(hm);
    for (u32 thread = 0; thread < HANDOFF_PERF_MAX_THREADS; thread++) {
        handoff_perf_thread_stats_t *stats = &hm->thread[thread];
        terminal += stats->terminal_packets;
        terminal_bytes += stats->terminal_bytes;
        return_enqueued += stats->return_enqueued;
        return_drops += stats->return_drops;
        return_cycles += stats->return_enqueue_cycles;
        samples += stats->latency_samples;
        sample_cycles += stats->latency_cycles_sum;
        if (stats->latency_cycles_min != 0)
            sample_min = sample_min == 0 ? stats->latency_cycles_min
                                         : clib_min(sample_min, stats->latency_cycles_min);
        sample_max = clib_max(sample_max, stats->latency_cycles_max);
    }
    measurement_seconds = hm->measurement_stopped > hm->measurement_started
                              ? hm->measurement_stopped - hm->measurement_started
                              : (hm->running ? vlib_time_now(vm) - hm->measurement_started : 0.0);
    diagnostics = handoff_perf_get_diagnostics(hm);
    exact_count = clib_min(__atomic_load_n(&hm->exact_latency_count, __ATOMIC_ACQUIRE),
                           (u32)HANDOFF_PERF_EXACT_LATENCY_CAPACITY);
    if (exact_count != 0) {
        vec_validate(exact_latency, exact_count - 1);
        clib_memcpy(exact_latency, hm->exact_latency, exact_count * sizeof(exact_latency[0]));
        qsort(exact_latency, exact_count, sizeof(exact_latency[0]), handoff_perf_u64_compare);
    }
    exact_sleep_count =
        clib_min(__atomic_load_n(&hm->exact_sleep_latency_count, __ATOMIC_ACQUIRE),
                 (u32)HANDOFF_PERF_EXACT_LATENCY_CAPACITY);
    if (exact_sleep_count != 0) {
        vec_validate(exact_sleep_latency, exact_sleep_count - 1);
        clib_memcpy(exact_sleep_latency, hm->exact_sleep_latency,
                    exact_sleep_count * sizeof(exact_sleep_latency[0]));
        qsort(exact_sleep_latency, exact_sleep_count, sizeof(exact_sleep_latency[0]),
              handoff_perf_u64_compare);
    }

    vlib_cli_output(vm,
                    "running %u mode %s distribution %s burst %u packet-size %u "
                    "sample-rate %u offered-pps %llu workers %u tokens-live %u "
                    "tokens-available %u wake-workers %u measurement-seconds %.9f",
                    hm->running, handoff_perf_mode_name(hm->mode),
                    handoff_perf_distribution_name(hm->distribution), hm->burst_size,
                    hm->packet_size, hm->sample_rate, hm->offered_pps, hm->worker_count,
                    hm->live_tokens, hm->available_count, hm->wake_workers, measurement_seconds);
    vlib_cli_output(vm,
                    "generated %llu bytes %llu local %llu ingress-enqueued %llu "
                    "ingress-drops %llu alloc-errors %llu terminal %llu bytes %llu "
                    "return-enqueued %llu return-drops %llu reclaimed %llu "
                    "reclaim-overflows %llu clock-anomalies %llu credit-stalls %llu "
                    "outstanding-packets %llu",
                    hm->generated_packets, hm->generated_bytes, hm->local_packets,
                    hm->ingress_enqueued, hm->ingress_drops, hm->alloc_errors, terminal,
                    terminal_bytes, return_enqueued, return_drops, hm->reclaimed_packets,
                    hm->reclaim_overflows, hm->clock_anomalies, hm->credit_stalls,
                    hm->generated_packets - terminal - hm->ingress_drops - return_drops);
    vlib_cli_output(vm,
                    "rate-scheduler scheduled-packets %llu backlog-packets %.2f "
                    "timer-wakes %llu missed-wakes %llu wake-requests %llu tick-usec %.0f",
                    hm->scheduled_packets, hm->rate_credit, hm->rate_timer_wakes,
                    hm->rate_timer_missed_wakes, hm->wake_requests, hm->rate_tick_seconds * 1e6);
    vlib_cli_output(
        vm,
        "cycles producer-total %llu producer-batches %llu producer-per-packet %.2f "
        "primary-enqueue-total %llu primary-enqueue-calls %llu "
        "primary-enqueue-per-packet %.2f return-enqueue-total %llu samples %llu "
        "latency-min %llu latency-mean %.2f "
        "latency-p50-upper %llu latency-p95-upper %llu latency-p99-upper %llu "
        "latency-max %llu",
        hm->producer_cycles, hm->producer_batches,
        hm->generated_packets ? (f64)hm->producer_cycles / hm->generated_packets : 0.0,
        hm->primary_enqueue_cycles, hm->primary_enqueue_calls,
        hm->ingress_enqueued ? (f64)hm->primary_enqueue_cycles / hm->ingress_enqueued : 0.0,
        return_cycles, samples, sample_min, samples ? (f64)sample_cycles / samples : 0.0,
        handoff_perf_hist_quantile(hm, 50, 100), handoff_perf_hist_quantile(hm, 95, 100),
        handoff_perf_hist_quantile(hm, 99, 100), sample_max);
    vlib_cli_output(vm,
                    "wake-diagnostics calls %llu sleeps-seen %llu pending-claims %llu "
                    "writes %llu write-errors %llu sleep-attempts %llu "
                    "frame-queue-rechecks %llu epoll-wakeups %llu epoll-timeouts %llu "
                    "sleep-cycles %llu sleep-max-cycles %llu fq-full-waits %llu "
                    "fq-full-wait-cycles %llu fq-full-wait-max-cycles %llu",
                    diagnostics.wake_calls, diagnostics.wake_sleeps_seen,
                    diagnostics.wake_pending_claims, diagnostics.wake_writes,
                    diagnostics.wake_write_errors, diagnostics.sleep_attempts,
                    diagnostics.sleep_frame_queue_rechecks, diagnostics.sleep_epoll_wakeups,
                    diagnostics.sleep_epoll_timeouts, diagnostics.sleep_cycles,
                    diagnostics.sleep_max_cycles, diagnostics.fq_full_waits,
                    diagnostics.fq_full_wait_cycles, diagnostics.fq_full_wait_max_cycles);
    vlib_cli_output(vm,
                    "wake-state epoch-max %llu faults %llu fault-code %llu awake %llu preparing %llu "
                    "sleeping %llu notified %llu draining %llu notifying %llu write-retries %llu "
                    "write-eagain %llu",
                    diagnostics.wake_epoch_max, diagnostics.wake_faults,
                    diagnostics.wake_fault_code,
                    diagnostics.wake_phase_awake, diagnostics.wake_phase_preparing,
                    diagnostics.wake_phase_sleeping, diagnostics.wake_phase_notified,
                    diagnostics.wake_phase_draining, diagnostics.wake_phase_notifying,
                    diagnostics.wake_write_retries,
                    diagnostics.wake_write_eagain);
#if VLIB_WAKE_FAULT_INJECTION
    for (u32 thread = 1; thread < vlib_get_n_threads (); thread++) {
        u32 plan = __atomic_load_n(
            &vlib_get_main_by_index(thread)->wakeup_inject_plan, __ATOMIC_ACQUIRE);

        vlib_cli_output(vm, "wake-injection thread %u available outcome %u remaining %u",
                        thread, plan & VLIB_WAKE_INJECT_OUTCOME_MASK,
                        plan >> VLIB_WAKE_INJECT_REMAINING_SHIFT);
    }
#else
    vlib_cli_output (vm, "wake-injection unavailable");
#endif
    vlib_cli_output(vm, "sleep-proof sampled-remote-enqueues %llu target-sleeping %llu",
                    hm->sampled_remote_enqueues, hm->sampled_target_sleeping);
    vlib_cli_output(vm,
                    "exact-latency samples %u overflows %llu p50 %llu p95 %llu p99 %llu",
                    exact_count, hm->exact_latency_overflows,
                    exact_count ? exact_latency[(exact_count * 50 + 99) / 100 - 1] : 0,
                    exact_count ? exact_latency[(exact_count * 95 + 99) / 100 - 1] : 0,
                    exact_count ? exact_latency[(exact_count * 99 + 99) / 100 - 1] : 0);
    vlib_cli_output(
        vm, "exact-sleep-latency samples %u overflows %llu p50 %llu p95 %llu p99 %llu",
        exact_sleep_count, hm->exact_sleep_latency_overflows,
        exact_sleep_count ? exact_sleep_latency[(exact_sleep_count * 50 + 99) / 100 - 1] : 0,
        exact_sleep_count ? exact_sleep_latency[(exact_sleep_count * 95 + 99) / 100 - 1] : 0,
        exact_sleep_count ? exact_sleep_latency[(exact_sleep_count * 99 + 99) / 100 - 1] : 0);
    vec_free(exact_latency);
    vec_free(exact_sleep_latency);

    for (u32 thread = 0; thread < vlib_get_n_threads(); thread++) {
        handoff_perf_thread_stats_t *stats = &hm->thread[thread];
        vlib_cli_output(vm,
                        "thread %u worker-packets %llu terminal %llu return-enqueued %llu "
                        "return-drops %llu latency-samples %llu",
                        thread, stats->worker_packets, stats->terminal_packets,
                        stats->return_enqueued, stats->return_drops, stats->latency_samples);
    }
    return 0;
}

VLIB_CLI_COMMAND(handoff_perf_show_command, static) = {
    .path = "show handoff-perf",
    .short_help = "show handoff-perf",
    .function = handoff_perf_show_command_fn,
};

static clib_error_t *handoff_perf_init(vlib_main_t *vm) {
    handoff_perf_main_t *hm = &handoff_perf_main;

    clib_memset(hm, 0, sizeof(*hm));
    hm->burst_size = 64;
    hm->packet_size = 64;
    hm->sample_rate = 1024;
    hm->worker_fq_index = vlib_frame_queue_main_init(handoff_perf_worker_node.index, 0);
    hm->return_fq_index = vlib_frame_queue_main_init(handoff_perf_completion_node.index, 0);
    return 0;
}

VLIB_INIT_FUNCTION(handoff_perf_init);

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum phase {
    PHASE_AWAKE = 0,
    PHASE_PREPARING = 1,
    PHASE_SLEEPING = 2,
    PHASE_NOTIFIED = 3,
    PHASE_DRAINING = 4,
    PHASE_NOTIFYING = 5,
};

enum { PHASE_MASK = 7, EPOCH_INCREMENT = 8 };

struct shared {
    atomic_uint_fast64_t epoch_state;
    atomic_uint generation;
    atomic_uint producers_done;
    atomic_uint worker_done;
    atomic_uint frame[2];
    atomic_uint payload[2];
    atomic_uint readable;
    atomic_uint round_claims;
    atomic_uint round_writes;
    atomic_bool stop;

    atomic_uint_fast64_t sleep_confirmations;
    atomic_uint_fast64_t notify_claims;
    atomic_uint_fast64_t lost_wakes;
    atomic_uint_fast64_t visibility_failures;
    atomic_uint_fast64_t double_notifications;
    atomic_uint_fast64_t cas_exhaustions;
};

struct thread_arg {
    struct shared *shared;
    uint64_t seed;
    unsigned role;
};

static uint64_t mix64(uint64_t value) {
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static void widen(uint64_t seed, unsigned role, unsigned round, unsigned point) {
    const uint64_t value = mix64(seed ^ ((uint64_t)role << 56) ^
                                 ((uint64_t)round << 16) ^ point);
    const unsigned count = (unsigned)(value & 3U);
    for (unsigned index = 0; index < count; ++index) {
        (void)sched_yield();
    }
}

static unsigned phase_of(uint64_t state) { return (unsigned)(state & PHASE_MASK); }

static void *producer_main(void *opaque) {
    const struct thread_arg *arg = opaque;
    struct shared *shared = arg->shared;
    const unsigned producer = arg->role;
    unsigned seen = 0;

    for (;;) {
        unsigned generation;
        do {
            generation = atomic_load_explicit(&shared->generation, memory_order_acquire);
            if (atomic_load_explicit(&shared->stop, memory_order_relaxed)) {
                return NULL;
            }
            if (generation == seen) {
                (void)sched_yield();
            }
        } while (generation == seen);
        seen = generation;

        widen(arg->seed, producer, generation, 0);
        atomic_store_explicit(&shared->payload[producer], generation, memory_order_relaxed);
        widen(arg->seed, producer, generation, 1);
        atomic_store_explicit(&shared->frame[producer], generation, memory_order_release);
        widen(arg->seed, producer, generation, 2);

        uint64_t state = atomic_load_explicit(&shared->epoch_state, memory_order_relaxed);
        bool published = false;
        for (unsigned attempt = 0; attempt < 64; ++attempt) {
            const unsigned phase = phase_of(state);
            uint64_t desired = state + EPOCH_INCREMENT;
            bool owns = false;
            if (phase == PHASE_PREPARING) {
                desired = (desired & ~(uint64_t)PHASE_MASK) | PHASE_NOTIFIED;
            } else if (phase == PHASE_SLEEPING) {
                desired = (desired & ~(uint64_t)PHASE_MASK) | PHASE_NOTIFYING;
                owns = true;
            }
            if (atomic_compare_exchange_strong_explicit(&shared->epoch_state, &state, desired,
                                                        memory_order_release,
                                                        memory_order_relaxed)) {
                if (owns) {
                    atomic_fetch_add_explicit(&shared->round_claims, 1, memory_order_relaxed);
                    atomic_fetch_add_explicit(&shared->notify_claims, 1, memory_order_relaxed);
                    widen(arg->seed, producer, generation, 3);
                    atomic_fetch_add_explicit(&shared->round_writes, 1, memory_order_relaxed);
                    atomic_store_explicit(&shared->readable, 1, memory_order_release);
                    uint64_t notifying = atomic_load_explicit(&shared->epoch_state,
                                                               memory_order_acquire);
                    bool retired = false;
                    for (unsigned retire_attempt = 0; retire_attempt < 64;
                         ++retire_attempt) {
                        if (phase_of(notifying) != PHASE_NOTIFYING) {
                            atomic_fetch_add_explicit(&shared->lost_wakes, 1,
                                                      memory_order_relaxed);
                            break;
                        }
                        const uint64_t notified =
                            (notifying & ~(uint64_t)PHASE_MASK) | PHASE_NOTIFIED;
                        if (atomic_compare_exchange_strong_explicit(
                                &shared->epoch_state, &notifying, notified,
                                memory_order_acq_rel, memory_order_acquire)) {
                            retired = true;
                            break;
                        }
                    }
                    if (!retired) {
                        atomic_fetch_add_explicit(&shared->cas_exhaustions, 1,
                                                  memory_order_relaxed);
                    }
                }
                published = true;
                break;
            }
            widen(arg->seed, producer, generation, 4);
        }
        if (!published) {
            atomic_fetch_add_explicit(&shared->cas_exhaustions, 1,
                                      memory_order_relaxed);
        }
        atomic_fetch_add_explicit(&shared->producers_done, 1, memory_order_release);
    }
}

static void *worker_main(void *opaque) {
    const struct thread_arg *arg = opaque;
    struct shared *shared = arg->shared;
    unsigned seen = 0;

    for (;;) {
        unsigned generation;
        do {
            generation = atomic_load_explicit(&shared->generation, memory_order_acquire);
            if (atomic_load_explicit(&shared->stop, memory_order_relaxed)) {
                return NULL;
            }
            if (generation == seen) {
                (void)sched_yield();
            }
        } while (generation == seen);
        seen = generation;

        uint64_t awake = atomic_load_explicit(&shared->epoch_state, memory_order_acquire);
        const uint64_t preparing =
            (awake & ~(uint64_t)PHASE_MASK) | PHASE_PREPARING;
        const bool announced =
            phase_of(awake) == PHASE_AWAKE &&
            atomic_compare_exchange_strong_explicit(&shared->epoch_state, &awake, preparing,
                                                    memory_order_acq_rel,
                                                    memory_order_acquire);
        if (announced) {
            awake = preparing;
        }

        widen(arg->seed, arg->role, generation, 1);
        const unsigned frame0 = atomic_load_explicit(&shared->frame[0], memory_order_acquire);
        const unsigned frame1 = atomic_load_explicit(&shared->frame[1], memory_order_acquire);
        bool slept = false;
        if (announced && frame0 != generation && frame1 != generation) {
            uint64_t preparing = awake;
            const uint64_t sleeping =
                (preparing & ~(uint64_t)PHASE_MASK) | PHASE_SLEEPING;
            slept = atomic_compare_exchange_strong_explicit(
                &shared->epoch_state, &preparing, sleeping, memory_order_acq_rel,
                memory_order_acquire);
            if (slept) {
                atomic_fetch_add_explicit(&shared->sleep_confirmations, 1,
                                          memory_order_relaxed);
            }
        }

        while (atomic_load_explicit(&shared->producers_done, memory_order_acquire) != 2) {
            widen(arg->seed, arg->role, generation, 2);
        }
        if (slept) {
            const uint64_t state = atomic_load_explicit(&shared->epoch_state,
                                                        memory_order_acquire);
            const unsigned readable =
                atomic_load_explicit(&shared->readable, memory_order_acquire);
            if (phase_of(state) == PHASE_SLEEPING && readable == 0) {
                atomic_fetch_add_explicit(&shared->lost_wakes, 1, memory_order_relaxed);
            }
        }

        uint64_t state = atomic_load_explicit(&shared->epoch_state, memory_order_acquire);
        while (phase_of(state) == PHASE_NOTIFYING) {
            widen(arg->seed, arg->role, generation, 3);
            state = atomic_load_explicit(&shared->epoch_state, memory_order_acquire);
        }
        bool began_draining = false;
        for (unsigned attempt = 0; attempt < 64; ++attempt) {
            if (phase_of(state) == PHASE_NOTIFYING) {
                break;
            }
            const uint64_t draining =
                (state & ~(uint64_t)PHASE_MASK) | PHASE_DRAINING;
            if (atomic_compare_exchange_strong_explicit(&shared->epoch_state, &state, draining,
                                                        memory_order_acq_rel,
                                                        memory_order_acquire)) {
                state = draining;
                began_draining = true;
                break;
            }
        }
        if (!began_draining) {
            atomic_fetch_add_explicit(&shared->cas_exhaustions, 1,
                                      memory_order_relaxed);
        }

        /* file.c drains only the eventfd callback before clearing AWAKE. */
        atomic_store_explicit(&shared->readable, 0, memory_order_relaxed);
        const unsigned writes =
            atomic_load_explicit(&shared->round_writes, memory_order_relaxed);
        const unsigned claims =
            atomic_load_explicit(&shared->round_claims, memory_order_relaxed);
        if (writes > 1 || writes > claims) {
            atomic_fetch_add_explicit(&shared->double_notifications, 1,
                                      memory_order_relaxed);
        }
        bool cleared = false;
        for (unsigned attempt = 0; attempt < 64; ++attempt) {
            const uint64_t desired = (state & ~(uint64_t)PHASE_MASK) | PHASE_AWAKE;
            if (atomic_compare_exchange_strong_explicit(&shared->epoch_state, &state, desired,
                                                        memory_order_acq_rel,
                                                        memory_order_acquire)) {
                cleared = true;
                break;
            }
        }
        if (!cleared) {
            atomic_fetch_add_explicit(&shared->cas_exhaustions, 1,
                                      memory_order_relaxed);
        }
        /* The subsequent awake main-loop dispatch acquires frame publication. */
        for (unsigned producer = 0; producer < 2; ++producer) {
            const unsigned frame =
                atomic_load_explicit(&shared->frame[producer], memory_order_acquire);
            const unsigned payload =
                atomic_load_explicit(&shared->payload[producer], memory_order_relaxed);
            if (frame != generation || payload != generation) {
                atomic_fetch_add_explicit(&shared->visibility_failures, 1,
                                          memory_order_relaxed);
            }
        }
        atomic_store_explicit(&shared->worker_done, generation, memory_order_release);
    }
}

static uint64_t parse_u64(const char *text, const char *name) {
    char *end = NULL;
    errno = 0;
    const unsigned long long value = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') {
        (void)fprintf(stderr, "invalid %s: %s\n", name, text);
        exit(2);
    }
    return (uint64_t)value;
}

int main(int argc, char **argv) {
    uint64_t transitions = 5000;
    uint64_t seed = UINT64_C(0x5A4B20260802);
    for (int index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--transitions") == 0 && index + 1 < argc) {
            transitions = parse_u64(argv[++index], "transitions");
        } else if (strcmp(argv[index], "--seed") == 0 && index + 1 < argc) {
            seed = parse_u64(argv[++index], "seed");
        } else {
            (void)fprintf(stderr, "usage: %s [--transitions N] [--seed N]\n", argv[0]);
            return 2;
        }
    }
    if (transitions == 0 || transitions > UINT32_MAX) {
        (void)fprintf(stderr, "transitions must be 1..%" PRIu32 "\n", UINT32_MAX);
        return 2;
    }

    struct shared shared = {0};
    atomic_init(&shared.epoch_state, PHASE_AWAKE);
    atomic_init(&shared.generation, 0);
    atomic_init(&shared.producers_done, 0);
    atomic_init(&shared.worker_done, 0);
    atomic_init(&shared.frame[0], 0);
    atomic_init(&shared.frame[1], 0);
    atomic_init(&shared.payload[0], 0);
    atomic_init(&shared.payload[1], 0);
    atomic_init(&shared.readable, 0);
    atomic_init(&shared.round_claims, 0);
    atomic_init(&shared.round_writes, 0);
    atomic_init(&shared.stop, false);
    atomic_init(&shared.sleep_confirmations, 0);
    atomic_init(&shared.notify_claims, 0);
    atomic_init(&shared.lost_wakes, 0);
    atomic_init(&shared.visibility_failures, 0);
    atomic_init(&shared.double_notifications, 0);
    atomic_init(&shared.cas_exhaustions, 0);

    pthread_t threads[3];
    struct thread_arg args[3] = {
        {.shared = &shared, .seed = seed, .role = 0},
        {.shared = &shared, .seed = seed, .role = 1},
        {.shared = &shared, .seed = seed, .role = 2},
    };
    if (pthread_create(&threads[0], NULL, producer_main, &args[0]) != 0 ||
        pthread_create(&threads[1], NULL, producer_main, &args[1]) != 0 ||
        pthread_create(&threads[2], NULL, worker_main, &args[2]) != 0) {
        (void)fprintf(stderr, "pthread_create failed\n");
        return 2;
    }

    for (uint64_t round = 1; round <= transitions; ++round) {
        atomic_store_explicit(&shared.producers_done, 0, memory_order_relaxed);
        atomic_store_explicit(&shared.round_claims, 0, memory_order_relaxed);
        atomic_store_explicit(&shared.round_writes, 0, memory_order_relaxed);
        atomic_store_explicit(&shared.readable, 0, memory_order_relaxed);
        atomic_store_explicit(&shared.generation, (unsigned)round, memory_order_release);
        while (atomic_load_explicit(&shared.worker_done, memory_order_acquire) != round) {
            (void)sched_yield();
        }
    }

    atomic_store_explicit(&shared.stop, true, memory_order_relaxed);
    atomic_fetch_add_explicit(&shared.generation, 1, memory_order_release);
    for (unsigned index = 0; index < 3; ++index) {
        (void)pthread_join(threads[index], NULL);
    }

    const uint64_t confirmations = atomic_load_explicit(&shared.sleep_confirmations,
                                                         memory_order_relaxed);
    const uint64_t claims = atomic_load_explicit(&shared.notify_claims, memory_order_relaxed);
    const uint64_t lost = atomic_load_explicit(&shared.lost_wakes, memory_order_relaxed);
    const uint64_t visibility = atomic_load_explicit(&shared.visibility_failures,
                                                      memory_order_relaxed);
    const uint64_t doubles = atomic_load_explicit(&shared.double_notifications,
                                                   memory_order_relaxed);
    const uint64_t exhaustions = atomic_load_explicit(&shared.cas_exhaustions,
                                                       memory_order_relaxed);
    const bool passed = lost == 0 && visibility == 0 && doubles == 0 && exhaustions == 0;
    (void)printf("{\"schema\":\"p6c-litmus-v1\",\"status\":\"%s\","
                 "\"seed\":\"0x%" PRIx64 "\",\"transitions\":%" PRIu64 ","
                 "\"sleep_confirmations\":%" PRIu64 ",\"notify_claims\":%" PRIu64 ","
                 "\"lost_wakes\":%" PRIu64 ",\"visibility_failures\":%" PRIu64 ","
                 "\"double_notifications\":%" PRIu64 ","
                 "\"cas_exhaustions\":%" PRIu64 "}\n",
                 passed ? "PASS" : "FAIL", seed, transitions, confirmations, claims,
                 lost, visibility, doubles, exhaustions);
    return passed ? 0 : 1;
}

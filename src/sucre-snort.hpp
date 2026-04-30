/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <android-base/logging.h>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <map>
#include <mutex>
#include <shared_mutex>

#define JSS(s) "\"" << s << "\""
#define JSF(s) JSS(s) << ":"
#define JSB(b) (b ? 1 : 0)

#define when(first, stm)                                                                           \
    if (first) {                                                                                   \
        first = false;                                                                             \
    } else {                                                                                       \
        stm;                                                                                       \
    }

// Removed custom injection of std::shared_lock<std::shared_mutex> to avoid undefined behavior.

extern std::shared_mutex mutexListeners;
extern std::mutex mutexControlMutations;

namespace PolicyCheckpoint {
struct Status;
struct SlotMetadata;
} // namespace PolicyCheckpoint

inline constexpr std::chrono::milliseconds snortControlSendDeadline{5000};
inline constexpr std::chrono::milliseconds snortDnsSendDeadline{250};

std::uint64_t snortResetEpoch() noexcept;
bool snortResetEpochIsStable(std::uint64_t epoch) noexcept;
bool snortResetEpochStillCurrent(std::uint64_t epoch) noexcept;
void snortBeginResetEpoch() noexcept;
void snortEndResetEpoch() noexcept;

void snortConfigureProcessSignals();
void snortStartSignalWaiter();
void snortRequestShutdown();
bool snortShutdownRequested();
bool snortWaitForShutdownFor(std::chrono::milliseconds timeout);
void snortResetShutdownForTests();

enum class SnortSessionBudgetKind : std::uint8_t {
    Control,
    Dns,
};

class SnortSessionBudgetToken {
public:
    SnortSessionBudgetToken() noexcept = default;
    ~SnortSessionBudgetToken();

    SnortSessionBudgetToken(const SnortSessionBudgetToken &) = delete;
    SnortSessionBudgetToken &operator=(const SnortSessionBudgetToken &) = delete;

    SnortSessionBudgetToken(SnortSessionBudgetToken &&other) noexcept;
    SnortSessionBudgetToken &operator=(SnortSessionBudgetToken &&other) noexcept;

    explicit operator bool() const noexcept { return _active; }

private:
    friend SnortSessionBudgetToken snortTryAcquireSessionBudget(SnortSessionBudgetKind kind) noexcept;

    SnortSessionBudgetToken(SnortSessionBudgetKind kind, bool active) noexcept;
    void release() noexcept;

    SnortSessionBudgetKind _kind{SnortSessionBudgetKind::Control};
    bool _active = false;
};

SnortSessionBudgetToken snortTryAcquireSessionBudget(SnortSessionBudgetKind kind) noexcept;
std::uint32_t snortSessionBudgetLimit(SnortSessionBudgetKind kind) noexcept;
std::uint32_t snortActiveSessions(SnortSessionBudgetKind kind) noexcept;
void snortResetSessionBudgetsForTests() noexcept;

bool snortWriteAllWithDeadline(int fd, const void *data, std::size_t len,
                               std::chrono::milliseconds deadline) noexcept;

void snortSave(bool quit = false);
void snortResetAll();
PolicyCheckpoint::Status snortCheckpointSave(std::uint32_t slot,
                                             PolicyCheckpoint::SlotMetadata &metadata);
PolicyCheckpoint::Status snortCheckpointRestore(std::uint32_t slot,
                                                PolicyCheckpoint::SlotMetadata &metadata);
PolicyCheckpoint::Status snortCheckpointClear(std::uint32_t slot,
                                              PolicyCheckpoint::SlotMetadata &metadata);

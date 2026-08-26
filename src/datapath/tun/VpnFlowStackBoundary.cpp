/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <VpnFlowStackBoundary.hpp>

namespace SnortDatapath::Tun {

VpnFlowStackServiceResult serviceDeferredFlowStackWork(
    VpnFlowStackBoundary &boundary,
    const VpnFlowStackDeferredWork &work,
    const VpnFlowStackDriveBudget budget) noexcept {
    if (work.currentWorker == work.targetOwner) {
        const auto driveStatus = boundary.driveOwner(work.targetOwner, budget);
        const auto finishStatus = boundary.finishOwnerIfReady(work.targetOwner);
        return VpnFlowStackServiceResult{
            .action = VpnFlowStackServiceAction::LocalDrive,
            .targetOwner = work.targetOwner,
            .driveStatus = driveStatus,
            .finishStatus = finishStatus,
            .wakeStatus = VpnFlowStackWakeStatus::NotRequested,
        };
    }

    return VpnFlowStackServiceResult{
        .action = VpnFlowStackServiceAction::CrossOwnerWake,
        .targetOwner = work.targetOwner,
        .driveStatus = VpnFlowStackDriveStatus::NotRequested,
        .finishStatus = VpnFlowStackDriveStatus::NotRequested,
        .wakeStatus = boundary.enqueueOwnerWake(work),
    };
}

} // namespace SnortDatapath::Tun

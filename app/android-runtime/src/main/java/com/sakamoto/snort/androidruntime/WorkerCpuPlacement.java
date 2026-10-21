package com.sakamoto.snort.androidruntime;

import java.util.Arrays;

/** Startup-only ordered owner placement. CPU IDs never identify packet/flow owners. */
public final class WorkerCpuPlacement {
    public static final WorkerCpuPlacement DEFAULT = new WorkerCpuPlacement(1, 2);
    public final int ownerCount;
    public final int worker0CpuId;
    public final int worker1CpuId;
    private final int[] orderedCpuIds;

    private WorkerCpuPlacement(int worker0, int worker1) {
        this(worker1 < 0 ? new int[] {worker0} : new int[] {worker0, worker1});
    }

    private WorkerCpuPlacement(int[] ordered) {
        orderedCpuIds = ordered.clone();
        ownerCount = ordered.length;
        worker0CpuId = ordered[0];
        worker1CpuId = ordered.length > 1 ? ordered[1] : -1;
    }

    /** Syntax/shape checks only; the native child validates its real CPU sets. */
    public static WorkerCpuPlacement parse(String value) {
        if (value == null || !value.matches("[0-9]{1,10}(,[0-9]{1,10})*"))
            throw new IllegalArgumentException("workerCpuIds requires ordered decimal CPU IDs");
        String[] parts = value.split(",", -1);
        if (parts.length > 62)
            throw new IllegalArgumentException("workerCpuIds exceeds pinned VPP thread limit");
        int[] ordered = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            long cpu = Long.parseLong(parts[i]);
            if (cpu >= 1024)
                throw new IllegalArgumentException("workerCpuIds exceeds native CPU_SETSIZE");
            if (cpu == 0)
                throw new IllegalArgumentException("workerCpuIds conflicts with main-core 0");
            ordered[i] = (int) cpu;
        }
        return new WorkerCpuPlacement(ordered);
    }

    public String encode() {
        StringBuilder encoded = new StringBuilder();
        for (int i = 0; i < ownerCount; i++) {
            if (i != 0) encoded.append(',');
            encoded.append(orderedCpuIds[i]);
        }
        return encoded.toString();
    }

    public String startupConfig() {
        return "cpu {\n  main-core 0\n  workers " + ownerCount
                + "\n  ordered-workers " + encode() + "\n}\n\n";
    }

    /** VPN requires a separate, explicit I/O binding after the owner CPUs. */
    public int parseTunIoCpuId(String value) {
        if (value == null || !value.matches("[0-9]{1,10}"))
            throw new IllegalArgumentException("tunIoCpuId requires one decimal CPU ID");
        long parsed = Long.parseLong(value);
        if (parsed == 0 || parsed >= 1024)
            throw new IllegalArgumentException("tunIoCpuId conflicts with main-core or CPU_SETSIZE");
        for (int cpu : orderedCpuIds)
            if (cpu == parsed)
                throw new IllegalArgumentException("tunIoCpuId conflicts with a FlowOwner CPU");
        return (int) parsed;
    }

    public String vpnStartupConfig(String tunIoCpuId) {
        if (ownerCount > 2)
            throw new IllegalArgumentException("VPN currently supports one or two FlowOwner CPU IDs");
        int cpu = parseTunIoCpuId(tunIoCpuId);
        return "cpu {\n  main-core 0\n  workers " + (ownerCount + 1)
                + "\n  ordered-workers " + encode() + "," + cpu + "\n}\n\n";
    }

    public String vpnStartupConfig(int tunIoCpuId) {
        return vpnStartupConfig(Integer.toString(tunIoCpuId));
    }

    @Override public boolean equals(Object other) {
        if (!(other instanceof WorkerCpuPlacement)) return false;
        WorkerCpuPlacement value = (WorkerCpuPlacement) other;
        return Arrays.equals(orderedCpuIds, value.orderedCpuIds);
    }

    @Override public int hashCode() {
        return Arrays.hashCode(orderedCpuIds);
    }

    public int cpuId(int owner) {
        return orderedCpuIds[owner];
    }
}

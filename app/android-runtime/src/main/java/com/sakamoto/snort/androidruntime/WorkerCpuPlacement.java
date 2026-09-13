package com.sakamoto.snort.androidruntime;

/** Startup-only W2 placement. CPU IDs never identify packet/flow owners. */
public final class WorkerCpuPlacement {
    public static final WorkerCpuPlacement DEFAULT = new WorkerCpuPlacement(1, 2);
    public final int worker0CpuId;
    public final int worker1CpuId;

    private WorkerCpuPlacement(int worker0, int worker1) {
        worker0CpuId = worker0;
        worker1CpuId = worker1;
    }

    /** Syntax/shape checks only; the native child validates its real CPU sets. */
    public static WorkerCpuPlacement parse(String value) {
        if (value == null || !value.matches("[0-9]{1,10},[0-9]{1,10}"))
            throw new IllegalArgumentException("workerCpuIds requires exactly two decimal CPU IDs");
        String[] parts = value.split(",", -1);
        long first = Long.parseLong(parts[0]);
        long second = Long.parseLong(parts[1]);
        if (first >= 1024 || second >= 1024)
            throw new IllegalArgumentException("workerCpuIds exceeds native CPU_SETSIZE");
        if (first == second)
            throw new IllegalArgumentException("workerCpuIds must not contain duplicates");
        if (first == 0 || second == 0)
            throw new IllegalArgumentException("workerCpuIds conflicts with main-core 0");
        return new WorkerCpuPlacement((int) first, (int) second);
    }

    public String encode() {
        return worker0CpuId + "," + worker1CpuId;
    }

    public String startupConfig() {
        return "cpu {\n  main-core 0\n  workers 2\n  ordered-workers " + encode() + "\n}\n\n";
    }

    @Override public boolean equals(Object other) {
        if (!(other instanceof WorkerCpuPlacement)) return false;
        WorkerCpuPlacement value = (WorkerCpuPlacement) other;
        return worker0CpuId == value.worker0CpuId && worker1CpuId == value.worker1CpuId;
    }

    @Override public int hashCode() {
        return worker0CpuId * 1024 + worker1CpuId;
    }
}

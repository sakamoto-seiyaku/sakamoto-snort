import com.sakamoto.snort.androidruntime.WorkerCpuPlacement;

/** Host shape checks; native/device tests prove online/allowed CPUs and binding. */
public final class WorkerCpuPlacementTest {
    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        WorkerCpuPlacement forward = WorkerCpuPlacement.parse("1,3");
        WorkerCpuPlacement reverse = WorkerCpuPlacement.parse("3,1");
        require(forward.worker0CpuId == 1 && forward.worker1CpuId == 3, "noncontiguous order");
        require(reverse.worker0CpuId == 3 && reverse.worker1CpuId == 1, "reverse order");
        require(!forward.equals(reverse), "placement is not a set");
        require(reverse.equals(WorkerCpuPlacement.parse(reverse.encode())), "round trip");
        require(WorkerCpuPlacement.DEFAULT.equals(WorkerCpuPlacement.parse("1,2")), "default");
        require(reverse.startupConfig().equals(
                "cpu {\n  main-core 0\n  workers 2\n  ordered-workers 3,1\n}\n\n"), "native sequence seam");
        require(WorkerCpuPlacement.parse("0003,01").equals(reverse), "decimal normalization preserves order");
        require(WorkerCpuPlacement.parse("1023,1").worker0CpuId == 1023, "syntactic upper bound");
        WorkerCpuPlacement single = WorkerCpuPlacement.parse("0003");
        require(single.ownerCount == 1 && single.worker0CpuId == 3 && single.worker1CpuId == -1,
                "single owner ordered placement");
        require(single.equals(WorkerCpuPlacement.parse(single.encode())), "single round trip");
        require(single.startupConfig().equals(
                "cpu {\n  main-core 0\n  workers 1\n  ordered-workers 3\n}\n\n"), "one native worker");
        WorkerCpuPlacement shared = WorkerCpuPlacement.parse("1,2,1");
        require(shared.ownerCount == 3 && shared.encode().equals("1,2,1"), "shared CPU keeps three owners");
        require(shared.startupConfig().contains("workers 3\n  ordered-workers 1,2,1"),
                "three native worker contexts");
        require(shared.vpnStartupConfig(3).contains("workers 4\n  ordered-workers 1,2,1,3"),
                "VPN starts three shared-CPU owners and separate I/O context");
        require(WorkerCpuPlacement.parse("1,2,1,2").vpnStartupConfig(3)
                .contains("workers 5\n  ordered-workers 1,2,1,2,3"),
                "VPN owner count is not restricted to three");
        require(forward.vpnStartupConfig(4).equals(
                "cpu {\n  main-core 0\n  workers 3\n  ordered-workers 1,3,4\n}\n\n"),
                "VPN appends explicit I/O CPU after owners");
        require(single.vpnStartupConfig(4).equals(
                "cpu {\n  main-core 0\n  workers 2\n  ordered-workers 3,4\n}\n\n"),
                "VPN N=1 starts one owner and one distinct I/O worker");
        for (String invalidIo : new String[] {null, "", "0", "1", "3", "1024", "x", "4,5"}) {
            try {
                forward.vpnStartupConfig(invalidIo);
                throw new AssertionError("accepted invalid VPN I/O CPU: " + invalidIo);
            } catch (IllegalArgumentException expected) {
                // No implicit default or conflicting CPU is accepted.
            }
        }
        String[] invalid = {null, "", "0", "0,1", "1,0",
                "1,", ",1", "1,,2", "1-3", "3-1", "-1,2", "+1,2", "1.0,2", "1, 2",
                " 1,2", "1,2 ", "1,2\n", "1,2\nworkers 9", "1,2}", "1024,1",
                "4294967297,2", "99999999999,2", "١,2", "1;2"};
        for (String value : invalid) {
            try {
                WorkerCpuPlacement.parse(value);
                throw new AssertionError("accepted invalid CPU list: " + value);
            } catch (IllegalArgumentException expected) {
                // Every supplied invalid value rejects; none selects a fallback.
            }
        }
        try {
            WorkerCpuPlacement.parse(String.join(",",
                    java.util.Collections.nCopies(63, "1")));
            throw new AssertionError("accepted a worker count beyond the pinned VPP limit");
        } catch (IllegalArgumentException expected) {
            // The 63rd owner exceeds the pinned VPP thread limit.
        }
        try {
            WorkerCpuPlacement.parse(String.join(",",
                    java.util.Collections.nCopies(62, "1"))).vpnStartupConfig(3);
            throw new AssertionError("accepted VPN without a TUN worker slot");
        } catch (IllegalArgumentException expected) {
            // VPN reserves one VPP worker slot after the owners.
        }
        String absent = "libvpp_runtime.so: cpu_config: ordered-workers: CPU 9 absent or offline\n";
        WorkerCpuPlacement.NativeStartupFailure rootFailure =
                WorkerCpuPlacement.nativeStartupFailure(absent, null);
        require(rootFailure != null && rootFailure.code.equals("invalid_worker_cpu_ids")
                && rootFailure.message.equals("ordered-workers: CPU 9 absent or offline"),
                "Root native CPU rejection reaches the user");
        WorkerCpuPlacement.NativeStartupFailure vpnIoFailure =
                WorkerCpuPlacement.nativeStartupFailure(absent, 9);
        require(vpnIoFailure != null && vpnIoFailure.code.equals("invalid_tun_io_cpu_id"),
                "VPN I/O CPU rejection keeps its distinct field");
        require(WorkerCpuPlacement.nativeStartupFailure(absent, 3).code
                .equals("invalid_worker_cpu_ids"), "VPN owner CPU rejection");
        require(WorkerCpuPlacement.nativeStartupFailure(
                "libvpp_runtime.so: unrelated startup fault\n", 9) == null,
                "unrelated startup faults keep their original diagnosis");
        System.out.println("Worker CPU placement: ordered W2/default/roundtrip and "
                + invalid.length + " invalid inputs PASS; native affinity remains a device gate");
    }
}

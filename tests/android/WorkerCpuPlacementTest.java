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
        String[] invalid = {null, "", "1", "1,2,3", "1,1", "01,1", "0,1", "1,0",
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
        System.out.println("Worker CPU placement: ordered W2/default/roundtrip and "
                + invalid.length + " invalid inputs PASS; native affinity remains a device gate");
    }
}

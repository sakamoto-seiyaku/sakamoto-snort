import com.sakamoto.snort.vpnlite.RuntimeSnapshot;
import com.sakamoto.snort.vpnlite.RuntimeStateStore;
import com.sakamoto.snort.vpnlite.VppHealthHandshake;

import java.nio.file.Files;
import java.nio.file.Path;

public final class RuntimeContractTest {
    public static void main(String[] args) throws Exception {
        Path files = Files.createTempDirectory("sakamoto-46-runtime");
        RuntimeSnapshot initial = RuntimeStateStore.read(files.toFile());
        check(RuntimeSnapshot.STATE_STOPPED.equals(initial.state), "missing state is stopped");

        RuntimeSnapshot starting = RuntimeSnapshot.starting(
                RuntimeSnapshot.PROFILE_ROOT, "v26.02-release", "arm64-v8a");
        RuntimeStateStore.write(files.toFile(), starting);
        RuntimeSnapshot restored = RuntimeStateStore.read(files.toFile());
        check(RuntimeSnapshot.STATE_STARTING.equals(restored.state), "starting state round-trips");
        check("arm64-v8a".equals(restored.abi), "ABI round-trips");

        VppHealthHandshake.Result healthy = VppHealthHandshake.parse(
                "Version: v26.02-release\n", "v26.02-release", "arm64-v8a");
        check(healthy.isReady(), "matching VPP health handshake is ready");
        VppHealthHandshake.Result mismatch = VppHealthHandshake.parse(
                "Version: v25.10\n", "v26.02-release", "arm64-v8a");
        check(!mismatch.isReady(), "version mismatch fails closed");
        System.out.println("runtime contract: PASS");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}

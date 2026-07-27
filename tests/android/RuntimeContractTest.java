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
                RuntimeSnapshot.PROFILE_ROOT, VppHealthHandshake.PROTOCOL,
                "v26.02-release", "arm64-v8a", "manifest+device");
        RuntimeStateStore.write(files.toFile(), starting);
        RuntimeSnapshot restored = RuntimeStateStore.read(files.toFile());
        check(RuntimeSnapshot.STATE_STARTING.equals(restored.state), "starting state round-trips");
        check(VppHealthHandshake.PROTOCOL.equals(restored.protocol),
                "handshake protocol round-trips");
        check("arm64-v8a".equals(restored.abi), "ABI round-trips");
        check("manifest+device".equals(restored.abiEvidence), "ABI evidence round-trips");

        RuntimeSnapshot cleanupFailed = RuntimeSnapshot.error(
                RuntimeSnapshot.PROFILE_ROOT, VppHealthHandshake.PROTOCOL,
                "v26.02-release", "arm64-v8a", "manifest+device",
                "cleanup_failed", "runtime residue remains", true, 4242L);
        RuntimeStateStore.write(files.toFile(), cleanupFailed);
        RuntimeSnapshot restoredFailure = RuntimeStateStore.read(files.toFile());
        check(RuntimeSnapshot.STATE_ERROR.equals(restoredFailure.state),
                "cleanup failure uses actionable error state");
        check(restoredFailure.mayBeActive, "cleanup failure preserves mayBeActive");
        check(restoredFailure.isActive(), "mayBeActive error keeps visible runtime semantics");

        VppHealthHandshake.Result healthy = VppHealthHandshake.parse(
                VppHealthHandshake.PROTOCOL, "v26.02-release", "arm64-v8a",
                "arm64-v8a", 0, "Version: v26.02-release\n");
        check(healthy.isReady(), "matching VPP health handshake is ready");
        VppHealthHandshake.Result mismatch = VppHealthHandshake.parse(
                VppHealthHandshake.PROTOCOL, "v26.02-release", "arm64-v8a",
                "arm64-v8a", 0, "Version: v25.10\n");
        check(!mismatch.isReady(), "version mismatch fails closed");
        check(!VppHealthHandshake.parse(
                "vpp-runtime-health/v0", "v26.02-release", "arm64-v8a",
                "arm64-v8a", 0, "Version: v26.02-release\n").isReady(),
                "manifest protocol mismatch fails closed");
        check(!VppHealthHandshake.parse(
                VppHealthHandshake.PROTOCOL, "v26.02-release", "arm64-v8a",
                "x86_64", 0, "Version: v26.02-release\n").isReady(),
                "device ABI mismatch fails closed");
        check(!VppHealthHandshake.parse(
                VppHealthHandshake.PROTOCOL, "v26.02-release", "arm64-v8a",
                "arm64-v8a", 1, "Version: v26.02-release\n").isReady(),
                "non-zero vppctl exit fails closed");
        System.out.println("runtime contract: PASS");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}

import com.sakamoto.snort.androidruntime.RuntimeControlProtocol;
import com.sakamoto.snort.androidruntime.RuntimeControlRequest;
import com.sakamoto.snort.androidruntime.RuntimeProfile;
import com.sakamoto.snort.androidruntime.RuntimeSnapshot;
import com.sakamoto.snort.androidruntime.RuntimeStateStore;
import com.sakamoto.snort.androidruntime.VppHealthHandshake;

import java.nio.file.Files;
import java.nio.file.Path;

/** Public-seam tests for the production Android runtime incubator. */
public final class AndroidRuntimeContractTest {
    public static void main(String[] args) throws Exception {
        requestRoundTripIsVersionedAndProfileAware();
        profileAdapterManifestIdentityIsStable();
        snapshotRoundTripPreservesBoundedHealthAndError();
        healthRequiresArtifactAndProfileAdapterIdentity();
        System.out.println("android runtime contract: PASS");
    }

    private static void requestRoundTripIsVersionedAndProfileAware() {
        RuntimeControlRequest start = RuntimeControlRequest.start(RuntimeProfile.VPN);
        check(start.protocolVersion == RuntimeControlProtocol.VERSION,
                "start request uses the current protocol version");
        check(RuntimeControlRequest.Action.START == start.action,
                "start action is preserved");
        check(RuntimeProfile.VPN == start.profile, "VPN profile is preserved");
        RuntimeControlRequest restored = RuntimeControlRequest.decode(start.encode());
        check(start.equals(restored), "request wire round-trips");

        RuntimeControlRequest query = RuntimeControlRequest.decode(
                RuntimeControlRequest.query().encode());
        check(RuntimeControlRequest.Action.QUERY == query.action,
                "query is a first-class public action");
        check(query.profile == null, "query does not select a profile");
        check(RuntimeControlRequest.STOP.equals(
                RuntimeControlRequest.stop().encode().get("action")),
                "stop action has a stable wire name");
    }

    private static void snapshotRoundTripPreservesBoundedHealthAndError() throws Exception {
        Path files = Files.createTempDirectory("sakamoto-67-runtime");
        RuntimeSnapshot running = RuntimeSnapshot.running(
                RuntimeProfile.ROOT, "vpp-runtime-health/v1", "v26.02-release",
                "arm64-v8a", "artifact-sha256:abc", "nfqueue", "ok", 42L);
        RuntimeStateStore.write(files.toFile(), running);
        RuntimeSnapshot restored = RuntimeStateStore.read(files.toFile());
        check(restored.state.equals(RuntimeSnapshot.STATE_RUNNING), "running state round-trips");
        check(restored.profile == RuntimeProfile.ROOT, "root profile round-trips");
        check("nfqueue".equals(restored.adapter), "adapter identity round-trips");
        check(restored.pid == 42L, "owner pid round-trips");

        RuntimeSnapshot failure = RuntimeSnapshot.error(
                RuntimeProfile.VPN, "vpp-runtime-health/v1", "v26.02-release",
                "arm64-v8a", "artifact-sha256:abc", "tun", "cleanup_failed",
                "socket residue remains", true, 77L);
        RuntimeStateStore.write(files.toFile(), failure);
        RuntimeSnapshot restoredFailure = RuntimeStateStore.read(files.toFile());
        check(restoredFailure.isActive(), "active uncertainty survives an error state");
        check(restoredFailure.errorCode.equals("cleanup_failed"), "error code round-trips");
        check(restoredFailure.errorMessage.length() <= RuntimeSnapshot.MAX_TEXT_LENGTH,
                "error message is bounded");
    }

    private static void profileAdapterManifestIdentityIsStable() {
        check("libnfqueue_poc_plugin.so".equals(RuntimeProfile.ROOT.adapterArtifact),
                "root profile has a stable adapter artifact identity");
        check("libtun_poc_plugin.so".equals(RuntimeProfile.VPN.adapterArtifact),
                "VPN profile has a stable adapter artifact identity");
    }

    private static void healthRequiresArtifactAndProfileAdapterIdentity() {
        VppHealthHandshake.Result healthy = VppHealthHandshake.parse(
                RuntimeProfile.ROOT, "vpp-runtime-health/v1", "v26.02-release", "arm64-v8a",
                "artifact-sha256:abc", 0,
                "Version: v26.02-release\nArtifact: artifact-sha256:abc\n"
                        + "Plugin: nfqueue adapter ready\n");
        check(healthy.isReady(), "matching version/artifact/adapter health is ready");
        check("nfqueue".equals(healthy.adapter), "root adapter is reported");

        check(!VppHealthHandshake.parse(
                RuntimeProfile.VPN, "vpp-runtime-health/v1", "v26.02-release", "arm64-v8a",
                "artifact-sha256:abc", 0,
                "Version: v26.02-release\nArtifact: artifact-sha256:abc\n"
                        + "Plugin: nfqueue adapter ready\n").isReady(),
                "VPN cannot claim readiness from the root adapter");
        check(!VppHealthHandshake.parse(
                RuntimeProfile.ROOT, "vpp-runtime-health/v1", "v26.02-release", "arm64-v8a",
                "artifact-sha256:wrong", 0,
                "Version: v26.02-release\nArtifact: artifact-sha256:abc\n"
                        + "Plugin: nfqueue adapter ready\n").isReady(),
                "artifact identity mismatch fails closed");
        check(!VppHealthHandshake.parse(
                RuntimeProfile.ROOT, "vpp-runtime-health/v1", "v26.02-release", "arm64-v8a",
                "artifact-sha256:abc", 1,
                "Version: v26.02-release\nArtifact: artifact-sha256:abc\n"
                        + "Plugin: nfqueue adapter ready\n").isReady(),
                "non-zero health command fails closed");
        check(VppHealthHandshake.parse(
                "vpp-runtime-health/v1", "v26.02-release", "arm64-v8a", "arm64-v8a", 0,
                "Version: v26.02-release\n").isReady(),
                "legacy health parser remains usable for migration evidence");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}

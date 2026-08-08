import com.sakamoto.snort.androidruntime.RuntimeControlProtocol;
import com.sakamoto.snort.androidruntime.RuntimeControlRequest;
import com.sakamoto.snort.androidruntime.RuntimeControlNative;
import com.sakamoto.snort.androidruntime.RuntimeProfile;
import com.sakamoto.snort.androidruntime.RuntimeOwnershipReconciliation;
import com.sakamoto.snort.androidruntime.RuntimeSnapshot;
import com.sakamoto.snort.androidruntime.RuntimeStateStore;
import com.sakamoto.snort.androidruntime.VppHealthHandshake;

import java.nio.file.Files;
import java.nio.file.Path;

/** Public-seam tests for the production Android runtime incubator. */
public final class AndroidRuntimeContractTest {
    public static void main(String[] args) throws Exception {
        requestRoundTripIsVersionedAndProfileAware();
        profileDoesNotExposeAdapterArtifacts();
        snapshotRoundTripPreservesBoundedHealthAndError();
        durableProjectionReadResultIsExplicit();
        durableOwnershipDecisionFailsClosed();
        stoppedSnapshotRetainsRecentFailure();
        coreHealthDoesNotClaimAdapterReadiness();
        nativeCoreHandshakeRequiresGeneratedIdentity();
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
                "arm64-v8a", "artifact-sha256:abc", "ok", 42L);
        RuntimeStateStore.write(files.toFile(), running);
        RuntimeSnapshot restored = RuntimeStateStore.read(files.toFile());
        check(restored.state.equals(RuntimeSnapshot.STATE_RUNNING), "running state round-trips");
        check(restored.profile == RuntimeProfile.ROOT, "root profile round-trips");
        check(RuntimeSnapshot.ADAPTER_UNAVAILABLE.equals(restored.adapterReadiness),
                "adapter readiness remains explicitly unavailable");
        check("ok".equals(restored.coreHealth), "core health round-trips separately");
        check(restored.pid == 42L, "owner pid round-trips");

        RuntimeSnapshot failure = RuntimeSnapshot.error(
                RuntimeProfile.VPN, "vpp-runtime-health/v1", "v26.02-release",
                "arm64-v8a", "artifact-sha256:abc", "cleanup_failed",
                "socket residue remains", true, 77L);
        RuntimeStateStore.write(files.toFile(), failure);
        RuntimeSnapshot restoredFailure = RuntimeStateStore.read(files.toFile());
        check(restoredFailure.isActive(), "active uncertainty survives an error state");
        check(restoredFailure.errorCode.equals("cleanup_failed"), "error code round-trips");
        check(restoredFailure.errorMessage.length() <= RuntimeSnapshot.MAX_TEXT_LENGTH,
                "error message is bounded");
    }

    private static void durableProjectionReadResultIsExplicit() throws Exception {
        Path missing = Files.createTempDirectory("sakamoto-67-runtime-missing");
        RuntimeStateStore.ReadResult absent = RuntimeStateStore.readResult(missing.toFile());
        check(!absent.present, "missing projection is reported as absent");
        check(absent.valid, "missing projection is not a parse failure");
        check(RuntimeSnapshot.STATE_STOPPED.equals(absent.snapshot.state),
                "missing projection starts from an inactive snapshot");

        Path corrupt = Files.createTempDirectory("sakamoto-67-runtime-corrupt");
        Files.createDirectories(corrupt.resolve("runtime-state"));
        Files.write(corrupt.resolve("runtime-state/snapshot.properties"),
                "schemaVersion=not-a-number\nprofile=vpn\nstate=running\n"
                        .getBytes("US-ASCII"));
        RuntimeStateStore.ReadResult unreadable = RuntimeStateStore.readResult(corrupt.toFile());
        check(unreadable.present, "corrupt projection is reported as present");
        check(!unreadable.valid, "corrupt projection is reported as invalid");
        check("state_projection_corrupt".equals(unreadable.snapshot.errorCode),
                "corrupt projection has an explicit bounded error");

        Path corruptPid = Files.createTempDirectory("sakamoto-67-runtime-pid-corrupt");
        Files.createDirectories(corruptPid.resolve("runtime-state"));
        Files.write(corruptPid.resolve("runtime-state/snapshot.properties"),
                "schemaVersion=2\nprofile=vpn\nstate=running\npid=not-a-pid\n"
                        .getBytes("US-ASCII"));
        check(!RuntimeStateStore.readResult(corruptPid.toFile()).valid,
                "malformed durable PID also requires reconciliation");
    }

    private static void durableOwnershipDecisionFailsClosed() {
        check(RuntimeOwnershipReconciliation.Action.ADOPT_ROOT
                        == RuntimeOwnershipReconciliation.decide(
                                RuntimeOwnershipReconciliation.Evidence.LIVE,
                                RuntimeOwnershipReconciliation.Evidence.NONE),
                "one live root owner can be adopted");
        check(RuntimeOwnershipReconciliation.Action.ADOPT_VPN
                        == RuntimeOwnershipReconciliation.decide(
                                RuntimeOwnershipReconciliation.Evidence.NONE,
                                RuntimeOwnershipReconciliation.Evidence.LIVE),
                "one live VPN owner can be adopted");
        check(RuntimeOwnershipReconciliation.Action.CLEAN
                        == RuntimeOwnershipReconciliation.decide(
                                RuntimeOwnershipReconciliation.Evidence.RESIDUE,
                                RuntimeOwnershipReconciliation.Evidence.NONE),
                "one dead residue profile can be cleaned");
        check(RuntimeOwnershipReconciliation.Action.BLOCK
                        == RuntimeOwnershipReconciliation.decide(
                                RuntimeOwnershipReconciliation.Evidence.LIVE,
                                RuntimeOwnershipReconciliation.Evidence.LIVE),
                "two live owners are blocked");
        check(RuntimeOwnershipReconciliation.Action.BLOCK
                        == RuntimeOwnershipReconciliation.decide(
                                RuntimeOwnershipReconciliation.Evidence.UNKNOWN,
                                RuntimeOwnershipReconciliation.Evidence.NONE),
                "unverifiable ownership is blocked");
    }

    private static void stoppedSnapshotRetainsRecentFailure() throws Exception {
        RuntimeSnapshot failure = RuntimeSnapshot.error(
                RuntimeProfile.ROOT, "vpp-runtime-health/v1", "v26.02-release",
                "arm64-v8a", "artifact-sha256:abc", "unexpected_exit",
                "VPP owner exited with status 137", false, -1L, 8L);
        RuntimeSnapshot stopped = RuntimeSnapshot.stoppedAfter(failure);
        check(RuntimeSnapshot.STATE_STOPPED.equals(stopped.state),
                "terminal snapshot is stopped");
        check("unexpected_exit".equals(stopped.errorCode),
                "terminal snapshot retains recent failure code");
        check("VPP owner exited with status 137".equals(stopped.errorMessage),
                "terminal snapshot retains recent failure message");
        check(!stopped.mayBeActive, "terminal failure cannot claim an active owner");
        check(!stopped.isActive(), "terminal failure is inactive");
        check(stopped.generation == 8L, "terminal snapshot retains generation");

        Path files = Files.createTempDirectory("sakamoto-67-stopped-failure");
        RuntimeStateStore.write(files.toFile(), stopped);
        RuntimeSnapshot restored = RuntimeStateStore.read(files.toFile());
        check("unexpected_exit".equals(restored.errorCode),
                "terminal failure code survives persistence");
        check(!restored.mayBeActive, "persisted terminal failure is inactive");
    }

    private static void profileDoesNotExposeAdapterArtifacts() {
        check("root".equals(RuntimeProfile.ROOT.wireName), "root profile wire name is stable");
        check("vpn".equals(RuntimeProfile.VPN.wireName), "VPN profile wire name is stable");
    }

    private static void coreHealthDoesNotClaimAdapterReadiness() {
        VppHealthHandshake.Result healthy = VppHealthHandshake.parse(
                RuntimeProfile.ROOT, "vpp-runtime-health/v1", "v26.02-release", "arm64-v8a",
                "artifact-sha256:abc", 0,
                "Version: v26.02-release\nArtifact: artifact-sha256:abc\n");
        check(healthy.isReady(), "matching core version/artifact health is ready");

        check(VppHealthHandshake.parse(
                RuntimeProfile.VPN, "vpp-runtime-health/v1", "v26.02-release", "arm64-v8a",
                "artifact-sha256:abc", 0,
                "Version: v26.02-release\nArtifact: artifact-sha256:abc\n").isReady(),
                "VPN core health is independent of Adapter readiness");
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

    private static void nativeCoreHandshakeRequiresGeneratedIdentity() {
        RuntimeControlNative.Status status = new RuntimeControlNative.Status(
                RuntimeControlNative.CONTROL_ABI_VERSION, 0, 0, "show_version_51077d14",
                "vpp", "v26.02-release", "", "");
        check(VppHealthHandshake.evaluate(RuntimeProfile.ROOT, "vpp-runtime-health/v1",
                "v26.02-release", "arm64-v8a", "sha256:core", "show_version_51077d14",
                status).isReady(), "generated VAPI core identity proves readiness");
        RuntimeSnapshot vpn = RuntimeSnapshot.running(RuntimeProfile.VPN,
                "vpp-runtime-health/v1", "v26.02-release", "sha256:core", "arm64-v8a",
                "ok", 43L);
        check(RuntimeSnapshot.ADAPTER_UNAVAILABLE.equals(vpn.adapterReadiness),
                "native core handshake leaves VPN Adapter unavailable");
        check(!VppHealthHandshake.evaluate(RuntimeProfile.ROOT, "vpp-runtime-health/v1",
                "v26.02-release", "arm64-v8a", "sha256:core", "wrong-api", status).isReady(),
                "generated API identity mismatch fails closed");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}

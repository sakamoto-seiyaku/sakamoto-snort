import com.sakamoto.snort.androidruntime.ApplicationSubjectId;
import com.sakamoto.snort.androidruntime.AuthoringPolicyBundle;
import com.sakamoto.snort.androidruntime.AuthoringPolicyCompiler;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Focused Java wire/layout checks for the SAKAMOTO-192 bundle contract. */
public final class S192PolicyBundleContractTest {
    public static void main(String[] args) {
        completeBundleUsesOneFixedPayload();
        capacityAndTypedValuesFailClosed();
        System.out.println("s192 Java policy bundle contract: PASS");
    }

    private static void completeBundleUsesOneFixedPayload() {
        ApplicationSubjectId subject = ApplicationSubjectId.fromUid(1010001);
        AuthoringPolicyBundle.NetworkGateRule gate =
                AuthoringPolicyBundle.NetworkGateRule.create(subject,
                        AuthoringPolicyBundle.NetworkContextId.WIFI, true, 7, true);
        AuthoringPolicyBundle.L4Rule tcp = AuthoringPolicyBundle.L4Rule.create(subject,
                AuthoringPolicyBundle.IpFamily.IPV4, "10.0.0.0/8", "192.0.2.0/24",
                null, AuthoringPolicyBundle.PortRange.exact(443), 6,
                AuthoringPolicyBundle.PacketDirection.OUTPUT,
                AuthoringPolicyBundle.NetworkContextId.WIFI,
                AuthoringPolicyBundle.L4Action.DROP, 10, 0, 7, true);
        AuthoringPolicyBundle.L4Rule udp = AuthoringPolicyBundle.L4Rule.create(
                ApplicationSubjectId.fromUid(1010002),
                AuthoringPolicyBundle.IpFamily.IPV6, "2001:db8::/32", "2001:4860::/32",
                AuthoringPolicyBundle.PortRange.exact(53), null, 17,
                AuthoringPolicyBundle.PacketDirection.INPUT,
                AuthoringPolicyBundle.NetworkContextId.MOBILE,
                AuthoringPolicyBundle.L4Action.ALLOW, 20, 1, 9, false);
        AuthoringPolicyBundle bundle = AuthoringPolicyBundle.restore(42L, "test",
                Collections.singletonList(gate), list(tcp, udp), 0);

        AuthoringPolicyCompiler.CompileResult result =
                AuthoringPolicyCompiler.compilePolicyBundle(bundle);
        check(result.ok, "complete Gate + L4 bundle compiles");
        check(result.nativeBundlePayload.length == AuthoringPolicyBundle.BUNDLE_BYTES,
                "native bundle payload has fixed size");
        check(result.applyPayload.contains("\"bundleAbiVersion\":1")
                        && result.applyPayload.contains("\"bundlePayload\":\""),
                "complete compiler payload carries one native bundle marker");
        ByteBuffer wire = ByteBuffer.wrap(result.nativeBundlePayload)
                .order(ByteOrder.LITTLE_ENDIAN);
        check(wire.getInt(0) == AuthoringPolicyBundle.BUNDLE_ABI_VERSION,
                "native bundle carries ABI version");
        check(wire.getInt(4) == AuthoringPolicyBundle.BUNDLE_BYTES,
                "native bundle carries struct size");
        check(wire.getLong(8) == 42L, "native bundle carries revision");
        long wireSnapshotHash = wire.getLong(16);
        check(wireSnapshotHash != 0L
                        && result.applyPayload.contains("\"bundleSnapshotHash\":\""
                        + Long.toUnsignedString(wireSnapshotHash) + "\""),
                "compiler binds local canonical hash to the fixed native payload");
        check(wire.getInt(24) == 1 && wire.getInt(28) == 2,
                "native bundle carries bounded Gate/L4 counts");
        int gateOffset = AuthoringPolicyBundle.BUNDLE_HEADER_BYTES;
        int l4Offset = gateOffset + AuthoringPolicyBundle.MAX_GATE_ENTRIES
                * AuthoringPolicyBundle.RULE_ENTRY_BYTES;
        check(wire.getInt(gateOffset + 0) == 1010001
                        && wire.getInt(gateOffset + 8) == 7
                        && wire.getInt(gateOffset + 12) == 1
                        && wire.getInt(gateOffset + 28) == 2
                        && wire.getLong(gateOffset + 80) == gate.ruleId,
                "Gate entry preserves UID/ifindex/kind/action/stable ID");
        check(wire.getInt(l4Offset + 0) == 1010001
                        && wire.getInt(l4Offset + 12) == 2
                        && wire.getInt(l4Offset + 16) == 4
                        && wire.getInt(l4Offset + 20) == 6
                        && wire.getInt(l4Offset + 56) == 443
                        && (wire.get(l4Offset + 88) & 0xff) == 10
                        && (wire.get(l4Offset + 104) & 0xff) == 192
                        && wire.get(l4Offset + 92) == 0
                        && wire.get(l4Offset + 108) == 0,
                "first L4 entry preserves IPv4 TCP, canonical address and port range");
        int secondL4 = l4Offset + AuthoringPolicyBundle.RULE_ENTRY_BYTES;
        check(wire.getInt(secondL4 + 0) == 1010002
                        && wire.getInt(secondL4 + 16) == 6
                        && wire.getInt(secondL4 + 20) == 17
                        && wire.getInt(secondL4 + 24) == 1
                        && wire.getInt(secondL4 + 32) == 0,
                "second L4 entry preserves IPv6 UDP input and disabled state");

        AuthoringPolicyBundle oneRule = AuthoringPolicyBundle.restore(43L, "test",
                Collections.emptyList(), Collections.singletonList(tcp), 0);
        AuthoringPolicyCompiler.CompileResult legacy =
                AuthoringPolicyCompiler.compilePacketPolicyApply(oneRule);
        check(legacy.ok && legacy.nativeBundlePayload.length == 0
                        && !legacy.applyPayload.contains("bundlePayload")
                        && legacy.applyPayload.contains("\"nativeApply\":\"s191-scalar\""),
                "single S191 L4 compile retains the legacy scalar payload path");

        AuthoringPolicyCompiler.CompileResult singleTyped =
                AuthoringPolicyCompiler.compilePolicyBundle(oneRule);
        check(singleTyped.ok && singleTyped.nativeBundlePayload.length
                        == AuthoringPolicyBundle.BUNDLE_BYTES
                        && singleTyped.applyPayload.contains("\"bundlePayload\":\""),
                "single S192 L4 compile uses one typed bundle rather than scalar replay");

        AuthoringPolicyCompiler.CompileResult emptyTyped =
                AuthoringPolicyCompiler.compilePolicyBundle(AuthoringPolicyBundle.empty());
        check(emptyTyped.ok && emptyTyped.revision == 1L
                        && emptyTyped.nativeBundlePayload.length == AuthoringPolicyBundle.BUNDLE_BYTES
                        && emptyTyped.applyPayload.contains("\"bundlePayload\":\""),
                "initial empty S192 apply materializes a positive typed successor revision");

        AuthoringPolicyBundle.L4Rule unspecifiedInterface = new AuthoringPolicyBundle.L4Rule(
                subject, AuthoringPolicyBundle.IpFamily.IPV4, "", "192.0.2.1/32", null,
                AuthoringPolicyBundle.PortRange.exact(443), 6,
                AuthoringPolicyBundle.PacketDirection.OUTPUT,
                AuthoringPolicyBundle.NetworkContextId.WIFI,
                AuthoringPolicyBundle.L4Action.DROP, 10, 0, 71L, 72);
        AuthoringPolicyCompiler.CompileResult wildcardResult =
                AuthoringPolicyCompiler.compilePolicyBundle(
                        AuthoringPolicyBundle.restore(44L, "test", Collections.emptyList(),
                                Collections.singletonList(unspecifiedInterface), 0));
        check(wildcardResult.ok
                        && ByteBuffer.wrap(wildcardResult.nativeBundlePayload)
                                .order(ByteOrder.LITTLE_ENDIAN)
                                .getInt(l4Offset + 8) == -1,
                "legacy authoring interface default maps to matcher wildcard");
    }

    private static void capacityAndTypedValuesFailClosed() {
        ArrayList<AuthoringPolicyBundle.NetworkGateRule> gates = new ArrayList<>();
        for (int index = 0; index < AuthoringPolicyBundle.MAX_GATE_ENTRIES + 1; ++index) {
            gates.add(AuthoringPolicyBundle.NetworkGateRule.create(
                    ApplicationSubjectId.fromUid(2000000 + index),
                    AuthoringPolicyBundle.NetworkContextId.WIFI, false));
        }
        AuthoringPolicyBundle overCapacity = AuthoringPolicyBundle.restore(1L, "test", gates,
                Collections.emptyList(), 0);
        expectIllegalArgument(() -> overCapacity.toNativeBundlePayload(),
                "Gate count above fixed capacity is rejected");

        ApplicationSubjectId subject = ApplicationSubjectId.fromUid(1010001);
        AuthoringPolicyBundle.L4Rule invalidProtocol = new AuthoringPolicyBundle.L4Rule(
                subject, AuthoringPolicyBundle.IpFamily.IPV4, "0.0.0.0/0", "192.0.2.1/32",
                null, AuthoringPolicyBundle.PortRange.exact(443), 1,
                AuthoringPolicyBundle.PacketDirection.OUTPUT,
                AuthoringPolicyBundle.NetworkContextId.WIFI,
                AuthoringPolicyBundle.L4Action.DROP, 1, 0, 10L, 11);
        AuthoringPolicyBundle invalid = AuthoringPolicyBundle.restore(2L, "test",
                Collections.emptyList(), Collections.singletonList(invalidProtocol), 0);
        AuthoringPolicyCompiler.CompileResult result =
                AuthoringPolicyCompiler.compilePolicyBundle(invalid);
        check(!result.ok && "authoring_policy_bundle_invalid_native_bundle".equals(result.errorCode),
                "unsupported L4 protocol is rejected before native apply");
    }

    private static List<AuthoringPolicyBundle.L4Rule> list(
            AuthoringPolicyBundle.L4Rule first, AuthoringPolicyBundle.L4Rule second) {
        ArrayList<AuthoringPolicyBundle.L4Rule> values = new ArrayList<>();
        values.add(first);
        values.add(second);
        return values;
    }

    private static void expectIllegalArgument(Runnable operation, String message) {
        try {
            operation.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError(message);
    }

    private static void check(boolean value, String message) {
        if (!value) {
            throw new AssertionError(message);
        }
    }
}

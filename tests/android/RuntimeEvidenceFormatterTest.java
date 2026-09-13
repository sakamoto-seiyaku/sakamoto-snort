package com.sakamoto.snort.androidruntime;

import java.util.Arrays;

/** Exact-output tests at the package-private formatter interface. */
public final class RuntimeEvidenceFormatterTest {
    public static void main(String[] args) {
        nullMutationUsesCapturedGeneration();
        populatedMutationPreservesFieldsAndUnsignedValues();
        readbackUsesNativeOrPreservedDetail();
        faultOutputPreservesTrailingBlankLine();
        propertyTokensRemainBounded();
        System.out.println("runtime evidence formatter: PASS");
    }

    private static void nullMutationUsesCapturedGeneration() {
        String expected = "schema=s194-product-mutation/v1"
                + "\nstage="
                + "\nstate=ok"
                + "\nerrorCode="
                + "\nerrorMessage="
                + "\ngeneration=73"
                + "\npolicy_generation=0"
                + "\npolicy_requested_revision=0"
                + "\npolicy_active_revision=0"
                + "\npolicy_snapshot_hash=0"
                + "\npolicy_snapshot_identity="
                + "\npolicy_generation_match=false"
                + "\npolicy_artifact_match=false"
                + "\npolicy_mixed_revision=false"
                + "\npolicy_last_apply_status_code=0"
                + "\nnative_status_detail="
                + "\nartifact_id="
                + "\napi_identity="
                + "\nvpp_revision="
                + "\noperation_status_code=-1"
                + "\nreconcile_readback_only=false"
                + "\nreconcile_no_replay=false\n";
        equal(expected, RuntimeEvidenceFormatter.productMutation(null, 73L,
                null, null, null));
        equal(expected, RuntimeEvidenceFormatter.productMutation(null, 73L, "", "", ""));
        // State is based on the original error code, not its trimmed projection.
        equal(expected.replace("state=ok", "state=error"),
                RuntimeEvidenceFormatter.productMutation(null, 73L, "", " ", ""));
    }

    private static void populatedMutationPreservesFieldsAndUnsignedValues() {
        String expected = "schema=s194-product-mutation/v1"
                + "\nstage=apply_retry"
                + "\nstate=error"
                + "\nerrorCode=failed_request"
                + "\nerrorMessage=first__second"
                + "\ngeneration=42"
                + "\npolicy_generation=41"
                + "\npolicy_requested_revision=18446744073709551615"
                + "\npolicy_active_revision=9223372036854775808"
                + "\npolicy_snapshot_hash=18446744073709551600"
                + "\npolicy_snapshot_identity=bundle_42"
                + "\npolicy_generation_match=false"
                + "\npolicy_artifact_match=true"
                + "\npolicy_mixed_revision=true"
                + "\npolicy_last_apply_status_code=15"
                + "\nnative_status_detail=native_detail"
                + "\nartifact_id=artifact_42"
                + "\napi_identity=api_v1"
                + "\nvpp_revision=vpp_26"
                + "\noperation_status_code=14"
                + "\nreconcile_readback_only=false"
                + "\nreconcile_no_replay=false\n";
        equal(expected, RuntimeEvidenceFormatter.productMutation(status(" native\ndetail "),
                999L, " apply\nretry ", " failed\rrequest ", " first\r\nsecond "));
    }

    private static void readbackUsesNativeOrPreservedDetail() {
        for (String detail : new String[] {
                "unknown policy mutation reconciled", "unknown policy mutation discarded"}) {
            String nativeResult = RuntimeEvidenceFormatter.productMutation(status(detail),
                    99L, "reconcile", "", "");
            String preservedResult = RuntimeEvidenceFormatter.productMutation(null,
                    99L, "reconcile", "", detail);
            String suffix = "\nreconcile_readback_only=true\nreconcile_no_replay=true\n";
            check(nativeResult.endsWith(suffix), "native readback detail");
            check(preservedResult.endsWith(suffix), "preserved readback detail");
        }
        check(RuntimeEvidenceFormatter.productMutation(status(null), 99L, "", "", null)
                .endsWith("\nreconcile_readback_only=false\nreconcile_no_replay=false\n"),
                "absent readback detail must not claim reconciliation");
    }

    private static void faultOutputPreservesTrailingBlankLine() {
        equal("schema=s194-product-mutation-fault/v1"
                        + "\nmode="
                        + "\narmed=false"
                        + "\ngeneration=73"
                        + "\noperation_status_code=-1"
                        + "\nerrorCode="
                        + "\nerrorMessage="
                        + "\nconsumption=next_typed_bundle_apply_only\n\n",
                RuntimeEvidenceFormatter.policyMutationFault(null, false, null, 73L, null));
        equal("schema=s194-product-mutation-fault/v1"
                        + "\nmode=bundle_callback_omission"
                        + "\narmed=true"
                        + "\ngeneration=42"
                        + "\noperation_status_code=14"
                        + "\nerrorCode=failed_request"
                        + "\nerrorMessage=native__detail"
                        + "\nconsumption=next_typed_bundle_apply_only\n\n",
                RuntimeEvidenceFormatter.policyMutationFault(" bundle_callback_omission ",
                        true, status(" native\r\ndetail "), 999L, " failed\nrequest "));
    }

    private static void propertyTokensRemainBounded() {
        equal("", RuntimeEvidenceFormatter.propertyToken(null));
        equal("a__b", RuntimeEvidenceFormatter.propertyToken(" \na\r\nb\r "));
        char[] chars = new char[RuntimeSnapshot.MAX_TEXT_LENGTH];
        Arrays.fill(chars, 'x');
        String bound = new String(chars);
        equal(bound, RuntimeEvidenceFormatter.propertyToken(" " + bound + "overflow "));
        check(RuntimeEvidenceFormatter.productMutation(null, 1L, bound + "overflow", "", "")
                .contains("\nstage=" + bound + "\nstate=ok\n"), "mutation stage is bounded");
        check(RuntimeEvidenceFormatter.policyMutationFault(bound + "overflow", false,
                null, 1L, "").contains("\nmode=" + bound + "\narmed=false\n"),
                "fault mode is bounded");
    }

    private static RuntimeControlNative.Status status(String detail) {
        return new RuntimeControlNative.Status(1, 1, 14, 14, 42L,
                true, false, false, true, true, true,
                " artifact\n42 ", " api\rv1 ", " vpp\n26 ", detail, "", "",
                0L, 0L, 0L,
                0, 0, 0, 0, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
                0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
                0, 0, 0, 0, 0, 0, 0,
                0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
                0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
                0L, 0L, 0L, 0L, 0L, 0L,
                1, 0L, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0L, 0L, 0L,
                -1L, Long.MIN_VALUE, 41L, -16L, 0L, 0L,
                false, false, 0, 0, 15, true, true, false, " bundle\n42 ",
                0, 0, false, 0, 0L, 0L, 0L, 0L, 0L,
                0, 0, 0, 0, 0, false, 0,
                0L, 0L, 0L, 0L, 0L, 0L,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    private static void equal(String expected, String actual) {
        if (!expected.equals(actual)) {
            throw new AssertionError("Expected:\n" + expected + "Actual:\n" + actual);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}

package com.sakamoto.snort.androidruntime;

/** Pure, bounded S194 evidence formatting; RuntimeService owns capture and I/O. */
final class RuntimeEvidenceFormatter {
    private RuntimeEvidenceFormatter() {}

    static String productMutation(RuntimeControlNative.Status status, long generation,
                                  String stage, String errorCode, String errorMessage) {
        String detail = status == null ? "" : status.errorDetail;
        boolean readbackOnly = isUnknownPolicyMutationReadbackDetail(detail)
                || isUnknownPolicyMutationReadbackDetail(errorMessage);
        String text = "schema=s194-product-mutation/v1"
                + "\nstage=" + propertyToken(stage)
                + "\nstate=" + (errorCode == null || errorCode.isEmpty() ? "ok" : "error")
                + "\nerrorCode=" + propertyToken(errorCode)
                + "\nerrorMessage=" + propertyToken(errorMessage)
                + "\ngeneration=" + (status == null ? generation : status.generation)
                + "\npolicy_generation=" + (status == null ? 0L : status.policyGeneration)
                + "\npolicy_requested_revision=" + (status == null ? 0L
                : Long.toUnsignedString(status.policyRequestedRevision))
                + "\npolicy_active_revision=" + (status == null ? 0L
                : Long.toUnsignedString(status.policyActiveRevision))
                + "\npolicy_snapshot_hash=" + (status == null ? 0L
                : Long.toUnsignedString(status.policySnapshotHash))
                + "\npolicy_snapshot_identity="
                + (status == null ? "" : propertyToken(status.policySnapshotIdentity))
                + "\npolicy_generation_match=" + (status != null && status.policyGenerationMatch)
                + "\npolicy_artifact_match=" + (status != null && status.policyArtifactMatch)
                + "\npolicy_mixed_revision=" + (status != null && status.policyMixedRevision)
                + "\npolicy_last_apply_status_code=" + (status == null ? 0
                : status.policyLastApplyStatusCode)
                + "\nnative_status_detail=" + propertyToken(detail)
                + "\nartifact_id=" + (status == null ? "" : propertyToken(status.artifactId))
                + "\napi_identity=" + (status == null ? "" : propertyToken(status.apiIdentity))
                + "\nvpp_revision=" + (status == null ? "" : propertyToken(status.vppRevision))
                + "\noperation_status_code=" + (status == null ? -1 : status.code)
                + "\nreconcile_readback_only=" + readbackOnly
                + "\nreconcile_no_replay=" + readbackOnly
                + "\n";
        return text;
    }

    static String policyMutationFault(String mode, boolean armed,
                                      RuntimeControlNative.Status status, long generation,
                                      String error) {
        String normalizedMode = propertyToken(mode);
        String statusCode = status == null ? "-1" : Integer.toString(status.code);
        String detail = status == null ? "" : propertyToken(status.errorDetail);
        String text = "schema=s194-product-mutation-fault/v1"
                + "\nmode=" + normalizedMode
                + "\narmed=" + armed
                + "\ngeneration=" + (status == null ? generation : status.generation)
                + "\noperation_status_code=" + statusCode
                + "\nerrorCode=" + propertyToken(error)
                + "\nerrorMessage=" + detail
                + "\nconsumption=next_typed_bundle_apply_only"
                + "\n\n";
        return text;
    }

    static boolean isUnknownPolicyMutationReadbackDetail(String value) {
        return value != null
                && (value.contains("unknown policy mutation reconciled")
                || value.contains("unknown policy mutation discarded"));
    }

    static String propertyToken(String value) {
        return BoundedText.value(value, RuntimeSnapshot.MAX_TEXT_LENGTH)
                .replace('\n', '_').replace('\r', '_');
    }
}

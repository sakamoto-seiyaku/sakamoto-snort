package com.sakamoto.snort.androidruntime;

import org.json.JSONObject;

/** Android runtime transport for applying compiled Product policy through vNext control. */
public final class RuntimePolicyApplyTransport
        implements LocalProductBackend.PolicyApplyTransport {
    @Override
    public LocalProductBackend.PolicyApplyResult apply(String applyArgsJson) {
        try {
            RuntimeControlFdClient.AttachResult result =
                    RuntimeControlFdClient.applyPacketPolicy(new JSONObject(applyArgsJson));
            if (result.ok) {
                return LocalProductBackend.PolicyApplyResult.ok();
            }
            return LocalProductBackend.PolicyApplyResult.error(
                    result.errorCode.isEmpty() ? "product_policy_apply_failed"
                            : result.errorCode,
                    result.errorMessage);
        } catch (Exception error) {
            return LocalProductBackend.PolicyApplyResult.error("product_policy_apply_failed",
                    error.getMessage() == null ? "runtime policy apply failed"
                            : error.getMessage());
        }
    }
}

package com.sakamoto.snort.androidruntime;

import java.io.File;
import java.util.List;

/**
 * Service-side Local Product Backend seam. It owns product state mutations and
 * consumes an ApplicationCatalogProvider; UI callers only receive projections.
 */
public final class LocalProductBackend {
    private final File filesDir;
    private final ProductStore productStore;
    private final ApplicationCatalogProvider catalogProvider;
    private final PolicyApplyTransport policyApplyTransport;

    @FunctionalInterface
    public interface PolicyApplyTransport {
        PolicyApplyResult apply(String applyArgsJson);
    }

    public static final class PolicyApplyResult {
        public final boolean ok;
        public final String errorCode;
        public final String errorMessage;

        private PolicyApplyResult(boolean ok, String errorCode, String errorMessage) {
            this.ok = ok;
            this.errorCode = errorCode == null ? "" : errorCode;
            this.errorMessage = errorMessage == null ? "" : errorMessage;
        }

        public static PolicyApplyResult ok() {
            return new PolicyApplyResult(true, "", "");
        }

        public static PolicyApplyResult error(String errorCode, String errorMessage) {
            return new PolicyApplyResult(false, errorCode, errorMessage);
        }
    }

    public LocalProductBackend(File filesDir, ApplicationCatalogProvider catalogProvider) {
        this(filesDir, catalogProvider,
                json -> PolicyApplyResult.error("product_policy_runtime_unavailable",
                        "runtime policy apply transport is not configured"));
    }

    public LocalProductBackend(File filesDir, ApplicationCatalogProvider catalogProvider,
                               PolicyApplyTransport policyApplyTransport) {
        this.filesDir = filesDir;
        this.productStore = new ProductStore(filesDir);
        this.catalogProvider = catalogProvider;
        this.policyApplyTransport = policyApplyTransport == null
                ? json -> PolicyApplyResult.error("product_policy_runtime_unavailable",
                        "runtime policy apply transport is not configured")
                : policyApplyTransport;
    }

    public ProductStateSnapshot productState() {
        return productStore.snapshot();
    }

    public ProductStateStore.ReadResult productStateReadResult() {
        return productStore.readResult();
    }

    public ProductStateStore.ReadResult reloadProductState() {
        return productStore.reload();
    }

    public List<ApplicationCatalogEntry> applicationCatalog() {
        return catalogProvider.listApplications();
    }

    public ProductCatalogFormatter.Projection productCatalogProjection() {
        return ProductCatalogProjectionStore.read(filesDir);
    }

    public ProductCatalogFormatter.Projection refreshProductCatalogProjection() {
        ProductStateStore.ReadResult productState = productStore.reload();
        ProductCatalogFormatter.Projection projection;
        try {
            projection = ProductCatalogFormatter.result(productState,
                    catalogProvider.listApplications());
        } catch (RuntimeException error) {
            projection = ProductCatalogFormatter.error(productState, "catalog_load_failed",
                    error.getMessage() == null ? "catalog could not be loaded"
                            : error.getMessage());
        }
        try {
            ProductCatalogProjectionStore.write(filesDir, projection);
        } catch (java.io.IOException ignored) {
            // RuntimeService owns lifecycle errors; this projection is a bounded
            // UI/evidence handoff and must not mutate product policy state.
        }
        return projection;
    }

    public ProductStore.MutationResult selectRuntimeProfile(RuntimeProfile profile) {
        ProductStore.MutationResult result = productStore.selectRuntimeProfile(profile);
        refreshProductCatalogProjection();
        return result;
    }

    public ProductStore.MutationResult bindApplication(ApplicationSubjectId subjectId) {
        ProductStore.MutationResult result = productStore.bindApplication(subjectId);
        refreshProductCatalogProjection();
        return result;
    }

    public ProductStore.MutationResult unbindApplication(ApplicationSubjectId subjectId) {
        ProductStore.MutationResult result = productStore.unbindApplication(subjectId);
        refreshProductCatalogProjection();
        return result;
    }

    public ProductStore.MutationResult setNetworkGate(ApplicationSubjectId subjectId,
                                                     AuthoringPolicyBundle.NetworkContextId context,
                                                     boolean blocked) {
        ProductStateStore.ReadResult readResult = productStore.readResult();
        if (readResult != null && !readResult.valid) {
            ProductStore.MutationResult result = ProductStore.MutationResult.rejected(
                    productStore.snapshot(), readResult.errorCode, readResult.errorMessage);
            refreshProductCatalogProjection();
            return result;
        }
        AuthoringPolicyBundle nextBundle = productStore.snapshot().authoringPolicyBundle
                .withNetworkGate(subjectId, context, blocked);
        AuthoringPolicyCompiler.CompileResult compiled =
                AuthoringPolicyCompiler.compilePacketPolicyApply(nextBundle);
        if (!compiled.ok) {
            ProductStore.MutationResult result = ProductStore.MutationResult.rejected(
                    productStore.snapshot(), compiled.errorCode, compiled.errorMessage);
            refreshProductCatalogProjection();
            return result;
        }
        PolicyApplyResult applied = policyApplyTransport.apply(compiled.applyPayload);
        if (applied == null || !applied.ok) {
            ProductStore.MutationResult result = ProductStore.MutationResult.rejected(
                    productStore.snapshot(),
                    applied == null || applied.errorCode.isEmpty()
                            ? "product_policy_apply_failed" : applied.errorCode,
                    applied == null || applied.errorMessage.isEmpty()
                            ? "runtime policy apply failed" : applied.errorMessage);
            refreshProductCatalogProjection();
            return result;
        }
        ProductStore.MutationResult result =
                productStore.replaceAuthoringPolicyBundle(nextBundle);
        refreshProductCatalogProjection();
        return result;
    }

}

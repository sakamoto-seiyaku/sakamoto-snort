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
    private final ProductPolicyTransactionStore.Writer policyTransactionWriter;
    private ProductPolicyTransactionStore.ReadResult policyTransactionReadResult;
    private ProductPolicyTransactions policyTransactions;

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

    public static final class PolicyTextResult {
        public final boolean ok;
        public final String payload;
        public final String errorCode;
        public final String errorMessage;

        private PolicyTextResult(boolean ok, String payload,
                                 String errorCode, String errorMessage) {
            this.ok = ok;
            this.payload = payload == null ? "" : payload;
            this.errorCode = errorCode == null ? "" : errorCode;
            this.errorMessage = errorMessage == null ? "" : errorMessage;
        }

        public static PolicyTextResult ok(String payload) {
            return new PolicyTextResult(true, payload, "", "");
        }

        public static PolicyTextResult error(String errorCode, String errorMessage) {
            return new PolicyTextResult(false, "", errorCode, errorMessage);
        }
    }

    public LocalProductBackend(File filesDir, ApplicationCatalogProvider catalogProvider) {
        this(filesDir, catalogProvider,
                json -> PolicyApplyResult.error("product_policy_runtime_unavailable",
                        "runtime policy apply transport is not configured"));
    }

    public LocalProductBackend(File filesDir, ApplicationCatalogProvider catalogProvider,
                               PolicyApplyTransport policyApplyTransport) {
        this(filesDir, catalogProvider, policyApplyTransport,
                ProductPolicyTransactionStore.defaultWriter());
    }

    public LocalProductBackend(File filesDir, ApplicationCatalogProvider catalogProvider,
                               PolicyApplyTransport policyApplyTransport,
                               ProductPolicyTransactionStore.Writer policyTransactionWriter) {
        this.filesDir = filesDir;
        this.productStore = new ProductStore(filesDir);
        this.catalogProvider = catalogProvider;
        this.policyApplyTransport = policyApplyTransport == null
                ? json -> PolicyApplyResult.error("product_policy_runtime_unavailable",
                        "runtime policy apply transport is not configured")
                : policyApplyTransport;
        this.policyTransactionWriter = policyTransactionWriter == null
                ? ProductPolicyTransactionStore.defaultWriter() : policyTransactionWriter;
        this.policyTransactionReadResult = ProductPolicyTransactionStore.readResult(filesDir);
        this.policyTransactions = initialTransactions(policyTransactionReadResult,
                productStore.snapshot().authoringPolicyBundle);
    }

    public ProductStateSnapshot productState() {
        return productStore.snapshot();
    }

    public ProductStateStore.ReadResult productStateReadResult() {
        return productStore.readResult();
    }

    public ProductPolicyTransactionStore.ReadResult policyTransactionReadResult() {
        return policyTransactionReadResult;
    }

    public ProductPolicyTransactions.Status policyTransactionStatus() {
        return policyTransactions.status();
    }

    public PolicyTextResult exportCommittedPolicy() {
        if (policyTransactionReadResult != null && !policyTransactionReadResult.valid) {
            return PolicyTextResult.error(policyTransactionReadResult.errorCode,
                    policyTransactionReadResult.errorMessage);
        }
        return PolicyTextResult.ok(policyTransactions.exportCommitted());
    }

    public ProductStore.MutationResult importPolicyDraft(String encoded) {
        if (policyTransactionReadResult != null && !policyTransactionReadResult.valid) {
            return ProductStore.MutationResult.rejected(productStore.snapshot(),
                    policyTransactionReadResult.errorCode,
                    policyTransactionReadResult.errorMessage);
        }
        ProductPolicyTransactions working = copyTransactions(policyTransactions);
        ProductPolicyTransactions.Result imported = working.importDraft(encoded);
        if (!imported.ok) {
            return rejected(imported);
        }
        return persistPolicyTransactions(working, null, null);
    }

    public ProductStore.MutationResult commitPolicyDraft() {
        ProductStateStore.ReadResult readResult = productStore.readResult();
        if (readResult != null && !readResult.valid) {
            return ProductStore.MutationResult.rejected(productStore.snapshot(),
                    readResult.errorCode, readResult.errorMessage);
        }
        if (policyTransactionReadResult != null && !policyTransactionReadResult.valid) {
            return ProductStore.MutationResult.rejected(productStore.snapshot(),
                    policyTransactionReadResult.errorCode,
                    policyTransactionReadResult.errorMessage);
        }
        ProductPolicyTransactions working = copyTransactions(policyTransactions);
        ProductStateSnapshot nextState = productStore.snapshot()
                .withAuthoringPolicyBundle(working.draft());
        List<ApplicationCatalogEntry> catalog;
        try {
            catalog = catalogProvider.listApplications();
        } catch (RuntimeException error) {
            return ProductStore.MutationResult.rejected(productStore.snapshot(),
                    "catalog_load_failed",
                    error.getMessage() == null ? "catalog could not be loaded"
                            : error.getMessage());
        }
        ProductPolicyTransactions.Result committed = working.commitDraft(
                ProductPolicyTransactions.CommitValidationContext.of(nextState, catalog));
        if (!committed.ok) {
            return rejected(committed);
        }
        ProductStore.MutationResult result = persistPolicyTransactions(working, nextState, null);
        refreshProductCatalogProjection();
        return result;
    }

    public ProductStore.MutationResult applyCommittedPolicy() {
        ProductStateStore.ReadResult readResult = productStore.readResult();
        if (readResult != null && !readResult.valid) {
            return ProductStore.MutationResult.rejected(productStore.snapshot(),
                    readResult.errorCode, readResult.errorMessage);
        }
        if (policyTransactionReadResult != null && !policyTransactionReadResult.valid) {
            return ProductStore.MutationResult.rejected(productStore.snapshot(),
                    policyTransactionReadResult.errorCode,
                    policyTransactionReadResult.errorMessage);
        }
        ProductPolicyTransactions working = copyTransactions(policyTransactions);
        AuthoringPolicyBundle rollbackBundle = currentRuntimeBundle(policyTransactions);
        ProductPolicyTransactions.Result applied = working.applyCommitted(
                payload -> policyApplyTransport.apply(payload));
        if (!applied.ok) {
            return rejected(applied);
        }
        ProductStateSnapshot nextState = productStore.snapshot()
                .withAuthoringPolicyBundle(working.committed());
        ProductStore.MutationResult result = persistPolicyTransactions(working, nextState,
                rollbackBundle);
        refreshProductCatalogProjection();
        return result;
    }

    public ProductStore.MutationResult restorePolicyCheckpoint(long revision) {
        ProductStateStore.ReadResult readResult = productStore.readResult();
        if (readResult != null && !readResult.valid) {
            return ProductStore.MutationResult.rejected(productStore.snapshot(),
                    readResult.errorCode, readResult.errorMessage);
        }
        if (policyTransactionReadResult != null && !policyTransactionReadResult.valid) {
            return ProductStore.MutationResult.rejected(productStore.snapshot(),
                    policyTransactionReadResult.errorCode,
                    policyTransactionReadResult.errorMessage);
        }
        ProductPolicyTransactions working = copyTransactions(policyTransactions);
        AuthoringPolicyBundle rollbackBundle = currentRuntimeBundle(policyTransactions);
        ProductPolicyTransactions.Result restored = working.restoreCheckpoint(revision,
                payload -> policyApplyTransport.apply(payload));
        if (!restored.ok) {
            return rejected(restored);
        }
        ProductStateSnapshot nextState = productStore.snapshot()
                .withAuthoringPolicyBundle(working.committed());
        ProductStore.MutationResult result = persistPolicyTransactions(working, nextState,
                rollbackBundle);
        refreshProductCatalogProjection();
        return result;
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
        ProductStore.MutationResult result = applyPolicyTransaction(subjectId, nextBundle);
        refreshProductCatalogProjection();
        return result;
    }

    public ProductStore.MutationResult setL4Rule(AuthoringPolicyBundle.L4Rule rule) {
        ProductStateStore.ReadResult readResult = productStore.readResult();
        if (readResult != null && !readResult.valid) {
            ProductStore.MutationResult result = ProductStore.MutationResult.rejected(
                    productStore.snapshot(), readResult.errorCode, readResult.errorMessage);
            refreshProductCatalogProjection();
            return result;
        }
        AuthoringPolicyBundle nextBundle = productStore.snapshot().authoringPolicyBundle
                .withL4Rule(rule);
        ProductStore.MutationResult result = applyPolicyTransaction(rule.subjectId, nextBundle);
        refreshProductCatalogProjection();
        return result;
    }

    private ProductStore.MutationResult applyPolicyTransaction(
            ApplicationSubjectId subjectId, AuthoringPolicyBundle nextBundle) {
        if (policyTransactionReadResult != null && !policyTransactionReadResult.valid) {
            return ProductStore.MutationResult.rejected(productStore.snapshot(),
                    policyTransactionReadResult.errorCode,
                    policyTransactionReadResult.errorMessage);
        }
        ProductStateSnapshot nextState = productStore.snapshot()
                .withBoundApplication(subjectId)
                .withAuthoringPolicyBundle(nextBundle);
        ProductPolicyTransactions working = copyTransactions(policyTransactions);
        AuthoringPolicyBundle rollbackBundle = currentRuntimeBundle(policyTransactions);
        ProductPolicyTransactions.Result replaced = working.replaceDraft(nextBundle);
        if (!replaced.ok) {
            return rejected(replaced);
        }
        List<ApplicationCatalogEntry> catalog;
        try {
            catalog = catalogProvider.listApplications();
        } catch (RuntimeException error) {
            return ProductStore.MutationResult.rejected(productStore.snapshot(),
                    "catalog_load_failed",
                    error.getMessage() == null ? "catalog could not be loaded"
                            : error.getMessage());
        }
        ProductPolicyTransactions.Result committed = working.commitDraft(
                ProductPolicyTransactions.CommitValidationContext.of(nextState, catalog));
        if (!committed.ok) {
            return rejected(committed);
        }
        ProductPolicyTransactions.Result applied = working.applyCommitted(
                payload -> policyApplyTransport.apply(payload));
        if (!applied.ok) {
            return rejected(applied);
        }
        return persistPolicyTransactions(working, nextState, rollbackBundle);
    }

    private ProductStore.MutationResult rejected(ProductPolicyTransactions.Result result) {
        return ProductStore.MutationResult.rejected(productStore.snapshot(),
                result.errorCode, result.errorMessage);
    }

    private ProductStore.MutationResult persistPolicyTransactions(
            ProductPolicyTransactions working, ProductStateSnapshot nextState,
            AuthoringPolicyBundle rollbackRuntimeBundle) {
        try {
            policyTransactionWriter.write(filesDir, working);
            ProductPolicyTransactionStore.ReadResult persistedTransactions =
                    ProductPolicyTransactionStore.readResult(filesDir);
            if (!persistedTransactions.valid) {
                return ProductStore.MutationResult.rejected(productStore.snapshot(),
                        persistedTransactions.errorCode,
                        persistedTransactions.errorMessage);
            }
            if (nextState == null) {
                policyTransactionReadResult = persistedTransactions;
                policyTransactions = persistedTransactions.transactions;
                return ProductStore.MutationResult.persisted(productStore.snapshot());
            }
            ProductStore.MutationResult published = productStore.replaceSnapshot(nextState);
            if (published.persisted) {
                policyTransactionReadResult = persistedTransactions;
                policyTransactions = persistedTransactions.transactions;
            }
            return published;
        } catch (java.io.IOException error) {
            rollbackRuntime(rollbackRuntimeBundle);
            return ProductStore.MutationResult.rejected(productStore.snapshot(),
                    "policy_transactions_persistence_failed",
                    error.getMessage() == null ? "policy transaction state could not be persisted"
                            : error.getMessage());
        }
    }

    private void rollbackRuntime(AuthoringPolicyBundle rollbackRuntimeBundle) {
        if (rollbackRuntimeBundle == null) {
            return;
        }
        AuthoringPolicyCompiler.CompileResult compiled =
                AuthoringPolicyCompiler.compilePacketPolicyApply(rollbackRuntimeBundle);
        if (!compiled.ok) {
            return;
        }
        policyApplyTransport.apply(compiled.applyPayload);
    }

    private static ProductPolicyTransactions initialTransactions(
            ProductPolicyTransactionStore.ReadResult readResult,
            AuthoringPolicyBundle fallbackCommitted) {
        if (readResult != null && readResult.valid && readResult.present) {
            return readResult.transactions;
        }
        return new ProductPolicyTransactions(fallbackCommitted);
    }

    private static ProductPolicyTransactions copyTransactions(ProductPolicyTransactions source) {
        ProductPolicyTransactions value = source == null
                ? new ProductPolicyTransactions(AuthoringPolicyBundle.empty()) : source;
        ProductPolicyTransactions.Status status = value.status();
        return ProductPolicyTransactions.restore(value.draft(), value.committed(),
                status.draftDirty, status.runtimeRevision,
                status.selectedCheckpointRevision, status.runtimeSnapshotState,
                value.checkpoints());
    }

    private static AuthoringPolicyBundle currentRuntimeBundle(
            ProductPolicyTransactions source) {
        if (source == null) {
            return AuthoringPolicyBundle.empty();
        }
        ProductPolicyTransactions.Status status = source.status();
        if (status.runtimeRevision == 0L) {
            return AuthoringPolicyBundle.empty();
        }
        for (ProductPolicyTransactions.Checkpoint checkpoint : source.checkpoints()) {
            if (checkpoint.revision == status.runtimeRevision) {
                return checkpoint.bundle;
            }
        }
        return source.committed();
    }
}

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

    public LocalProductBackend(File filesDir, ApplicationCatalogProvider catalogProvider) {
        this.filesDir = filesDir;
        this.productStore = new ProductStore(filesDir);
        this.catalogProvider = catalogProvider;
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
}

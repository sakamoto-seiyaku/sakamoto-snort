package com.sakamoto.snort.androidruntime;

import java.io.File;
import java.util.List;

/**
 * Service-side Local Product Backend seam. It owns product state mutations and
 * consumes an ApplicationCatalogProvider; UI callers only receive projections.
 */
public final class LocalProductBackend {
    private final ProductStore productStore;
    private final ApplicationCatalogProvider catalogProvider;

    public LocalProductBackend(File filesDir, ApplicationCatalogProvider catalogProvider) {
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

    public ProductStore.MutationResult selectRuntimeProfile(RuntimeProfile profile) {
        return productStore.selectRuntimeProfile(profile);
    }

    public ProductStore.MutationResult bindApplication(ApplicationSubjectId subjectId) {
        return productStore.bindApplication(subjectId);
    }

    public ProductStore.MutationResult unbindApplication(ApplicationSubjectId subjectId) {
        return productStore.unbindApplication(subjectId);
    }
}

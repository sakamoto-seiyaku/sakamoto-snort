package com.sakamoto.snort.androidruntime;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Pure Java projection seam for the debug Product catalog shell. */
public final class ProductCatalogFormatter {
    public static final int DEFAULT_PREVIEW_LIMIT = 5;

    private ProductCatalogFormatter() {}

    public static Projection loading(ProductStateSnapshot state) {
        return project(readResultFromSnapshot(state), Collections.emptyList(), "loading", "", "",
                DEFAULT_PREVIEW_LIMIT);
    }

    public static Projection loading(ProductStateStore.ReadResult state) {
        return project(state, Collections.emptyList(), "loading", "", "",
                DEFAULT_PREVIEW_LIMIT);
    }

    public static Projection result(ProductStateSnapshot state,
                                    List<ApplicationCatalogEntry> catalog) {
        return project(readResultFromSnapshot(state), catalog, "result", "", "",
                DEFAULT_PREVIEW_LIMIT);
    }

    public static Projection result(ProductStateStore.ReadResult state,
                                    List<ApplicationCatalogEntry> catalog) {
        return project(state, catalog, "result", "", "", DEFAULT_PREVIEW_LIMIT);
    }

    public static Projection error(ProductStateSnapshot state, String errorCode,
                                   String errorMessage) {
        return project(readResultFromSnapshot(state), Collections.emptyList(), "error", errorCode,
                errorMessage, DEFAULT_PREVIEW_LIMIT);
    }

    public static Projection error(ProductStateStore.ReadResult state, String errorCode,
                                   String errorMessage) {
        return project(state, Collections.emptyList(), "error", errorCode,
                errorMessage, DEFAULT_PREVIEW_LIMIT);
    }

    public static Projection project(ProductStateSnapshot state,
                                     List<ApplicationCatalogEntry> catalog,
                                     String catalogStatus, String errorCode,
                                     String errorMessage, int previewLimit) {
        return project(readResultFromSnapshot(state), catalog, catalogStatus, errorCode,
                errorMessage, previewLimit);
    }

    public static Projection project(ProductStateStore.ReadResult state,
                                     List<ApplicationCatalogEntry> catalog,
                                     String catalogStatus, String errorCode,
                                     String errorMessage, int previewLimit) {
        ProductStateStore.ReadResult productState = state == null
                ? readResultFromSnapshot(null) : state;
        ProductStateSnapshot product = productState.snapshot == null
                ? ProductStateSnapshot.empty() : productState.snapshot;
        List<ApplicationCatalogEntry> entries = catalog == null
                ? Collections.emptyList() : catalog;
        int limit = Math.max(0, previewLimit);
        ArrayList<EntryRow> rows = new ArrayList<>();
        ApplicationSubjectId firstAvailable = null;
        boolean productStateValid = productState.valid;
        for (ApplicationCatalogEntry entry : entries) {
            if (entry == null) {
                continue;
            }
            boolean bound = product.boundApplications.contains(entry.subjectId);
            if (productStateValid && entry.available && !bound && firstAvailable == null) {
                firstAvailable = entry.subjectId;
            }
            if (rows.size() < limit) {
                rows.add(new EntryRow(entry, bound));
            }
        }
        ApplicationSubjectId firstBound = !productStateValid || product.boundApplications.isEmpty()
                ? null : product.boundApplications.iterator().next();
        String status = catalogStatus == null || catalogStatus.trim().isEmpty()
                ? "result" : catalogStatus.trim();
        String boundedErrorCode = bounded(errorCode);
        String boundedErrorMessage = bounded(errorMessage);
        String productStateStatus = productStateStatus(productState);
        String productStateErrorCode = productState.valid ? "" : bounded(productState.errorCode);
        String productStateErrorMessage = productState.valid
                ? "" : bounded(productState.errorMessage);
        return new Projection(product.selectedProfile, product.boundApplications.size(),
                entries.size(), status, boundedErrorCode, boundedErrorMessage,
                rows, firstAvailable, firstBound, productStateStatus,
                productStateErrorCode, productStateErrorMessage);
    }

    private static ProductStateStore.ReadResult readResultFromSnapshot(ProductStateSnapshot state) {
        ProductStateSnapshot snapshot = state == null ? ProductStateSnapshot.empty() : state;
        return ProductStateStore.ReadResult.validSnapshot(snapshot);
    }

    private static String productStateStatus(ProductStateStore.ReadResult state) {
        if (!state.valid) {
            return "invalid";
        }
        return state.present ? "valid" : "missing";
    }

    private static String bounded(String value) {
        return BoundedText.value(value == null ? "" : value,
                RuntimeSnapshot.MAX_TEXT_LENGTH);
    }

    public static final class Projection {
        public final RuntimeProfile selectedProfile;
        public final int boundApplicationCount;
        public final int catalogEntryCount;
        public final String catalogStatus;
        public final String errorCode;
        public final String errorMessage;
        public final List<EntryRow> rows;
        public final ApplicationSubjectId firstAvailableSubjectId;
        public final ApplicationSubjectId firstBoundSubjectId;
        public final String productStateStatus;
        public final String productStateErrorCode;
        public final String productStateErrorMessage;
        public final String displayText;

        private Projection(RuntimeProfile selectedProfile, int boundApplicationCount,
                           int catalogEntryCount, String catalogStatus, String errorCode,
                           String errorMessage, List<EntryRow> rows,
                           ApplicationSubjectId firstAvailableSubjectId,
                           ApplicationSubjectId firstBoundSubjectId,
                           String productStateStatus, String productStateErrorCode,
                           String productStateErrorMessage) {
            this.selectedProfile = selectedProfile == null ? RuntimeProfile.ROOT
                    : selectedProfile;
            this.boundApplicationCount = boundApplicationCount;
            this.catalogEntryCount = catalogEntryCount;
            this.catalogStatus = catalogStatus;
            this.errorCode = errorCode;
            this.errorMessage = errorMessage;
            this.rows = Collections.unmodifiableList(new ArrayList<>(rows));
            this.firstAvailableSubjectId = firstAvailableSubjectId;
            this.firstBoundSubjectId = firstBoundSubjectId;
            this.productStateStatus = productStateStatus == null
                    || productStateStatus.trim().isEmpty() ? "valid" : productStateStatus;
            this.productStateErrorCode = productStateErrorCode == null
                    ? "" : productStateErrorCode;
            this.productStateErrorMessage = productStateErrorMessage == null
                    ? "" : productStateErrorMessage;
            this.displayText = buildDisplayText();
        }

        private String buildDisplayText() {
            StringBuilder out = new StringBuilder();
            out.append("Product Store state: ").append(productStateStatus);
            if ("invalid".equals(productStateStatus)) {
                if (!productStateErrorCode.isEmpty()) {
                    out.append(" ").append(productStateErrorCode);
                }
                if (!productStateErrorMessage.isEmpty()) {
                    out.append(": ").append(productStateErrorMessage);
                }
            }
            out.append('\n');
            out.append("Product Store selected profile: ")
                    .append(selectedProfile.displayName)
                    .append(" (")
                    .append(selectedProfile.wireName)
                    .append(")\n");
            out.append("Bound application count: ")
                    .append(boundApplicationCount)
                    .append('\n');
            out.append("Catalog: ");
            if ("loading".equals(catalogStatus)) {
                out.append("loading");
            } else if ("error".equals(catalogStatus)) {
                out.append("error");
                if (!errorCode.isEmpty()) {
                    out.append(" ").append(errorCode);
                }
                if (!errorMessage.isEmpty()) {
                    out.append(": ").append(errorMessage);
                }
            } else {
                out.append("result: ").append(catalogEntryCount).append(" application instance");
                if (catalogEntryCount != 1) {
                    out.append('s');
                }
            }
            out.append('\n');
            if (rows.isEmpty()) {
                out.append("Apps: (none)");
                return out.toString();
            }
            out.append("Apps (first ").append(rows.size()).append("):");
            for (int i = 0; i < rows.size(); i++) {
                EntryRow row = rows.get(i);
                out.append('\n')
                        .append(i + 1)
                        .append(". ")
                        .append(row.label)
                        .append(" | package ")
                        .append(row.packageName)
                        .append(" | profile ")
                        .append(row.profileLabel)
                        .append(" | full uid ")
                        .append(row.fullUid)
                        .append(" | subject ")
                        .append(row.subjectId.encode())
                        .append(" | availability ")
                        .append(row.availability)
                        .append(" | bound ")
                        .append(row.bound ? "yes" : "no");
            }
            return out.toString();
        }
    }

    public static final class EntryRow {
        public final ApplicationSubjectId subjectId;
        public final String packageName;
        public final String label;
        public final String profileLabel;
        public final int userId;
        public final int fullUid;
        public final String availability;
        public final boolean bound;

        private EntryRow(ApplicationCatalogEntry entry, boolean bound) {
            this.subjectId = entry.subjectId;
            this.packageName = entry.packageName;
            this.label = entry.label;
            this.profileLabel = entry.profileLabel.isEmpty()
                    ? "user " + entry.userId : entry.profileLabel;
            this.userId = entry.userId;
            this.fullUid = entry.subjectId.uid;
            this.availability = entry.available ? "available" : "unavailable";
            this.bound = bound;
        }
    }
}

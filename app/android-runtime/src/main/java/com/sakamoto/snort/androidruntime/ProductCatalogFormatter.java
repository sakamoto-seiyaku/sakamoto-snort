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
        ArrayList<EntryRow> selectableRows = new ArrayList<>();
        ApplicationSubjectId firstAvailable = null;
        boolean productStateValid = productState.valid;
        for (ApplicationCatalogEntry entry : entries) {
            if (entry == null) {
                continue;
            }
            boolean bound = product.boundApplications.contains(entry.subjectId);
            EntryRow row = new EntryRow(entry, bound, productStateValid,
                    product.authoringPolicyBundle);
            if (productStateValid && entry.available && !bound && firstAvailable == null) {
                firstAvailable = entry.subjectId;
            }
            if (rows.size() < limit) {
                rows.add(row);
            }
            selectableRows.add(row);
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
                rows, selectableRows, firstAvailable, firstBound, productStateStatus,
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
        public final List<EntryRow> selectableRows;
        public final ApplicationSubjectId firstAvailableSubjectId;
        public final ApplicationSubjectId firstBoundSubjectId;
        public final String productStateStatus;
        public final String productStateErrorCode;
        public final String productStateErrorMessage;
        public final String displayText;

        Projection(RuntimeProfile selectedProfile, int boundApplicationCount,
                   int catalogEntryCount, String catalogStatus, String errorCode,
                   String errorMessage, List<EntryRow> rows, List<EntryRow> selectableRows,
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
            this.selectableRows = Collections.unmodifiableList(new ArrayList<>(selectableRows));
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
                        .append(" | icon ")
                        .append(row.iconToken.isEmpty() ? "(none)" : row.iconToken)
                        .append(" | subject ")
                        .append(row.subjectId.encode())
                        .append(" | availability ")
                        .append(row.availability)
                        .append(" | bound ")
                        .append(row.bound ? "yes" : "no")
                        .append(" | gate wifi=")
                        .append(row.wifiGateBlocked ? "blocked" : "open")
                        .append(" mobile=")
                        .append(row.mobileGateBlocked ? "blocked" : "open")
                        .append(" vpn=")
                        .append(row.vpnGateBlocked ? "blocked" : "open");
                out.append(" | l4Rules=")
                        .append(row.l4RuleCount);
            }
            return out.toString();
        }
    }

    public static final class EntryRow {
        public final ApplicationSubjectId subjectId;
        public final String packageName;
        public final String label;
        public final String profileLabel;
        public final String iconToken;
        public final int userId;
        public final int fullUid;
        public final String availability;
        public final boolean bound;
        public final boolean wifiGateBlocked;
        public final boolean mobileGateBlocked;
        public final boolean vpnGateBlocked;
        public final int l4RuleCount;
        public final boolean productStateValid;
        private final boolean canBind;
        private final boolean canUnbind;
        private final boolean canToggleGate;

        private EntryRow(ApplicationCatalogEntry entry, boolean bound, boolean productStateValid,
                         AuthoringPolicyBundle bundle) {
            this(entry.subjectId, entry.packageName, entry.label,
                    entry.profileLabel.isEmpty() ? "user " + entry.userId : entry.profileLabel,
                    entry.iconToken, entry.userId, entry.subjectId.uid,
                    entry.available ? "available" : "unavailable", bound,
                    gateBlocked(bundle, entry.subjectId, AuthoringPolicyBundle.NetworkContextId.WIFI),
                    gateBlocked(bundle, entry.subjectId, AuthoringPolicyBundle.NetworkContextId.MOBILE),
                    gateBlocked(bundle, entry.subjectId, AuthoringPolicyBundle.NetworkContextId.VPN),
                    l4RuleCount(bundle, entry.subjectId),
                    productStateValid);
        }

        EntryRow(ApplicationSubjectId subjectId, String packageName, String label,
                 String profileLabel, String iconToken, int userId, int fullUid,
                 String availability, boolean bound, boolean wifiGateBlocked,
                 boolean mobileGateBlocked, boolean vpnGateBlocked, int l4RuleCount,
                 boolean productStateValid) {
            if (subjectId == null) {
                throw new IllegalArgumentException("subjectId is required");
            }
            this.subjectId = subjectId;
            this.packageName = BoundedText.value(packageName == null || packageName.trim().isEmpty()
                    ? "(unknown package)" : packageName, RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.label = BoundedText.value(label == null || label.trim().isEmpty()
                    ? this.packageName : label, RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.profileLabel = BoundedText.value(profileLabel == null
                    || profileLabel.trim().isEmpty() ? "user " + userId : profileLabel,
                    RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.iconToken = BoundedText.value(iconToken == null ? "" : iconToken,
                    RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.userId = userId;
            this.fullUid = fullUid;
            this.availability = "available".equals(availability) ? "available" : "unavailable";
            this.bound = bound;
            this.wifiGateBlocked = wifiGateBlocked;
            this.mobileGateBlocked = mobileGateBlocked;
            this.vpnGateBlocked = vpnGateBlocked;
            this.l4RuleCount = Math.max(0, l4RuleCount);
            this.productStateValid = productStateValid;
            this.canBind = productStateValid && "available".equals(this.availability) && !bound;
            this.canUnbind = productStateValid && bound;
            this.canToggleGate = productStateValid && "available".equals(this.availability);
        }

        public boolean canBind() {
            return canBind;
        }

        public boolean canUnbind() {
            return canUnbind;
        }

        public boolean canToggleGate() {
            return canToggleGate;
        }

        public boolean isNetworkGateBlocked(AuthoringPolicyBundle.NetworkContextId context) {
            if (context == AuthoringPolicyBundle.NetworkContextId.WIFI) {
                return wifiGateBlocked;
            }
            if (context == AuthoringPolicyBundle.NetworkContextId.MOBILE) {
                return mobileGateBlocked;
            }
            return vpnGateBlocked;
        }

        public String networkGateButtonLabel(AuthoringPolicyBundle.NetworkContextId context) {
            return (isNetworkGateBlocked(context) ? "Open " : "Block ")
                    + context.wireName;
        }

        @Override
        public String toString() {
            return label + " | " + profileLabel + " | uid " + fullUid
                    + (bound ? " | bound" : " | unbound")
                    + " | gate wifi=" + (wifiGateBlocked ? "blocked" : "open")
                    + " mobile=" + (mobileGateBlocked ? "blocked" : "open")
                    + " vpn=" + (vpnGateBlocked ? "blocked" : "open")
                    + " | l4Rules=" + l4RuleCount;
        }
    }

    private static boolean gateBlocked(AuthoringPolicyBundle bundle,
                                       ApplicationSubjectId subjectId,
                                       AuthoringPolicyBundle.NetworkContextId context) {
        AuthoringPolicyBundle value = bundle == null ? AuthoringPolicyBundle.empty() : bundle;
        for (AuthoringPolicyBundle.NetworkGateRule rule : value.gateMatrix) {
            if (rule.subjectId.equals(subjectId) && rule.networkContext == context) {
                return rule.blocked;
            }
        }
        return false;
    }

    private static int l4RuleCount(AuthoringPolicyBundle bundle,
                                   ApplicationSubjectId subjectId) {
        AuthoringPolicyBundle value = bundle == null ? AuthoringPolicyBundle.empty() : bundle;
        int count = 0;
        for (AuthoringPolicyBundle.L4Rule rule : value.l4Rules) {
            if (rule.subjectId.equals(subjectId)) {
                count++;
            }
        }
        return count;
    }
}

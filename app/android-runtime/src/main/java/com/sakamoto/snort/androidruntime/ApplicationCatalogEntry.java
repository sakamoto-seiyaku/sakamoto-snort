package com.sakamoto.snort.androidruntime;

/** Product-facing catalog metadata for one Android user/profile app instance. */
public final class ApplicationCatalogEntry implements Comparable<ApplicationCatalogEntry> {
    public final ApplicationSubjectId subjectId;
    public final String packageName;
    public final String label;
    public final String iconToken;
    public final int userId;
    public final String profileLabel;
    public final boolean available;

    public ApplicationCatalogEntry(ApplicationSubjectId subjectId, String packageName,
                                   String label, String iconToken, int userId,
                                   String profileLabel, boolean available) {
        if (subjectId == null) {
            throw new IllegalArgumentException("subjectId is required");
        }
        if (packageName == null || packageName.trim().isEmpty()) {
            throw new IllegalArgumentException("packageName is required");
        }
        this.subjectId = subjectId;
        this.packageName = packageName;
        this.label = bounded(label == null || label.trim().isEmpty() ? packageName : label);
        this.iconToken = bounded(iconToken == null ? "" : iconToken);
        this.userId = userId;
        this.profileLabel = bounded(profileLabel == null ? "" : profileLabel);
        this.available = available;
    }

    private static String bounded(String value) {
        return BoundedText.value(value, RuntimeSnapshot.MAX_TEXT_LENGTH);
    }

    @Override
    public int compareTo(ApplicationCatalogEntry other) {
        int byUid = subjectId.compareTo(other.subjectId);
        if (byUid != 0) {
            return byUid;
        }
        return packageName.compareTo(other.packageName);
    }
}

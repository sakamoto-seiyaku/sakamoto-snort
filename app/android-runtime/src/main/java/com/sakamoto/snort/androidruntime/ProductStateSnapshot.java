package com.sakamoto.snort.androidruntime;

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/** Durable product/config state. It intentionally contains no catalog metadata. */
public final class ProductStateSnapshot {
    public static final int SCHEMA_VERSION = 1;

    public final int schemaVersion;
    public final RuntimeProfile selectedProfile;
    public final Set<ApplicationSubjectId> boundApplications;
    public final AuthoringPolicyBundle authoringPolicyBundle;

    public ProductStateSnapshot(RuntimeProfile selectedProfile,
                                Set<ApplicationSubjectId> boundApplications,
                                AuthoringPolicyBundle authoringPolicyBundle) {
        this.schemaVersion = SCHEMA_VERSION;
        this.selectedProfile = selectedProfile == null ? RuntimeProfile.ROOT : selectedProfile;
        TreeSet<ApplicationSubjectId> ordered = new TreeSet<>();
        if (boundApplications != null) {
            ordered.addAll(boundApplications);
        }
        this.boundApplications = Collections.unmodifiableSet(ordered);
        this.authoringPolicyBundle = authoringPolicyBundle == null
                ? AuthoringPolicyBundle.empty() : authoringPolicyBundle;
    }

    public static ProductStateSnapshot empty() {
        return new ProductStateSnapshot(RuntimeProfile.ROOT, Collections.emptySet(),
                AuthoringPolicyBundle.empty());
    }

    public ProductStateSnapshot withSelectedProfile(RuntimeProfile profile) {
        return new ProductStateSnapshot(profile, boundApplications, authoringPolicyBundle);
    }

    public ProductStateSnapshot withBoundApplication(ApplicationSubjectId subjectId) {
        TreeSet<ApplicationSubjectId> next = new TreeSet<>(boundApplications);
        next.add(subjectId);
        return new ProductStateSnapshot(selectedProfile, next, authoringPolicyBundle);
    }

    public ProductStateSnapshot withoutBoundApplication(ApplicationSubjectId subjectId) {
        TreeSet<ApplicationSubjectId> next = new TreeSet<>(boundApplications);
        next.remove(subjectId);
        return new ProductStateSnapshot(selectedProfile, next, authoringPolicyBundle);
    }

    public ProductStateSnapshot withAuthoringPolicyBundle(AuthoringPolicyBundle bundle) {
        return new ProductStateSnapshot(selectedProfile, boundApplications, bundle);
    }
}

package com.sakamoto.snort.androidruntime;

import java.io.File;
import java.io.IOException;

/** Backend-side single writer for durable product state mutations. */
public final class ProductStore {
    public static final class MutationResult {
        public final boolean persisted;
        public final ProductStateSnapshot snapshot;
        public final String errorCode;
        public final String errorMessage;

        private MutationResult(boolean persisted, ProductStateSnapshot snapshot,
                               String errorCode, String errorMessage) {
            this.persisted = persisted;
            this.snapshot = snapshot;
            this.errorCode = errorCode == null ? "" : errorCode;
            this.errorMessage = errorMessage == null ? "" : errorMessage;
        }

        public static MutationResult rejected(ProductStateSnapshot snapshot,
                                              String errorCode, String errorMessage) {
            return new MutationResult(false,
                    snapshot == null ? ProductStateSnapshot.empty() : snapshot,
                    errorCode, errorMessage);
        }
    }

    private final File filesDir;
    private final ProductStateStore.Writer writer;
    private ProductStateSnapshot snapshot;
    private ProductStateStore.ReadResult lastReadResult;

    public ProductStore(File filesDir) {
        this(filesDir, ProductStateStore.defaultWriter());
    }

    public ProductStore(File filesDir, ProductStateStore.Writer writer) {
        this.filesDir = filesDir;
        this.writer = writer == null ? ProductStateStore.defaultWriter() : writer;
        this.lastReadResult = ProductStateStore.readResult(filesDir);
        this.snapshot = lastReadResult.snapshot;
    }

    public synchronized ProductStateSnapshot snapshot() {
        return snapshot;
    }

    public synchronized ProductStateStore.ReadResult readResult() {
        return lastReadResult;
    }

    public synchronized MutationResult selectRuntimeProfile(RuntimeProfile profile) {
        return publish(snapshot.withSelectedProfile(profile));
    }

    public synchronized MutationResult bindApplication(ApplicationSubjectId subjectId) {
        return publish(snapshot.withBoundApplication(subjectId));
    }

    public synchronized MutationResult unbindApplication(ApplicationSubjectId subjectId) {
        return publish(snapshot.withoutBoundApplication(subjectId));
    }

    public synchronized MutationResult setNetworkGate(ApplicationSubjectId subjectId,
                                                     AuthoringPolicyBundle.NetworkContextId context,
                                                     boolean blocked) {
        AuthoringPolicyBundle nextBundle = snapshot.authoringPolicyBundle.withNetworkGate(
                subjectId, context, blocked);
        return publish(snapshot.withAuthoringPolicyBundle(nextBundle));
    }

    public synchronized MutationResult replaceAuthoringPolicyBundle(
            AuthoringPolicyBundle bundle) {
        return publish(snapshot.withAuthoringPolicyBundle(bundle));
    }

    public synchronized ProductStateStore.ReadResult reload() {
        ProductStateStore.ReadResult result = ProductStateStore.readResult(filesDir);
        if (result.valid) {
            snapshot = result.snapshot;
            lastReadResult = result;
        } else {
            lastReadResult = result.withSnapshot(snapshot);
        }
        return lastReadResult;
    }

    private MutationResult publish(ProductStateSnapshot next) {
        if (lastReadResult != null && !lastReadResult.valid) {
            return new MutationResult(false, snapshot, lastReadResult.errorCode,
                    lastReadResult.errorMessage);
        }
        try {
            writer.write(filesDir, next);
            lastReadResult = ProductStateStore.readResult(filesDir);
            if (!lastReadResult.valid) {
                lastReadResult = lastReadResult.withSnapshot(snapshot);
                return new MutationResult(false, snapshot, lastReadResult.errorCode,
                        lastReadResult.errorMessage);
            }
            snapshot = next;
            return new MutationResult(true, snapshot, "", "");
        } catch (IOException error) {
            return new MutationResult(false, snapshot, "product_state_persistence_failed",
                    error.getMessage() == null ? "product state could not be persisted"
                            : error.getMessage());
        }
    }
}
